package persist

import (
	"context"
	"sync"
	"time"
	"zjdns/internal/log"
)

// Manager is the unified periodic + shutdown persist sink: subsystems
// register their Saver, and the Manager writes them all on an interval and
// once more when its context is cancelled. This is the only place that owns
// persist timing — subsystems never schedule their own flushes.
type Manager struct {
	mu     sync.Mutex
	savers []namedSaver
}

type namedSaver struct {
	name string
	s    Saver
}

// Saver is implemented by every subsystem with persistent state. Save is
// called periodically and at shutdown; it must be safe to call concurrently
// with normal operation.
type Saver interface {
	Save() error
}

// SaverFunc adapts a function to the Saver interface.
type SaverFunc func() error

// Save implements Saver.
func (f SaverFunc) Save() error { return f() }

// NewManager creates an empty persist manager.
func NewManager() *Manager {
	return &Manager{}
}

// Register adds a saver. Registration must happen before Run.
func (m *Manager) Register(name string, s Saver) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s == nil {
		return
	}
	m.savers = append(m.savers, namedSaver{name: name, s: s})
}

// Run drives SaveAll on every interval until ctx is cancelled, then performs
// one final SaveAll and returns. interval <= 0 skips periodic saves and only
// saves at shutdown. Intended to be run in the server's background errgroup,
// so the caller owns panic recovery and shutdown ordering.
func (m *Manager) Run(ctx context.Context, interval time.Duration) error {
	if interval > 0 {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				m.SaveAll()
			case <-ctx.Done():
				m.SaveAll()
				return nil
			}
		}
	}
	<-ctx.Done()
	m.SaveAll()
	return nil
}

// SaveAll saves every registered subsystem, logging but continuing past
// individual failures. One subsystem failing must not starve the others.
func (m *Manager) SaveAll() {
	m.mu.Lock()
	savers := make([]namedSaver, len(m.savers))
	copy(savers, m.savers)
	m.mu.Unlock()
	for _, s := range savers {
		if err := s.s.Save(); err != nil {
			log.Warnf("SERVER: persist %s failed: %v", s.name, err)
		}
	}
}
