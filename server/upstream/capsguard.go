// Capsguard (draft-vixie-dnsext-dns0x20): per-address randomisation
// state — mismatch counting, downgrade after repeated failures, retry
// cooldown.

package upstream

import (
	"sync"
	"time"
	"zjdns/config"
)

// capsDowngradeStat tracks one upstream address's 0x20 mismatch history.
// Stored by pointer — the counter update runs under mu (U6).
type capsDowngradeStat struct {
	mu            sync.Mutex
	mismatches    int
	disabledUntil time.Time
}

// capsDisabled reports whether 0x20 randomisation is currently skipped for
// addr (too many echo mismatches within the retry window).  The address-level
// downgrade state is shared across all queries.
func (c *Client) capsDisabled(addr string) bool {
	if c.capsDowngrades == nil {
		return false
	}
	st, ok := c.capsDowngrades.Get(addr)
	return ok && time.Now().Before(st.disabledUntil)
}

// noteCapsSuccess resets the consecutive-mismatch counter after a
// successful 0x20 echo (draft §6.4 — the downgrade tracks current, not
// lifetime, behaviour) (S8).
func (c *Client) noteCapsSuccess(addr string) {
	if c.capsDowngrades == nil {
		return
	}
	if st, ok := c.capsDowngrades.Get(addr); ok && st != nil {
		st.mu.Lock()
		st.mismatches = 0
		st.mu.Unlock()
	}
}

// noteCapsMismatch records one 0x20 echo mismatch for addr and reports
// whether this mismatch crossed the downgrade threshold.  The stat is a
// pointer keyed in the LRU: the read-modify-write runs under the stat's own
// mutex, so concurrent mismatches for one address cannot lose increments
// (lrumap.Get returns a value copy) (U6).
func (c *Client) noteCapsMismatch(addr string) bool {
	if c.capsDowngrades == nil {
		return false
	}
	st, _ := c.capsDowngrades.Get(addr)
	if st == nil {
		st, _ = c.capsDowngrades.LoadOrStore(addr, new(capsDowngradeStat))
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	st.mismatches++
	if st.mismatches >= config.DefaultCapsGuardDowngradeAfter {
		st.mismatches = 0
		st.disabledUntil = time.Now().Add(config.DefaultCapsGuardRetryAfter)
		return true
	}
	return false
}
