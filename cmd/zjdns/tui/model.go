package tui

import (
	"strings"
	"time"

	"charm.land/bubbles/v2/viewport"
	"charm.land/bubbletea/v2"
)

// Model is the Bubble Tea model for the ZJDNS dashboard.
type Model struct {
	client *SocketClient

	stats      StatsSnapshot
	queryLog   []QueryEvent
	prevTotal  int64
	currentQPS int64
	uptime     time.Duration

	width      int
	height     int
	paused     bool
	filter     string
	filterMode bool
	logVP      viewport.Model

	startTime time.Time
}

type tickMsg time.Time

// NewModel creates a new dashboard model connected to the server via socket.
func NewModel(client *SocketClient) Model {
	vp := viewport.New(viewport.WithWidth(80), viewport.WithHeight(20))

	return Model{
		client:    client,
		logVP:     vp,
		startTime: time.Now(),
	}
}

//nolint:gocritic // bubbletea.Model requires value receivers
func (m Model) Init() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

//nolint:gocritic // bubbletea.Model requires value receivers
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit

		case "r":
			m.paused = !m.paused

		case "f":
			m.filterMode = !m.filterMode
			if !m.filterMode {
				m.filter = ""
			}

		case "esc":
			m.filterMode = false
			m.filter = ""

		case "pgup":
			m.logVP.PageUp()

		case "pgdown":
			m.logVP.PageDown()

		default:
			if m.filterMode {
				m.filter += msg.String()
			}
		}

	case tickMsg:
		if !m.paused {
			m.refresh()
			m.uptime = time.Duration(time.Since(m.startTime).Seconds())
		}
		cmds = append(cmds, tea.Tick(time.Second, func(t time.Time) tea.Msg {
			return tickMsg(t)
		}))
	}

	return m, tea.Batch(cmds...)
}

//nolint:gocritic // bubbletea.Model requires value receivers
func (m Model) View() tea.View {
	return tea.NewView(renderDashboard(&m))
}

func (m *Model) refresh() {
	if stats, err := m.client.Stats(); err == nil {
		m.stats = *stats
		if m.prevTotal > 0 {
			m.currentQPS = m.stats.Total - m.prevTotal
		}
		m.prevTotal = m.stats.Total
	}

	if events, err := m.client.QueryLog(200); err == nil {
		m.queryLog = events
	}
}

func (m *Model) filteredLog() []QueryEvent {
	if m.filter == "" {
		return m.queryLog
	}
	f := strings.ToLower(m.filter)
	var out []QueryEvent
	for _, e := range m.queryLog {
		if strings.Contains(strings.ToLower(e.Qname), f) ||
			strings.Contains(strings.ToLower(e.Qtype), f) ||
			strings.Contains(strings.ToLower(e.Result), f) {
			out = append(out, e)
		}
	}
	return out
}
