package tui

import (
	"fmt"

	"charm.land/bubbletea/v2"
)

// RunDashboard connects to the server's Unix socket and starts the TUI.
// socketPath is the filesystem path to the dashboard socket (e.g., "/tmp/zjdns.sock").
func RunDashboard(socketPath string) error {
	client, err := DialSocket(socketPath)
	if err != nil {
		return fmt.Errorf("dashboard: %w", err)
	}
	defer func() { _ = client.Close() }()

	m := NewModel(client)
	p := tea.NewProgram(m)

	if _, err := p.Run(); err != nil {
		return fmt.Errorf("dashboard TUI: %w", err)
	}
	return nil
}
