package tui

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
)

// SocketClient communicates with the server's dashboard Unix socket.
// Each request opens a new connection (the server handles one command per connection).
type SocketClient struct {
	path string
}

// DialSocket stores the socket path for later connections.
func DialSocket(path string) (*SocketClient, error) {
	// Verify the socket is reachable with a test connection.
	conn, err := net.Dial("unix", path)
	if err != nil {
		return nil, fmt.Errorf("dashboard: dial %s: %w", path, err)
	}
	_ = conn.Close()
	return &SocketClient{path: path}, nil
}

// Close is a no-op (no persistent connection).
func (c *SocketClient) Close() error { return nil }

// Stats requests aggregated statistics from the server.
func (c *SocketClient) Stats() (*StatsSnapshot, error) {
	conn, err := net.Dial("unix", c.path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)

	if err := enc.Encode(map[string]string{"cmd": "stats"}); err != nil {
		return nil, err
	}

	var resp struct {
		Type string        `json:"type"`
		Data StatsSnapshot `json:"data"`
	}
	if err := dec.Decode(&resp); err != nil {
		return nil, err
	}
	if resp.Type == "error" {
		return nil, errors.New("stats request failed")
	}
	return &resp.Data, nil
}

// QueryLog requests the most recent N query log entries.
func (c *SocketClient) QueryLog(limit int) ([]QueryEvent, error) {
	conn, err := net.Dial("unix", c.path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)

	if err := enc.Encode(map[string]any{"cmd": "log", "limit": limit}); err != nil {
		return nil, err
	}

	var resp struct {
		Type    string       `json:"type"`
		Entries []QueryEvent `json:"entries"`
	}
	if err := dec.Decode(&resp); err != nil {
		return nil, err
	}
	if resp.Type == "error" {
		return nil, errors.New("log request failed")
	}
	return resp.Entries, nil
}
