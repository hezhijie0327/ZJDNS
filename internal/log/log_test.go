package log

import (
	"bytes"
	"strings"
	"testing"
)

func TestLevel_String(t *testing.T) {
	tests := []struct {
		lvl  Level
		want string
	}{
		{Error, "error"},
		{Warn, "warn"},
		{Info, "info"},
		{Debug, "debug"},
		{Level(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.lvl.String(); got != tt.want {
			t.Errorf("Level(%d).String() = %q, want %q", tt.lvl, got, tt.want)
		}
	}
}

func TestSetLevel_Clamped(t *testing.T) {
	m := NewLogger()
	m.SetLevel(Level(99))
	if m.Level() != Debug {
		t.Errorf("SetLevel(99) should clamp to Debug, got %d", m.Level())
	}
	m.SetLevel(Level(-1))
	if m.Level() != Error {
		t.Errorf("SetLevel(-1) should clamp to Error, got %d", m.Level())
	}
}

func TestSetLevel_Normal(t *testing.T) {
	m := NewLogger()
	m.SetLevel(Debug)
	if m.Level() != Debug {
		t.Errorf("got %d, want Debug", m.Level())
	}
	m.SetLevel(Warn)
	if m.Level() != Warn {
		t.Errorf("got %d, want Warn", m.Level())
	}
}

func TestParseLevelFilter_Empty(t *testing.T) {
	lvl, comps := ParseLevelFilter("", Warn)
	if lvl != Warn {
		t.Errorf("level = %d, want Warn", lvl)
	}
	if comps != nil {
		t.Errorf("components = %v, want nil", comps)
	}
}

func TestParseLevelFilter_Plain(t *testing.T) {
	tests := []struct {
		input string
		want  Level
	}{
		{"error", Error},
		{"warn", Warn},
		{"info", Info},
		{"debug", Debug},
		{"DEBUG", Debug},
		{"Info", Info},
	}
	for _, tt := range tests {
		lvl, _ := ParseLevelFilter(tt.input, Info)
		if lvl != tt.want {
			t.Errorf("ParseLevelFilter(%q) level = %d, want %d", tt.input, lvl, tt.want)
		}
	}
}

func TestParseLevelFilter_WithComponents(t *testing.T) {
	lvl, comps := ParseLevelFilter("debug:UPSTREAM,RECURSION", Info)
	if lvl != Debug {
		t.Errorf("level = %d, want Debug", lvl)
	}
	if len(comps) != 2 {
		t.Fatalf("components length = %d, want 2", len(comps))
	}
	if comps[0] != "UPSTREAM" || comps[1] != "RECURSION" {
		t.Errorf("components = %v, want [UPSTREAM RECURSION]", comps)
	}
}

func TestParseLevelFilter_Invalid(t *testing.T) {
	lvl, _ := ParseLevelFilter("invalid", Warn)
	if lvl != Warn {
		t.Errorf("level = %d, want Warn (default)", lvl)
	}
}

func TestParseLevelFilter_ColonNoComponents(t *testing.T) {
	lvl, comps := ParseLevelFilter("debug:", Info)
	if lvl != Debug {
		t.Errorf("level = %d, want Debug", lvl)
	}
	if comps != nil {
		t.Errorf("components = %v, want nil", comps)
	}
}

func TestParseLevelFilter_Spaces(t *testing.T) {
	_, comps := ParseLevelFilter("debug: UPSTREAM , RECURSION ", Info)
	if len(comps) != 2 {
		t.Fatalf("components length = %d, want 2", len(comps))
	}
	if comps[0] != "UPSTREAM" || comps[1] != "RECURSION" {
		t.Errorf("components = %v, want [UPSTREAM RECURSION]", comps)
	}
}

func TestExtractPrefix(t *testing.T) {
	tests := []struct {
		msg  string
		want string
	}{
		{"UPSTREAM: querying 8.8.8.8", "UPSTREAM"},
		{"CACHE: hit for example.com", "CACHE"},
		{"SERVER: Starting DNS server", "SERVER"},
		{"no prefix here", ""},
		{"", ""},
		{"X:", ""}, // no space after colon
		{": missing prefix", ""},
	}
	for _, tt := range tests {
		if got := extractPrefix(tt.msg); got != tt.want {
			t.Errorf("extractPrefix(%q) = %q, want %q", tt.msg, got, tt.want)
		}
	}
}

func TestSetComponentFilter_Empty(t *testing.T) {
	m := NewLogger()
	m.SetComponentFilter(nil)
	if m.componentFilter != nil {
		t.Error("nil components should set filter to nil")
	}
	m.SetComponentFilter([]string{})
	if m.componentFilter != nil {
		t.Error("empty components should set filter to nil")
	}
}

func TestSetComponentFilter_Normal(t *testing.T) {
	m := NewLogger()
	m.SetComponentFilter([]string{"UPSTREAM", "cache "})
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.componentFilter) != 2 {
		t.Fatalf("filter length = %d, want 2", len(m.componentFilter))
	}
	if !m.componentFilter["UPSTREAM"] {
		t.Error("UPSTREAM should be in filter")
	}
	if !m.componentFilter["CACHE"] {
		t.Error("CACHE (trimmed+uppered) should be in filter")
	}
}

func TestSanitizeLogMessage_Clean(t *testing.T) {
	msg := "hello world"
	if got := sanitizeLogMessage(msg); got != msg {
		t.Errorf("sanitizeLogMessage(%q) = %q, want unchanged", msg, got)
	}
}

func TestSanitizeLogMessage_Empty(t *testing.T) {
	if got := sanitizeLogMessage(""); got != "" {
		t.Errorf("sanitizeLogMessage(\"\") = %q, want empty", got)
	}
}

func TestSanitizeLogMessage_ControlChars(t *testing.T) {
	msg := "hello\x00world"
	got := sanitizeLogMessage(msg)
	if strings.Contains(got, "\x00") {
		t.Error("NUL byte should be replaced")
	}
	if got != "hello world" {
		t.Errorf("got %q, want 'hello world'", got)
	}
}

func TestSanitizeLogMessage_DEL(t *testing.T) {
	msg := "test\x7fend"
	got := sanitizeLogMessage(msg)
	if strings.Contains(got, "\x7f") {
		t.Error("DEL byte should be replaced")
	}
}

func TestLog_LevelFiltered(t *testing.T) {
	var buf bytes.Buffer
	m := NewLogger()
	m.writer = &buf
	m.SetLevel(Info)

	// Debug should be filtered
	m.Debug("should not appear")
	if buf.Len() > 0 {
		t.Error("debug message should be filtered at info level")
	}

	// Info should appear
	m.Info("should appear")
	if !strings.Contains(buf.String(), "should appear") {
		t.Error("info message should appear")
	}
}

func TestLog_ComponentFilter(t *testing.T) {
	var buf bytes.Buffer
	m := NewLogger()
	m.writer = &buf
	m.SetLevel(Debug)
	m.SetComponentFilter([]string{"UPSTREAM"})

	m.Debug("UPSTREAM: querying server")
	if !strings.Contains(buf.String(), "UPSTREAM") {
		t.Error("UPSTREAM message should pass filter")
	}

	buf.Reset()
	m.Debug("CACHE: hit")
	if buf.Len() > 0 {
		t.Error("CACHE message should be filtered out")
	}

	buf.Reset()
	m.Debug("no prefix message")
	if !strings.Contains(buf.String(), "no prefix") {
		t.Error("message without prefix should always pass")
	}
}

func TestNewLogger(t *testing.T) {
	m := NewLogger()
	if m == nil {
		t.Fatal("NewLogger returned nil")
	}
	if m.Level() != Info {
		t.Errorf("default level = %d, want Info", m.Level())
	}
}
