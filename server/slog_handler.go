package server

import (
	"context"
	"log/slog"

	"zjdns/internal/log"
)

// dnsproxyLogHandler bridges slog calls to the project-level log package
// so dnsproxy's output uses the same timestamp format and level filter.
type dnsproxyLogHandler struct{}

func (dnsproxyLogHandler) Enabled(_ context.Context, level slog.Level) bool {
	switch level {
	case slog.LevelDebug:
		return log.Default.Level() >= log.Debug
	case slog.LevelInfo:
		return log.Default.Level() >= log.Info
	case slog.LevelWarn:
		return log.Default.Level() >= log.Warn
	case slog.LevelError:
		return log.Default.Level() >= log.Error
	default:
		return true
	}
}

func (dnsproxyLogHandler) Handle(_ context.Context, r slog.Record) error {
	msg := "PROXY: " + r.Message
	switch r.Level {
	case slog.LevelDebug:
		log.Debugf("%s", msg)
	case slog.LevelInfo:
		log.Infof("%s", msg)
	case slog.LevelWarn:
		log.Warnf("%s", msg)
	case slog.LevelError:
		log.Errorf("%s", msg)
	}
	return nil
}

func (h dnsproxyLogHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h dnsproxyLogHandler) WithGroup(_ string) slog.Handler      { return h }
