package dnscrypt

import (
	"context"
	"log/slog"

	"zjdns/internal/log"
)

// slogHandler bridges slog calls to the project-level log package with the
// DNSCRYPT prefix, so all DNSCrypt-related output is consistent and routed
// through the same logger (file, level filter, timestamp format).
type slogHandler struct{}

func (slogHandler) Enabled(_ context.Context, level slog.Level) bool {
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

func (slogHandler) Handle(_ context.Context, r slog.Record) error {
	msg := "DNSCRYPT: " + r.Message
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

func (h slogHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h slogHandler) WithGroup(_ string) slog.Handler      { return h }
