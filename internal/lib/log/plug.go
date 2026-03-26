package log

import (
	"context"
	"log/slog"
)

func NewPlugLogger() *slog.Logger {
	return slog.New(&PlugLogger{})
}

type PlugLogger struct{}

func (p PlugLogger) Enabled(ctx context.Context, level slog.Level) bool {
	return false
}

func (p PlugLogger) Handle(ctx context.Context, record slog.Record) error {
	return nil
}

func (p PlugLogger) WithAttrs(attrs []slog.Attr) slog.Handler {
	return p
}

func (p PlugLogger) WithGroup(name string) slog.Handler {
	return p
}
