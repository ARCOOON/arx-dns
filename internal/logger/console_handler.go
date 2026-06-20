package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
)

const (
	ansiReset  = "\033[0m"
	ansiRed    = "\033[31m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
	ansiGray   = "\033[90m"
)

// ConsoleHandler writes human-readable, colorized log lines to an io.Writer.
// Format: [TIME] [LEVEL] Message (key=value)
type ConsoleHandler struct {
	opts  slog.HandlerOptions
	w     io.Writer
	mu    *sync.Mutex
	attrs []slog.Attr
	group string
}

// NewConsoleHandler creates a handler for terminal-friendly log output.
func NewConsoleHandler(w io.Writer, opts *slog.HandlerOptions) *ConsoleHandler {
	if opts == nil {
		opts = &slog.HandlerOptions{}
	}
	return &ConsoleHandler{
		opts: *opts,
		w:    w,
		mu:   &sync.Mutex{},
	}
}

func (h *ConsoleHandler) Enabled(_ context.Context, level slog.Level) bool {
	min := slog.LevelInfo
	if h.opts.Level != nil {
		min = h.opts.Level.Level()
	}
	return level >= min
}

func (h *ConsoleHandler) Handle(_ context.Context, r slog.Record) error {
	buf := make([]byte, 0, 256)
	buf = append(buf, '[')
	buf = r.Time.AppendFormat(buf, "2006-01-02T15:04:05.000Z07:00")
	buf = append(buf, "] ["...)
	buf = append(buf, levelColor(r.Level)...)
	buf = append(buf, r.Level.String()...)
	buf = append(buf, ansiReset...)
	buf = append(buf, "] "...)
	buf = append(buf, r.Message...)

	attrs := formatAttrs(h.attrs, h.group, &r)
	if attrs != "" {
		buf = append(buf, " ("...)
		buf = append(buf, attrs...)
		buf = append(buf, ')')
	}
	buf = append(buf, '\n')

	h.mu.Lock()
	_, err := h.w.Write(buf)
	h.mu.Unlock()
	return err
}

func (h *ConsoleHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ConsoleHandler{
		opts:  h.opts,
		w:     h.w,
		mu:    h.mu,
		attrs: appendAttrs(h.attrs, h.group, attrs),
		group: h.group,
	}
}

func (h *ConsoleHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &ConsoleHandler{
		opts:  h.opts,
		w:     h.w,
		mu:    h.mu,
		attrs: h.attrs,
		group: joinGroup(h.group, name),
	}
}

func levelColor(level slog.Level) string {
	switch {
	case level >= slog.LevelError:
		return ansiRed
	case level >= slog.LevelWarn:
		return ansiYellow
	case level >= slog.LevelInfo:
		return ansiCyan
	default:
		return ansiGray
	}
}

func joinGroup(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "." + name
}

func appendAttrs(existing []slog.Attr, group string, attrs []slog.Attr) []slog.Attr {
	if len(attrs) == 0 {
		return existing
	}
	out := make([]slog.Attr, len(existing), len(existing)+len(attrs))
	copy(out, existing)
	for _, attr := range attrs {
		out = append(out, slog.Attr{
			Key:   joinGroup(group, attr.Key),
			Value: attr.Value,
		})
	}
	return out
}

func formatAttrs(preAttrs []slog.Attr, group string, r *slog.Record) string {
	parts := make([]string, 0, len(preAttrs)+8)
	for _, attr := range preAttrs {
		if part := formatAttr(attr); part != "" {
			parts = append(parts, part)
		}
	}
	r.Attrs(func(attr slog.Attr) bool {
		key := joinGroup(group, attr.Key)
		if part := formatAttr(slog.Attr{Key: key, Value: attr.Value}); part != "" {
			parts = append(parts, part)
		}
		return true
	})
	return strings.Join(parts, " ")
}

func formatAttr(attr slog.Attr) string {
	if attr.Equal(slog.Attr{}) {
		return ""
	}
	value := attr.Value.String()
	if value == "" {
		return ""
	}
	return fmt.Sprintf("%s=%s", attr.Key, value)
}
