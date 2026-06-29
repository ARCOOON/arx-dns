package logger

import (
	"log/slog"
	"time"
)

// timestampLayout formats log timestamps with exactly three millisecond digits.
// The literal .000 pads fractional seconds with zeros so bracketed timestamps
// stay fixed-width and log levels align in console output.
const timestampLayout = "2006-01-02T15:04:05.000Z07:00"

// FormatTimestamp renders t using the fixed millisecond layout shared by all sinks.
func FormatTimestamp(t time.Time) string {
	return t.Format(timestampLayout)
}

// HandlerOptions returns slog.HandlerOptions with a shared level gate and
// millisecond-precise timestamp formatting for JSON sinks.
func HandlerOptions(level slog.Leveler) *slog.HandlerOptions {
	return &slog.HandlerOptions{
		Level:       level,
		ReplaceAttr: replaceTimestampAttr,
	}
}

func replaceTimestampAttr(_ []string, attr slog.Attr) slog.Attr {
	if attr.Key != slog.TimeKey {
		return attr
	}
	t, ok := attr.Value.Any().(time.Time)
	if !ok {
		return attr
	}
	return slog.String(slog.TimeKey, FormatTimestamp(t))
}
