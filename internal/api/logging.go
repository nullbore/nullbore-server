package api

import (
	"bufio"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/nullbore/nullbore-server/internal/auth"
)

// statusWriter wraps http.ResponseWriter to capture the status code.
type statusWriter struct {
	http.ResponseWriter
	status int
	size   int
}

func (sw *statusWriter) WriteHeader(status int) {
	sw.status = status
	sw.ResponseWriter.WriteHeader(status)
}

func (sw *statusWriter) Write(b []byte) (int, error) {
	n, err := sw.ResponseWriter.Write(b)
	sw.size += n
	return n, err
}

// Hijack passes through to the underlying ResponseWriter if it supports hijacking.
// This is critical — without it, the proxy handler can't hijack connections.
func (sw *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := sw.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// LoggingMiddleware logs HTTP requests with method, path, status, duration, and size.
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)

		duration := time.Since(start)

		// Skip logging for health checks (noisy)
		if r.URL.Path == "/health" {
			return
		}

		attrs := []slog.Attr{
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", sw.status),
			slog.String("duration", duration.Round(time.Microsecond).String()),
			slog.Int("bytes", sw.size),
		}
		if clientID := auth.ClientIDFrom(r.Context()); clientID != "" {
			attrs = append(attrs, slog.String("client_id", clientID))
		}
		if r.URL.RawQuery != "" {
			attrs = append(attrs, slog.String("query", r.URL.RawQuery))
		}

		level := slog.LevelInfo
		if sw.status >= 500 {
			level = slog.LevelError
		} else if sw.status >= 400 {
			level = slog.LevelWarn
		}

		slog.LogAttrs(r.Context(), level, "http request", attrs...)
	})
}
