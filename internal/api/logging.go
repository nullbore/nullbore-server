package api

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/nullbore/nullbore-server/internal/auth"
)

// ctxKeyRequestID is the context key under which the per-request ID is stored.
type ctxKeyRequestID struct{}

// RequestIDFrom extracts the request ID from a request context. Returns
// empty string if no request ID was set (e.g. unit tests bypassing the
// middleware). Use this in error response bodies and structured logs to
// give operators a single string they can grep across logs/responses.
func RequestIDFrom(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyRequestID{}).(string); ok {
		return v
	}
	return ""
}

// RequestIDMiddleware ensures every request has an X-Request-ID. If the
// caller already provided one (e.g. an upstream proxy or load balancer),
// use it; otherwise generate a fresh 16-hex-char id. The id is stored in
// the request context, returned in the X-Request-ID response header so
// clients can echo it back to support, and surfaced in structured logs by
// LoggingMiddleware.
//
// Inbound IDs are length-capped to prevent log-injection or memory abuse
// from a malicious client sending a multi-megabyte X-Request-ID header.
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" || len(id) > 64 || !isPrintableASCII(id) {
			id = generateRequestID()
		}
		w.Header().Set("X-Request-ID", id)
		ctx := context.WithValue(r.Context(), ctxKeyRequestID{}, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func generateRequestID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

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
		if reqID := RequestIDFrom(r.Context()); reqID != "" {
			attrs = append(attrs, slog.String("request_id", reqID))
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
