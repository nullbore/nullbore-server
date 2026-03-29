package api

import (
	"bufio"
	"log"
	"net"
	"net/http"
	"time"
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

		log.Printf("%s %s %d %s %d bytes",
			r.Method,
			r.URL.Path,
			sw.status,
			duration.Round(time.Microsecond),
			sw.size,
		)
	})
}
