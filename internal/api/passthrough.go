package api

// TLS passthrough ("tls-passthrough" tunnel mode).
//
// When TLS is enabled, every accepted TCP connection first passes through
// sniListener, which reads (but does not terminate) the TLS ClientHello and
// extracts the SNI hostname. If that hostname resolves — under the same
// routing rules as HTTP Host routing — to a live tunnel in tls-passthrough
// mode, the raw connection is handed to the WebSocket relay with the peeked
// bytes replayed first, and the tunnel owner's own TLS server completes the
// handshake. The relay never holds a key for that session and only ever
// forwards ciphertext.
//
// Every other connection (no SNI, unknown host, relay-mode tunnel, the API
// host, non-TLS bytes, malformed/oversized/slow ClientHello) is handed to the
// regular http.Server TLS stack with the peeked bytes replayed verbatim, so
// its behaviour is unchanged.

import (
	"errors"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/nullbore/nullbore-server/internal/tunnel"
	"golang.org/x/crypto/cryptobyte"
)

const (
	// sniPeekTimeout bounds how long we wait for a complete ClientHello
	// before giving up on SNI routing. Legitimate clients send it
	// immediately after the TCP handshake. On timeout the connection is
	// NOT dropped: it is handed to http.Server with whatever was read, and
	// http.Server applies its own ReadTimeout from there, as before.
	sniPeekTimeout = 5 * time.Second

	// sniPeekMaxBytes caps how much we buffer while looking for the end of
	// the ClientHello. Real-world ClientHellos (including post-quantum key
	// shares) are ~0.5–2 KB. Exceeding the cap falls back to http.Server.
	sniPeekMaxBytes = 32 << 10

	tlsRecordHeaderLen          = 5
	tlsRecordTypeHandshake      = 0x16
	tlsHandshakeTypeClientHello = 0x01
	tlsMaxRecordPayload         = 1 << 14 // TLSPlaintext.length limit (RFC 8446 §5.1)
)

var (
	errNotTLSHandshake      = errors.New("sni: not a TLS handshake record")
	errNotClientHello       = errors.New("sni: first handshake message is not a ClientHello")
	errClientHelloTooLarge  = errors.New("sni: ClientHello exceeds peek limit")
	errMalformedClientHello = errors.New("sni: malformed ClientHello")
	errInvalidSNI           = errors.New("sni: invalid server name")
)

// peekClientHello reads from r exactly the TLS records needed to assemble
// the first handshake message — never a byte more — and returns the SNI host
// name from it ("" if the ClientHello carries none).
//
// raw always holds every byte consumed from r, on success AND on error, so
// the caller can replay it verbatim to whoever handles the connection next.
// Records may fragment the ClientHello arbitrarily (RFC 8446 §5.1); reads may
// return short. Total consumption is bounded by maxBytes.
func peekClientHello(r io.Reader, maxBytes int) (raw []byte, sni string, err error) {
	raw = make([]byte, 0, 2048)
	var hs []byte // reassembled handshake-layer bytes
	for {
		// Record header.
		if len(raw)+tlsRecordHeaderLen > maxBytes {
			return raw, "", errClientHelloTooLarge
		}
		var hdr [tlsRecordHeaderLen]byte
		n, err := io.ReadFull(r, hdr[:])
		raw = append(raw, hdr[:n]...)
		if err != nil {
			return raw, "", err
		}
		if hdr[0] != tlsRecordTypeHandshake || hdr[1] != 3 {
			return raw, "", errNotTLSHandshake
		}
		recLen := int(hdr[3])<<8 | int(hdr[4])
		if recLen == 0 || recLen > tlsMaxRecordPayload {
			return raw, "", errMalformedClientHello
		}
		if len(raw)+recLen > maxBytes {
			return raw, "", errClientHelloTooLarge
		}

		// Record payload.
		start := len(raw)
		raw = append(raw, make([]byte, recLen)...)
		n, err = io.ReadFull(r, raw[start:])
		raw = raw[:start+n]
		if err != nil {
			return raw, "", err
		}
		hs = append(hs, raw[start:]...)

		if len(hs) < 4 {
			continue
		}
		if hs[0] != tlsHandshakeTypeClientHello {
			return raw, "", errNotClientHello
		}
		msgLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
		if 4+msgLen > maxBytes {
			return raw, "", errClientHelloTooLarge
		}
		if len(hs) >= 4+msgLen {
			sni, err := parseClientHelloSNI(hs[4 : 4+msgLen])
			return raw, sni, err
		}
	}
}

// parseClientHelloSNI extracts the server_name (host_name) extension from a
// ClientHello handshake body (the bytes after the 4-byte handshake header).
// Returns "" with a nil error when the ClientHello has no SNI.
func parseClientHelloSNI(body []byte) (string, error) {
	s := cryptobyte.String(body)
	var (
		version     uint16
		random      []byte
		sessionID   cryptobyte.String
		cipherSuite cryptobyte.String
		compression cryptobyte.String
	)
	if !s.ReadUint16(&version) ||
		!s.ReadBytes(&random, 32) ||
		!s.ReadUint8LengthPrefixed(&sessionID) ||
		!s.ReadUint16LengthPrefixed(&cipherSuite) ||
		!s.ReadUint8LengthPrefixed(&compression) {
		return "", errMalformedClientHello
	}
	if s.Empty() {
		return "", nil // no extensions block at all
	}
	var exts cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&exts) || !s.Empty() {
		return "", errMalformedClientHello
	}
	for !exts.Empty() {
		var (
			extType uint16
			extData cryptobyte.String
		)
		if !exts.ReadUint16(&extType) || !exts.ReadUint16LengthPrefixed(&extData) {
			return "", errMalformedClientHello
		}
		if extType != 0 { // server_name
			continue
		}
		var list cryptobyte.String
		if !extData.ReadUint16LengthPrefixed(&list) || list.Empty() {
			return "", errMalformedClientHello
		}
		for !list.Empty() {
			var (
				nameType uint8
				name     cryptobyte.String
			)
			if !list.ReadUint8(&nameType) || !list.ReadUint16LengthPrefixed(&name) {
				return "", errMalformedClientHello
			}
			if nameType == 0 { // host_name
				return normalizeSNI(string(name))
			}
		}
		return "", nil
	}
	return "", nil
}

// normalizeSNI lowercases a host_name (DNS names compare case-insensitively,
// RFC 6066 §3) and rejects anything that is not a plausible DNS name. The
// result feeds routing lookups — including a query string sent to the
// dashboard resolvers — so only [a-z0-9-_.] in non-empty labels passes.
func normalizeSNI(name string) (string, error) {
	if len(name) == 0 || len(name) > 253 {
		return "", errInvalidSNI
	}
	name = strings.ToLower(name)
	prevDot := true // treats a leading dot as an empty label
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c == '.':
			if prevDot {
				return "", errInvalidSNI
			}
			prevDot = true
			continue
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return "", errInvalidSNI
		}
		prevDot = false
	}
	if prevDot { // trailing dot
		return "", errInvalidSNI
	}
	return name, nil
}

// passthroughHandler takes ownership of a raw inbound connection whose
// ClientHello (already consumed, in prefix) named a passthrough tunnel.
type passthroughHandler func(c net.Conn, prefix []byte)

// sniListener wraps the TLS-port TCP listener. Accept returns only
// connections destined for the regular http.Server TLS stack; passthrough
// connections are diverted before http.Server ever sees them.
//
// Peeking happens on a per-connection goroutine, never in Accept, so one slow
// client cannot stall the accept loop.
type sniListener struct {
	inner       net.Listener
	lookup      func(sni string) passthroughHandler
	peekTimeout time.Duration

	results  chan acceptResult // unbuffered: handoff only when Accept is waiting
	stop     chan struct{}     // closed by Close or a permanent inner Accept error
	stopOnce sync.Once
	stopErr  error // written once before stop is closed
}

type acceptResult struct {
	c   net.Conn
	err error
}

func newSNIListener(inner net.Listener, lookup func(sni string) passthroughHandler) *sniListener {
	return newSNIListenerWithTimeout(inner, lookup, sniPeekTimeout)
}

func newSNIListenerWithTimeout(inner net.Listener, lookup func(sni string) passthroughHandler, peekTimeout time.Duration) *sniListener {
	l := &sniListener{
		inner:       inner,
		lookup:      lookup,
		peekTimeout: peekTimeout,
		results:     make(chan acceptResult),
		stop:        make(chan struct{}),
	}
	go l.acceptLoop()
	return l
}

func (l *sniListener) shutdown(err error) {
	l.stopOnce.Do(func() {
		l.stopErr = err
		close(l.stop)
	})
}

func (l *sniListener) acceptLoop() {
	for {
		c, err := l.inner.Accept()
		if err != nil {
			// Temporary errors (e.g. EMFILE) are passed up so http.Server
			// applies its usual backoff; the unbuffered send means we don't
			// call inner.Accept again until it has.
			if te, ok := err.(interface{ Temporary() bool }); ok && te.Temporary() {
				select {
				case l.results <- acceptResult{err: err}:
					continue
				case <-l.stop:
					return
				}
			}
			l.shutdown(err)
			return
		}
		go l.handle(c)
	}
}

// handle peeks the ClientHello and either diverts the connection to a
// passthrough handler or delivers it (with the peeked bytes replayed) to
// Accept.
func (l *sniListener) handle(c net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("sni: panic handling connection from %s: %v", c.RemoteAddr(), r)
			c.Close()
		}
	}()

	_ = c.SetReadDeadline(time.Now().Add(l.peekTimeout))
	raw, sni, err := peekClientHello(c, sniPeekMaxBytes)
	// Clear the peek deadline before any handoff; http.Server and the relay
	// set their own.
	_ = c.SetReadDeadline(time.Time{})

	if err == nil && sni != "" {
		if h := l.lookup(sni); h != nil {
			h(c, raw)
			return
		}
	}

	var out net.Conn = c
	if len(raw) > 0 {
		out = &prefixConn{Conn: c, prefix: raw}
	}
	select {
	case l.results <- acceptResult{c: out}:
	case <-l.stop:
		c.Close()
	}
}

func (l *sniListener) Accept() (net.Conn, error) {
	select {
	case r := <-l.results:
		return r.c, r.err
	case <-l.stop:
		return nil, l.stopErr
	}
}

func (l *sniListener) Close() error {
	l.shutdown(net.ErrClosed)
	return l.inner.Close()
}

func (l *sniListener) Addr() net.Addr { return l.inner.Addr() }

// passthroughFor is the sniListener lookup: it returns a handler when sni
// resolves (via resolveTunnelForHost, i.e. the HTTP routing rules) to a
// tls-passthrough tunnel, and nil otherwise.
func (s *Server) passthroughFor(sni string) passthroughHandler {
	t, ok := s.resolveTunnelForHost(sni)
	if !ok || !t.IsTLSPassthrough() {
		return nil
	}
	return func(c net.Conn, prefix []byte) { s.servePassthrough(c, prefix, t) }
}

// servePassthrough relays a raw TLS connection to a passthrough tunnel.
//
// Kept from the relay path: suspension, TTL/expiry, the owner's IP allowlist
// (checked against the TCP peer — there is no X-Forwarded-For without
// HTTP), the per-tunnel rate limiter (one token per connection), byte
// accounting and idle-TTL touch (via the hub's pipe + AddRequest), and
// offline handling. Dropped, because they need plaintext: basic auth,
// inspection/request_log, body limits, status sniffing.
//
// Every rejection is a bare close: the relay holds no certificate for this
// hostname, so it has no way to send a readable error, and writing plaintext
// into a TLS stream would only produce a confusing client-side error.
func (s *Server) servePassthrough(c net.Conn, prefix []byte, t *tunnel.Tunnel) {
	reject := func(reason string) {
		log.Printf("passthrough rejected: tunnel=%s remote=%s reason=%s", t.ID, c.RemoteAddr(), reason)
		c.Close()
	}
	if t.Suspended {
		reject("suspended")
		return
	}
	if time.Now().After(t.ExpiresAt) {
		reject("expired")
		return
	}
	if s.cfg.IPChecker != nil {
		allowlist := s.cfg.IPChecker.GetIPAllowlistForUser(t.ClientID)
		if !checkIPAllowed(c.RemoteAddr().String(), allowlist) {
			reject("ip not allowed")
			return
		}
	}
	if !s.allowProxyRequest(t) {
		reject("rate limited")
		return
	}
	if err := s.wsHub.RelayRawConn(t.ID, c, prefix); err != nil {
		// Typically: tunnel registered but its client is not connected.
		reject("relay: " + err.Error())
		return
	}
	t.AddRequest()
}
