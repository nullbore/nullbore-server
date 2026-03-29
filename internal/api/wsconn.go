package api

import (
	"net"
	"time"

	"github.com/gorilla/websocket"
)

// WSNetConn wraps a websocket.Conn into a net.Conn interface.
// This allows io.Copy to work directly on WebSocket connections
// without JSON framing overhead — raw byte streaming.
//
// Pattern borrowed from chisel (jpillora/chisel/share/cnet/conn_ws.go).
type WSNetConn struct {
	conn *websocket.Conn
	buf  []byte
}

func NewWSNetConn(conn *websocket.Conn) *WSNetConn {
	return &WSNetConn{conn: conn}
}

func (c *WSNetConn) Read(dst []byte) (int, error) {
	// Drain buffer from previous partial read
	if len(c.buf) > 0 {
		n := copy(dst, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}

	// Read next WebSocket message
	_, msg, err := c.conn.ReadMessage()
	if err != nil {
		return 0, err
	}

	// Copy as much as fits into dst
	n := copy(dst, msg)
	if n < len(msg) {
		// Buffer the remainder
		c.buf = make([]byte, len(msg)-n)
		copy(c.buf, msg[n:])
	}
	return n, nil
}

func (c *WSNetConn) Write(b []byte) (int, error) {
	if err := c.conn.WriteMessage(websocket.BinaryMessage, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *WSNetConn) Close() error {
	return c.conn.Close()
}

func (c *WSNetConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *WSNetConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *WSNetConn) SetDeadline(t time.Time) error {
	if err := c.conn.SetReadDeadline(t); err != nil {
		return err
	}
	return c.conn.SetWriteDeadline(t)
}

func (c *WSNetConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *WSNetConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
