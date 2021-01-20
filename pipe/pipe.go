package pipe

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

var (
	_ net.Addr     = (*Addr)(nil)
	_ net.Conn     = (*Conn)(nil)
	_ net.Listener = (*Listener)(nil)
)

type Addr Listener

func ResolveAddr(s string) *Addr {
	l := &Listener{
		Path: s,
	}
	return (*Addr)(l)
}

func (a *Addr) Network() string {
	return "in-memory pipe"
}

func (a *Addr) String() string {
	return a.Path
}

type Listener struct {
	Path string

	conns  chan net.Conn
	closed chan struct{}
}

func Listen(a *Addr) (net.Listener, error) {
	l := (*Listener)(a)
	l.conns = make(chan net.Conn, 4)
	l.closed = make(chan struct{})
	return l, nil
}

func (l *Listener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, os.ErrClosed
	case c := <-l.conns:
		return c, nil
	}
	return nil, os.ErrClosed
}

func (l *Listener) Addr() net.Addr {
	return (*Addr)(l)
}

func (l *Listener) Close() error {
	select {
	case <-l.closed:
		return nil
	default:
		close(l.closed)
	}
	return nil
}

func (l *Listener) dial() (net.Conn, error) {
	c1, c2 := Pipe()
	select {
	case l.conns <- c1:
		return c2, nil
	case <-l.closed:
		return nil, os.ErrClosed
	}
	return nil, os.ErrClosed
}

type Conn struct {
	conn   net.Conn
	pipe   *Conn
	closed chan struct{}
}

func Dial(a *Addr) (net.Conn, error) {
	return (*Listener)(a).dial()
}

func Pipe() (*Conn, *Conn) {
	c1, c2 := net.Pipe()
	l := &Conn{
		conn:   c1,
		closed: make(chan struct{}),
	}
	r := &Conn{
		conn:   c2,
		closed: make(chan struct{}),
	}
	l.pipe = r
	r.pipe = l
	return l, r
}

func (c *Conn) Read(b []byte) (int, error) {
	n, err := c.conn.Read(b)
	if err == nil {
		return n, nil
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		select {
		case <-c.closed:
			return n, io.EOF
		default:
		}
	}

	return n, fmt.Errorf("read from pipe.Conn error: %w", err)
}

func (c *Conn) Write(b []byte) (int, error) {
	return c.conn.Write(b)
}

func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *Conn) Close() error {
	return c.conn.Close()
}

func (c *Conn) CloseWrite() error {
	select {
	case <-c.pipe.closed:
	default:
		close(c.pipe.closed)
		c.pipe.SetReadDeadline(time.Now())
	}
	return nil
}
