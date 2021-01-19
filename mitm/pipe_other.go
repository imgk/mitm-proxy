// +build !windows
// +build !linux
// +build !darwin

package mitm

import "net"

const (
	AddrPort80  = "127.0.0.1:80"
	AddrPort443 = "127.0.0.1:443"
)

func Listen(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}

func Dial(addr string) (net.Conn, error) {
	return net.Dial("tcp", addr)
}
