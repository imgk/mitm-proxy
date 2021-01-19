// +build linux darwin

package mitm

import (
	"net"
	"os"
)

var (
	AddrPort80  = "/tmp/mitm-proxy-port80.sock"
	AddrPort443 = "/tmp/mitm-proxy-port443.sock"
)

func Listen(addr string) (net.Listener, error) {
	os.Remove(addr)
	return net.Listen("unix", addr)
}

func Dial(addr string) (net.Conn, error) {
	return net.Dial("unix", addr)
}
