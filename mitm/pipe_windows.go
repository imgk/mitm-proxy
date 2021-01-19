// +build windows

package mitm

import (
	"net"

	"github.com/imgk/mitm-proxy/winpipe"
)

const (
	AddrPort80  = `\\.\pipe\ProtectedPrefix\Administrators\mitm-proxy-port80`
	AddrPort443 = `\\.\pipe\ProtectedPrefix\Administrators\mitm-proxy-port443`
)

func Listen(addr string) (net.Listener, error) {
	return winpipe.ListenPipe(addr, nil)
}

func Dial(addr string) (net.Conn, error) {
	return winpipe.DialPipe(addr, nil, nil)
}
