//go:build windows

package tunnel

import (
	"context"
	"net"
	"syscall"
)

func dialTCP(ctx context.Context, addr string) (net.Conn, error) {
	d := net.Dialer{
		Timeout: dialTimeout,
		Control: func(_, _ string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			})
		},
	}
	return d.DialContext(ctx, "tcp", addr)
}
