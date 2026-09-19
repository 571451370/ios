//go:build !windows

package tunnel

import (
	"context"
	"net"
)

func dialTCP(ctx context.Context, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: dialTimeout}
	return d.DialContext(ctx, "tcp", addr)
}
