package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/xtaci/smux"
)

// DialContext 建立到 addr 的隧道；ctx 取消时立即放弃。
// Windows 上 Hyper-V/WinNAT 会排除一段本地端口，连出去时报
// WSAEACCES（forbidden by its access permissions）。这是本机端口问题，
// 不是对端挂了。每次换新的本地端口重试，不能据此切高防节点。
func DialContext(ctx context.Context, addr string) (*Tunnel, error) {
	var last error
	for i := 0; i < 16; i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		conn, err := dialTCP(ctx, addr)
		if err != nil {
			last = err
			if isLocalAccessDenied(err) {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(40 * time.Millisecond):
				}
				continue
			}
			return nil, fmt.Errorf("dial %s: %w", addr, err)
		}
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetNoDelay(true)
			_ = tcp.SetKeepAlive(true)
			_ = tcp.SetKeepAlivePeriod(15 * time.Second)
			_ = tcp.SetReadBuffer(socketBuf)
			_ = tcp.SetWriteBuffer(socketBuf)
		}
		sess, err := smux.Client(conn, smuxConfig())
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		return &Tunnel{addr: addr, conn: conn, sess: sess}, nil
	}
	return nil, fmt.Errorf("dial %s: %w", addr, last)
}

func isLocalAccessDenied(err error) bool {
	if err == nil {
		return false
	}
	var op *net.OpError
	if errors.As(err, &op) {
		err = op.Err
	}
	var sys *os.SyscallError
	if errors.As(err, &sys) {
		err = sys.Err
	}
	if errno, ok := err.(syscall.Errno); ok && (errno == 10013 || errno == syscall.EACCES) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "forbidden by its access permissions") ||
		strings.Contains(s, "WSAEACCES")
}
