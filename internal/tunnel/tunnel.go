// Package tunnel 管理到高防节点的 TCP/smux 隧道。
//
// 设计要点（取代旧版 switchNow/maintainBackup/dialingAddr 等并发标志堆）：
//
//   - 所有隧道状态变更（升主、建备、换节点）由唯一的 manager goroutine 串行执行，
//     不存在并发切换的竞态，也就不需要锁外的互斥标志。
//   - 读侧（relay 取隧道）通过 atomic.Pointer 无锁获取当前主隧道。
//   - 主隧道故障时：manager 先原节点重建（保住该 Server 上的身份端口），
//     失败再热备升主，最后才换别的节点拨号。
//   - relay 侧重试节奏（200ms）> 升主耗时，重试天然拿到新隧道，
//     无需「等待切换完成」的同步机制。
package tunnel

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/xtaci/smux"
)

// smux 隧道参数。
const (
	KeepAliveInterval = 1 * time.Second
	KeepAliveTimeout  = 3 * time.Second
	dialTimeout       = 8 * time.Second
	// socketBuf 隧道 TCP 收发缓冲。T4：Write 成功只代表进了本端内核缓冲，
	// 隧道死掉时这部分字节丢失且不会续传；缓冲越大丢得越多。
	// 游戏流量小，256KB 在 50ms RTT 下仍有 ~40Mbps，够用。
	socketBuf = 256 * 1024
)

func smuxConfig() *smux.Config {
	c := smux.DefaultConfig()
	c.KeepAliveInterval = KeepAliveInterval
	c.KeepAliveTimeout = KeepAliveTimeout
	c.MaxFrameSize = 4096
	c.MaxStreamBuffer = socketBuf
	c.MaxReceiveBuffer = 64 * 1024 * 1024
	return c
}

// Tunnel 一条到节点的 smux 会话。
// 生命周期: active（可用）→ retired（已摘除，等在用流归零后关闭）。
type Tunnel struct {
	addr    string
	conn    net.Conn
	sess    *smux.Session
	refs    atomic.Int32 // 在用 stream 计数
	retired atomic.Bool
	// dead 表示隧道被判定为不通（写超时等），关闭时直接 RST 丢弃内核里未发出的字节：
	// 这些字节 Backend 已按「未送达」在新隧道重发，若隧道随后恢复把它们补发出去就会重复（T4）。
	dead atomic.Bool
}

// Dial 建立到 addr 的隧道。
func Dial(addr string) (*Tunnel, error) {
	return DialContext(context.Background(), addr)
}

func (t *Tunnel) Addr() string { return t.addr }

// Open 打开一条新流并增加引用计数。
func (t *Tunnel) Open() (*smux.Stream, error) {
	// 先占 refs 再 OpenStream：避免「OpenStream 成功、refs 仍为 0」时 Retire 把 session 关掉（S4）。
	t.refs.Add(1)
	if t.retired.Load() || t.sess.IsClosed() {
		t.Release()
		return nil, fmt.Errorf("tunnel %s 不可用", t.addr)
	}
	s, err := t.sess.OpenStream()
	if err != nil {
		t.Release()
		return nil, err
	}
	if t.retired.Load() || t.sess.IsClosed() {
		_ = s.Close()
		t.Release()
		return nil, fmt.Errorf("tunnel %s 不可用", t.addr)
	}
	return s, nil
}

// Release 归还一个流引用；retired 且归零时真正关闭。
func (t *Tunnel) Release() {
	if t.refs.Add(-1) == 0 && t.retired.Load() {
		t.close()
	}
}

// Retire 摘除隧道（不再提供新流），等在用流归零后关闭。
func (t *Tunnel) Retire() {
	t.retired.Store(true)
	if t.refs.Load() == 0 {
		t.close()
	}
}

// Alive 报告隧道是否仍可提供服务。
func (t *Tunnel) Alive() bool {
	return !t.retired.Load() && !t.sess.IsClosed()
}

func (t *Tunnel) Retired() bool { return t.retired.Load() }

func (t *Tunnel) SessionClosed() bool {
	return t.sess != nil && t.sess.IsClosed()
}

// MarkDead 标记隧道级故障。Retire 仍会等所有引用释放后才真正关闭；
// 到那时必须用 RST 丢弃旧连接内核缓冲，避免它恢复后把已在新隧道重放的字节再送一次。
func (t *Tunnel) MarkDead() {
	t.dead.Store(true)
}

func (t *Tunnel) close() {
	if t.dead.Load() {
		if tcp, ok := t.conn.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0)
		}
	}
	if t.sess != nil {
		_ = t.sess.Close()
	}
}
