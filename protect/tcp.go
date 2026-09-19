package protect

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"iossdk/internal/proto"
	"iossdk/internal/tunnel"

	"github.com/xtaci/smux"
)

func (e *engine) handleTCP(local net.Conn, dst string) {
	defer recoverConn("TCP")
	defer local.Close()
	src := local.RemoteAddr().String()
	if tcp, ok := local.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	}
	s := newSlot(e.pool, "tcp", src, dst)
	defer s.Close()
	logf("[TCP] %s → %s", src, dst)

	var playerGone atomic.Bool
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer recoverConn("TCP↑")
		defer wg.Done()
		defer s.Close()
		buf := make([]byte, 32*1024)
		for {
			n, rErr := local.Read(buf)
			if n > 0 {
				if !e.pumpUp(s, buf[:n]) {
					return
				}
			}
			if rErr != nil {
				playerGone.Store(true)
				return
			}
		}
	}()
	go func() {
		defer recoverConn("TCP↓")
		defer wg.Done()
		buf := make([]byte, 32*1024)
		var st *smux.Stream
		var tun *tunnel.Tunnel
		emptyEOF := 0
		gotDown := false
		var eofTun *tunnel.Tunnel
		for {
			if st == nil {
				var err error
				st, tun, err = s.Acquire()
				if err != nil {
					if errorsIsClosed(err) {
						return
					}
					if !e.sleepBackoff() {
						return
					}
					continue
				}
				gotDown = false
				if eofTun != nil && tun != eofTun {
					emptyEOF = 0
					eofTun = nil
				}
			}
			_ = st.SetReadDeadline(time.Now().Add(retiredPollInterval))
			s.downWG.Add(1)
			n, rErr := st.Read(buf)
			if n > 0 {
				gotDown = true
				emptyEOF = 0
				_, wErr := local.Write(buf[:n])
				if wErr != nil {
					s.downWG.Done()
					return
				}
				s.downRecv.Add(uint64(n))
			}
			s.downWG.Done()
			if rErr == nil {
				continue
			}
			if isWriteTimeout(rErr) {
				if tun != nil && tun.Alive() {
					continue
				}
				s.Failed(st)
				st, tun = nil, nil
				continue
			}
			if ioEOF(rErr) {
				// 节点被禁/隧道死时 smux 也是 EOF，不能当成游戏服关连接。
				if tun != nil && tun.Alive() && s.stillPrimary(tun) {
					time.Sleep(300 * time.Millisecond)
					if tun != nil && tun.Alive() && s.stillPrimary(tun) {
						if !gotDown {
							emptyEOF++
							eofTun = tun
							if emptyEOF >= 2 {
								logf("[TCP] 判定游戏服关闭 %s → %s", src, dst)
								s.PeerClosed(st)
								return
							}
							logf("[TCP] 空 EOF，重建 (%d/2) %s → %s", emptyEOF, src, dst)
						} else {
							logf("[TCP] 节点流 EOF，重建续传 %s → %s", src, dst)
						}
					}
				}
				s.Failed(st)
				st, tun = nil, nil
				if !e.sleepBackoff() {
					return
				}
				continue
			}
			s.Failed(st)
			st, tun = nil, nil
			if !e.sleepBackoff() {
				return
			}
		}
	}()
	wg.Wait()
	// 只有游戏本机 socket 断开才发 exit。切节点/握手失败不能拆源站会话。
	if playerGone.Load() && !s.wasPeerClosed() {
		e.forwardExit(src, dst)
	}
}

func (e *engine) pumpUp(s *slot, data []byte) bool {
	deadline := time.Now().Add(retryBudget)
	for len(data) > 0 && time.Now().Before(deadline) {
		st, tun, err := s.Acquire()
		if err != nil {
			if errorsIsClosed(err) {
				return false
			}
			if !e.sleepUntil(deadline) {
				return false
			}
			continue
		}
		if tun != nil && !tun.Alive() {
			s.Failed(st)
			continue
		}
		_ = st.SetWriteDeadline(time.Now().Add(writeDeadline))
		s.upWG.Add(1)
		n, wErr := st.Write(data)
		if n > 0 {
			s.upRing.Append(data[:n])
			data = data[n:]
		}
		s.upWG.Done()
		_ = st.SetWriteDeadline(time.Time{})
		if wErr == nil {
			return true
		}
		if ioEOF(wErr) && s.stillPrimary(tun) {
			time.Sleep(300 * time.Millisecond)
			if tun.Alive() && s.stillPrimary(tun) {
				s.PeerClosed(st)
				return false
			}
			s.Failed(st)
			continue
		}
		if isWriteTimeout(wErr) {
			s.FailTunnel(st)
		} else {
			s.Failed(st)
		}
	}
	return len(data) == 0
}

func (e *engine) forwardExit(src, dst string) {
	defer recoverConn("TCP-exit")
	var tun *tunnel.Tunnel
	for i := 0; i < 5; i++ {
		if tun = e.pool.Active(); tun != nil {
			break
		}
		if !e.sleepBackoff() {
			return
		}
	}
	if tun == nil {
		return
	}
	st, err := tun.Open()
	if err != nil {
		return
	}
	defer tun.Release()
	_ = st.SetWriteDeadline(time.Now().Add(writeDeadline))
	pid, guid := currentIdent()
	if err := proto.WriteHeader(st, proto.ProtoExit, src, dst, pid, guid); err != nil {
		logf("[TCP] exit 失败 %s → %s: %v", src, dst, err)
	}
	closeStreamAsync(st)
}

func errorsIsClosed(err error) bool {
	return err == errClosed || err == errResumeGap
}

func logf(format string, args ...any) {
	log.Printf("[protect] "+format, args...)
}
