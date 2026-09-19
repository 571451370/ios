package protect

import (
	"errors"
	"net"
	"strconv"
	"time"

	"iossdk/internal/proto"
)

type udpFlow struct {
	dst    string
	slot   *slot
	engine *engine
}

func (e *engine) handleUDPPacket(from *net.UDPAddr, destIP net.IP, destPort int, payload []byte) {
	host := destIP.String()
	if v4 := destIP.To4(); v4 != nil {
		host = v4.String()
	}
	dst := net.JoinHostPort(host, strconv.Itoa(destPort))
	flow := e.udpFlow(dst)
	deadline := time.Now().Add(retryBudget)
	client := from.String()
	for time.Now().Before(deadline) {
		st, _, err := flow.slot.Acquire()
		if err != nil {
			if errors.Is(err, errClosed) {
				return
			}
			if !e.sleepUntil(deadline) {
				return
			}
			continue
		}
		_ = st.SetWriteDeadline(time.Now().Add(writeDeadline))
		werr := proto.WriteFrame(st, client, payload)
		_ = st.SetWriteDeadline(time.Time{})
		if werr == nil {
			return
		}
		if isWriteTimeout(werr) {
			flow.slot.FailTunnel(st)
		} else {
			flow.slot.Failed(st)
		}
		if !e.sleepUntil(deadline) {
			return
		}
	}
}

func (e *engine) udpFlow(dst string) *udpFlow {
	e.udpMu.Lock()
	f, ok := e.udps[dst]
	if !ok {
		f = &udpFlow{dst: dst, slot: newSlot(e.pool, "udp", "0.0.0.0:0", dst), engine: e}
		e.udps[dst] = f
		go f.downLoop()
	}
	e.udpMu.Unlock()
	return f
}

func (e *engine) closeUDP() {
	e.udpMu.Lock()
	for dst, f := range e.udps {
		f.slot.Close()
		delete(e.udps, dst)
	}
	e.udpMu.Unlock()
}

func (f *udpFlow) downLoop() {
	defer recoverConn("UDP↓")
	buf := make([]byte, proto.MaxDataLen)
	for {
		s, tun, err := f.slot.Acquire()
		if err != nil {
			if errors.Is(err, errClosed) {
				return
			}
			if !f.engine.sleepBackoff() {
				return
			}
			continue
		}
		_ = s.SetReadDeadline(time.Now().Add(retiredPollInterval))
		client, data, rerr := proto.ReadFrame(s, buf)
		if rerr != nil {
			if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
				if tun != nil && tun.Retired() {
					f.slot.Failed(s)
				}
				continue
			}
			f.slot.Failed(s)
			continue
		}
		ua, err := net.ResolveUDPAddr("udp", client)
		if err != nil {
			continue
		}
		// 回包头必须是虚拟目标（游戏服），hook 的 recvfrom 用它伪装 from。
		// 不能填 client：那是玩家本机端口，游戏会以为包来自自己。
		fromAddr, err := net.ResolveUDPAddr("udp", f.dst)
		if err != nil {
			continue
		}
		pkt := encodeUDPLocal(fromAddr, data)
		_ = f.engine.udpConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = f.engine.udpConn.WriteToUDP(pkt, ua)
		_ = f.engine.udpConn.SetWriteDeadline(time.Time{})
	}
}
