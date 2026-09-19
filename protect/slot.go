package protect

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"iossdk/internal/proto"
	"iossdk/internal/resume"
	"iossdk/internal/tunnel"

	"github.com/xtaci/smux"
)

type slot struct {
	pool  *tunnel.Pool
	proto string
	src   string
	dst   string

	mu       sync.Mutex
	cond     *sync.Cond
	building bool
	stream   *smux.Stream
	tun      *tunnel.Tunnel
	closed   bool

	peerClosed atomic.Bool
	lastTun    atomic.Pointer[tunnel.Tunnel]

	upRing   *resume.Ring
	downRecv atomic.Uint64
	downWG   sync.WaitGroup
	upWG     sync.WaitGroup
}

func newSlot(pool *tunnel.Pool, protoName, src, dst string) *slot {
	s := &slot{pool: pool, proto: protoName, src: src, dst: dst}
	s.cond = sync.NewCond(&s.mu)
	if protoName == "tcp" {
		s.upRing = resume.NewRing(resume.RingCap)
	}
	return s
}

func (s *slot) Acquire() (*smux.Stream, *tunnel.Tunnel, error) {
	s.mu.Lock()
	for {
		if s.closed {
			s.mu.Unlock()
			return nil, nil, errClosed
		}
		if s.stream != nil && s.tun.Alive() && !streamDead(s.stream) {
			st, tun := s.stream, s.tun
			s.mu.Unlock()
			return st, tun, nil
		}
		if !s.building {
			s.building = true
			break
		}
		s.cond.Wait()
	}
	old, oldTun := s.stream, s.tun
	s.stream, s.tun = nil, nil
	s.mu.Unlock()

	defer s.finishBuild()

	if old != nil {
		closeStreamAsync(old)
	}
	if oldTun != nil {
		oldTun.Release()
	}

	tun := s.pool.Active()
	if tun == nil {
		return nil, nil, errNoTunnel
	}
	st, err := tun.Open()
	if err != nil {
		if !tun.Alive() {
			s.pool.Drop(tun)
		} else {
			s.pool.Report(tun)
		}
		return nil, nil, err
	}
	_ = st.SetWriteDeadline(time.Now().Add(writeDeadline))
	pid, guid := currentIdent()
	err = proto.WriteHeader(st, s.proto, s.src, s.dst, pid, guid)
	_ = st.SetWriteDeadline(time.Time{})
	if err != nil {
		closeStreamAsync(st)
		s.failOpen(tun, err)
		return nil, nil, err
	}
	if s.proto == "tcp" {
		if err := s.handshakeTCP(st); err != nil {
			closeStreamAsync(st)
			if errors.Is(err, errResumeGap) {
				tun.Release()
				s.Close()
				return nil, nil, err
			}
			s.failOpen(tun, err)
			return nil, nil, err
		}
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		closeStreamAsync(st)
		tun.Release()
		return nil, nil, errClosed
	}
	s.stream, s.tun = st, tun
	s.lastTun.Store(tun)
	s.mu.Unlock()
	return st, tun, nil
}

func (s *slot) failOpen(tun *tunnel.Tunnel, err error) {
	if isWriteTimeout(err) {
		s.pool.Drop(tun)
		tun.MarkDead()
		tun.Release()
		return
	}
	if !tun.Alive() {
		s.pool.Drop(tun)
		tun.Release()
		return
	}
	tun.Release()
	s.pool.Report(tun)
}

func (s *slot) handshakeTCP(st *smux.Stream) error {
	if !s.waitWG(&s.downWG, resumeDrainDeadline) {
		return errors.New("等待下行水位超时")
	}
	if !s.waitWG(&s.upWG, resumeDrainDeadline) {
		return errors.New("等待上行水位超时")
	}
	_ = st.SetWriteDeadline(time.Now().Add(handshakeDeadline))
	if err := resume.Write(st, s.downRecv.Load()); err != nil {
		_ = st.SetWriteDeadline(time.Time{})
		return err
	}
	_ = st.SetReadDeadline(time.Now().Add(handshakeDeadline))
	upRecv, leftover, err := resume.Read(st)
	_ = st.SetReadDeadline(time.Time{})
	_ = st.SetWriteDeadline(time.Time{})
	if leftover != nil {
		return fmt.Errorf("proxy 未升级续传协议")
	}
	if err != nil {
		return err
	}
	if upRecv == resume.Reject {
		return fmt.Errorf("%w: Proxy 拒绝续传", errResumeGap)
	}
	end := s.upRing.End()
	if upRecv < s.upRing.Base() {
		return fmt.Errorf("%w: 上行 miss=%d", errResumeGap, s.upRing.Base()-upRecv)
	}
	replay := s.upRing.Slice(upRecv, end)
	if len(replay) == 0 {
		return nil
	}
	_ = st.SetWriteDeadline(time.Now().Add(15 * time.Second))
	_, werr := st.Write(replay)
	_ = st.SetWriteDeadline(time.Time{})
	return werr
}

func (s *slot) waitWG(wg *sync.WaitGroup, d time.Duration) bool {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

func (s *slot) finishBuild() {
	s.mu.Lock()
	s.building = false
	s.cond.Broadcast()
	s.mu.Unlock()
}

func (s *slot) Failed(bad *smux.Stream) {
	if !s.dropIfCurrent(bad) {
		return
	}
}

func (s *slot) FailTunnel(bad *smux.Stream) {
	s.mu.Lock()
	if s.stream != bad {
		s.mu.Unlock()
		return
	}
	tun := s.tun
	s.stream, s.tun = nil, nil
	s.mu.Unlock()
	if bad != nil {
		closeStreamAsync(bad)
	}
	if tun != nil {
		s.pool.Drop(tun)
		tun.MarkDead()
		tun.Release()
	}
}

func (s *slot) PeerClosed(bad *smux.Stream) {
	s.peerClosed.Store(true)
	s.dropIfCurrent(bad)
}

func (s *slot) wasPeerClosed() bool { return s.peerClosed.Load() }

func (s *slot) dropIfCurrent(bad *smux.Stream) bool {
	s.mu.Lock()
	if s.stream != bad {
		s.mu.Unlock()
		return false
	}
	tun := s.tun
	s.stream, s.tun = nil, nil
	s.mu.Unlock()
	if bad != nil {
		closeStreamAsync(bad)
	}
	if tun != nil {
		tun.Release()
		if !tun.Alive() {
			s.pool.Drop(tun)
		}
	}
	return true
}

func (s *slot) stillPrimary(tun *tunnel.Tunnel) bool {
	cur := s.pool.Active()
	return cur != nil && cur == tun && tun.Alive()
}

func (s *slot) Close() {
	s.mu.Lock()
	s.closed = true
	st, tun := s.stream, s.tun
	s.stream, s.tun = nil, nil
	s.cond.Broadcast()
	s.mu.Unlock()
	if st != nil {
		closeStreamAsync(st)
	}
	if tun != nil {
		tun.Release()
	}
}

func closeStreamAsync(st *smux.Stream) {
	if st != nil {
		go func() { _ = st.Close() }()
	}
}

func streamDead(s *smux.Stream) bool {
	select {
	case <-s.GetDieCh():
		return true
	default:
		return false
	}
}
