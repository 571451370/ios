package tunnel

import (
	"net"
	"sort"
	"sync"
	"time"
)

// prober 周期性测量节点 TCP 握手延迟，产出优先级列表；
// 失败节点进入冷却期，避免反复拨号坏节点。
type prober struct {
	mu     sync.Mutex
	nodes  []string
	ranked []string
	// failedUntil: 节点冷却截止时刻
	failedUntil map[string]time.Time
	measuring   bool
	refreshAt   time.Time
	// gen 在 Replace 后递增，使进行中的测量作废并自动重测
	gen uint64
}

func newProber(nodes []string) *prober {
	return &prober{
		nodes:       dedup(nodes),
		failedUntil: make(map[string]time.Time),
	}
}

const (
	probeTimeout   = 3 * time.Second
	probeGap       = 30 * time.Second
	failedCooldown = 10 * time.Second
)

// Ranked 返回按延迟升序的可用节点（可能为空，触发异步重测）。
func (p *prober) Ranked() []string {
	p.mu.Lock()
	need := len(p.ranked) == 0 || time.Now().After(p.refreshAt)
	measuring := p.measuring
	p.mu.Unlock()
	if need && !measuring {
		go p.measure()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, len(p.ranked))
	copy(out, p.ranked)
	return out
}

func (p *prober) Fail(addr string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failedUntil[addr] = time.Now().Add(failedCooldown)
	// R3：唯一候选留在 ranked。踢掉后 Ranked 为空 → 冷却 10s 内测速也不回填，
	// 再加一次 measure + 拨号，单节点重建会超过 Proxy 12s/15s 等流窗口。
	if len(p.ranked) == 1 && p.ranked[0] == addr {
		return
	}
	for i, a := range p.ranked {
		if a == addr {
			p.ranked = append(p.ranked[:i], p.ranked[i+1:]...)
			break
		}
	}
}

// Replace 替换候选节点列表并触发重测。
func (p *prober) Replace(nodes []string) {
	p.mu.Lock()
	p.nodes = dedup(nodes)
	p.gen++
	p.mu.Unlock()
	go p.measure()
}

// refreshNow 同步等待一次新鲜的测速结果（「优化延迟」切换决策用）。
// abort 关闭时立即返回当前快照（不阻塞池关闭）。
// 新鲜判据是「refreshAt 在本函数开始之后被 measure 刷新过」：空 ranked
// （全节点失败）也是合法的完成状态，不因 len==0 白等到超时。
func (p *prober) refreshNow(abort <-chan struct{}) []string {
	p.mu.Lock()
	need := len(p.ranked) == 0 || time.Now().After(p.refreshAt)
	measuring := p.measuring
	started := time.Now()
	p.mu.Unlock()
	if !need {
		// 数据本来就在有效期内，直接用。
		p.mu.Lock()
		out := make([]string, len(p.ranked))
		copy(out, p.ranked)
		p.mu.Unlock()
		return out
	}
	if !measuring {
		go p.measure()
	}
	deadline := time.Now().Add(probeTimeout + time.Second)
	for {
		p.mu.Lock()
		fresh := !p.measuring && p.refreshAt.After(started)
		p.mu.Unlock()
		if fresh || time.Now().After(deadline) {
			break
		}
		select {
		case <-abort:
			// 池关闭：不再等待，返回现有快照（调用方随后会丢弃）。
			p.mu.Lock()
			out := make([]string, len(p.ranked))
			copy(out, p.ranked)
			p.mu.Unlock()
			return out
		case <-time.After(100 * time.Millisecond):
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, len(p.ranked))
	copy(out, p.ranked)
	return out
}

// nodesSnapshot 返回当前候选节点副本。
func (p *prober) nodesSnapshot() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string{}, p.nodes...)
}

// otherNode 返回 exclude 以外、未在冷却期的候选。
func (p *prober) otherNode(exclude string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for _, a := range p.nodes {
		if a == "" || a == exclude {
			continue
		}
		if until := p.failedUntil[a]; !until.IsZero() && now.Before(until) {
			continue
		}
		return a
	}
	return ""
}

func (p *prober) measure() {
	p.mu.Lock()
	if p.measuring {
		p.mu.Unlock()
		return
	}
	p.measuring = true
	gen := p.gen
	nodes := append([]string{}, p.nodes...)
	p.mu.Unlock()

	type item struct {
		addr string
		lat  time.Duration
	}
	ch := make(chan item, len(nodes))
	var wg sync.WaitGroup
	for _, addr := range nodes {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			start := time.Now()
			c, err := net.DialTimeout("tcp", addr, probeTimeout)
			if err != nil {
				return
			}
			_ = c.Close()
			ch <- item{addr, time.Since(start)}
		}(addr)
	}
	wg.Wait()
	close(ch)

	var ok []item
	for it := range ch {
		ok = append(ok, it)
	}
	sort.Slice(ok, func(i, j int) bool { return ok[i].lat < ok[j].lat })

	p.mu.Lock()
	defer p.mu.Unlock()
	p.measuring = false
	if p.gen != gen {
		go p.measure() // 测量期间名单已变，重测
		return
	}
	p.ranked = p.ranked[:0]
	now := time.Now()
	var cooled []string
	for _, it := range ok {
		if until := p.failedUntil[it.addr]; !until.IsZero() && now.Before(until) {
			cooled = append(cooled, it.addr)
			continue
		}
		p.ranked = append(p.ranked, it.addr)
	}
	// S1：冷却期内不要把 ranked 滤成空，否则 Fail 留住的唯一节点会被测速清掉，
	// 第一次拨号失败后 pick() 拿不到地址。
	if len(p.ranked) == 0 {
		p.ranked = append(p.ranked, cooled...)
	}
	p.refreshAt = now.Add(probeGap)
}

func dedup(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
