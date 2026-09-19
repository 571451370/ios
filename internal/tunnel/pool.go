package tunnel

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// Pool 高防节点隧道池：主备热备 + 智能调度 + 故障切换。
//
// 并发模型:
//
//	读侧  Active()/Report()   —— 任意 goroutine，无锁或非阻塞
//	写侧  primary/backup 只经 atomic CAS/Swap 修改：manager 是决策
//	       主脑（reconcile/applyOptSwitch 的换主与摘备）；后台拨号
//	       goroutine（buildBackup、optimizeAsync 拨号段）完成后按
//	       条件校验换入，不覆盖他者已建结果。
//
// manager 每 tick 执行一次 reconcile：
//  1. 主不可用 → 先原节点重建，失败再热备升主
//  2. 热备缺失 → 后台拨号补备（不阻塞主恢复路径）
type Pool struct {
	probe   *prober
	primary atomic.Pointer[Tunnel]
	backup  atomic.Pointer[Tunnel]

	reports chan string   // 失败上报（非阻塞投递）
	done    chan struct{} // 关闭信号
	start   sync.Once     // manager 唯一启动
	wg      sync.WaitGroup

	// dialCtx 随 Close 取消，让进行中的拨号立刻返回（T8）。
	dialCtx    context.Context
	dialCancel context.CancelFunc

	// 拨号互斥：同一时刻只允许一个后台建备
	dialingBackup atomic.Bool

	// optCh 「优化延迟」手动切换信号（容量 1，重复触发合并）。
	// 决策与拨号（慢操作）在临时 goroutine 出队执行，结果通过 optReady
	// 回到 manager 做瞬时换主——manager 不被测速/拨号阻塞。
	optCh    chan struct{}
	optReady chan optSwitch
}

// optSwitch 一次「优化延迟」的执行请求（optimizeAsync 产出，manager 消费）。
type optSwitch struct {
	tun           *Tunnel // 已拨好的新隧道（promoteBackup=false 时非 nil）
	addr          string  // 目标节点地址
	promoteBackup bool    // true = 升热备（零延迟路径，tun 为 nil）
}

// New 创建池。nodes 为空则池保持空（等待 Update 拉起 manager）。
func New(nodes []string) *Pool {
	ctx, cancel := context.WithCancel(context.Background())
	p := &Pool{
		probe:      newProber(nodes),
		reports:    make(chan string, 64),
		done:       make(chan struct{}),
		dialCtx:    ctx,
		dialCancel: cancel,
		optCh:      make(chan struct{}, 1),
		optReady:   make(chan optSwitch, 1),
	}
	p.ensureManager()
	return p
}

// ensureManager 启动 manager（幂等）。
func (p *Pool) ensureManager() {
	p.start.Do(func() {
		p.wg.Add(1)
		go p.manager()
	})
}

// Update 更新候选节点列表（配置刷新时调用）。
func (p *Pool) Update(nodes []string) {
	p.probe.Replace(nodes)
	if len(dedup(nodes)) == 0 {
		return
	}
	p.ensureManager()
	// 当前主不在新名单：隧道级摘除，促使切到新名单里的节点
	if cur := p.Active(); cur != nil && !contains(nodes, cur.Addr()) {
		p.Drop(cur)
	}
	// B3：热备同样不迁就旧名单——摘掉名单外热备，reconcile 的备保障会
	// 从新名单（probe.Ranked）重拨。否则主故障升备后仍落在旧节点上，
	// 配置要滞后到这条隧道自己死掉才生效。
	if bak := p.backup.Load(); bak != nil && !contains(nodes, bak.Addr()) {
		if p.backup.CompareAndSwap(bak, nil) {
			bak.Retire()
			log.Printf("[Pool] 热备 %s 不在新名单，摘除", bak.Addr())
		}
	}
}

// Active 返回当前主隧道（可能为 nil，调用方自行判活）。
func (p *Pool) Active() *Tunnel {
	t := p.primary.Load()
	if t == nil || !t.Alive() {
		return nil
	}
	return t
}

// Report 上报节点冷却（非阻塞；重复上报安全）。
// 只影响下次选点，不摘当前主——单条流 Open/写头失败不能拖垮所有连接（R1）。
func (p *Pool) Report(t *Tunnel) {
	if t == nil {
		return
	}
	select {
	case p.reports <- t.Addr():
	default: // 已有积压上报，丢弃即可（manager 会重测）
	}
}

// Drop 隧道级死亡（写超时 / 会话已关 / 名单变更）：冷却该节点，并摘除
// 「正是这条」主隧道。按指针比较，避免旧隧道同地址误伤已经升上去的新主。
func (p *Pool) Drop(t *Tunnel) {
	if t == nil {
		return
	}
	p.Report(t)
	if cur := p.primary.Load(); cur == t && !t.retired.Load() {
		t.Retire()
		log.Printf("[Pool] 主隧道 %s 隧道级故障，摘除", t.Addr())
	}
}

// Refresh 强制重新测速（「优化延迟」入口第一步）。
func (p *Pool) Refresh() {
	p.probe.Replace(p.probe.nodesSnapshot())
}

// TriggerReconnect 触发切换到测速最优节点（「优化延迟」入口第二步，对齐旧项目同名行为）。
// 异步投递给 manager（唯一写侧）执行：等测速完成后若最优节点不是当前主则换主。
func (p *Pool) TriggerReconnect() {
	select {
	case p.optCh <- struct{}{}:
	default: // 已有待处理的优化请求，合并
	}
}

// Close 关闭池及所有隧道。
func (p *Pool) Close() {
	select {
	case <-p.done:
		return
	default:
		close(p.done)
	}
	p.dialCancel()
	p.wg.Wait()
	if t := p.primary.Load(); t != nil {
		t.Retire()
	}
	if t := p.backup.Load(); t != nil {
		t.Retire()
	}
}

// ---- manager：决策主脑（换主/摘备在此执行）----

func (p *Pool) manager() {
	defer p.wg.Done()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-p.done:
			return
		case addr := <-p.reports:
			p.probe.Fail(addr) // 只冷却；摘主走 Drop（R1）
		case <-p.optCh:
			// 「优化延迟」：测速与拨号（慢操作）出队到临时 goroutine，
			// manager 只消费最终结果执行瞬时换主，不被阻塞（reconcile 照常跑）。
			go p.optimizeAsync()
		case sw := <-p.optReady:
			p.applyOptSwitch(sw)
		case <-tick.C:
		}
		p.reconcile()
	}
}

// optimizeAsync 「优化延迟」决策与拨号（在临时 goroutine 出队执行）。
// 换主动作不在此做——交由 manager 的 applyOptSwitch 统一执行。
func (p *Pool) optimizeAsync() {
	cur := p.Active()
	if cur == nil {
		return // 无主，reconcile 的主保障会拨号
	}
	ranked := p.probe.refreshNow(p.done)
	if len(ranked) == 0 {
		return
	}
	best := ranked[0]
	if best == cur.Addr() {
		return // 已是最优
	}
	// 热备恰是最优：零延迟升主（省一次拨号），请求 manager 执行。
	if bak := p.backup.Load(); bak != nil && bak.Alive() && bak.Addr() == best {
		p.sendOptSwitch(optSwitch{addr: best, promoteBackup: true})
		return
	}
	t, err := DialContext(p.dialCtx, best)
	if err != nil {
		log.Printf("[Pool] 优化延迟拨号 %s 失败: %v", best, err)
		if p.dialCtx.Err() == nil && !isLocalAccessDenied(err) {
			p.probe.Fail(best)
		}
		return
	}
	p.sendOptSwitch(optSwitch{tun: t, addr: best})
}

// sendOptSwitch 非阻塞投递切换请求（manager 忙不过来时丢弃本次优化，不积压）。
func (p *Pool) sendOptSwitch(sw optSwitch) {
	select {
	case p.optReady <- sw:
	case <-p.done:
		if sw.tun != nil {
			sw.tun.Retire() // 池已关闭，丢弃拨好的隧道
		}
	default:
		// B18：manager 忙（如 dialPrimary 最长 8s）时 optReady 满且池未关，
		// 没有 default 会把 optimizeAsync 卡在发送上。上一条结果未被消费
		// 说明已有更新鲜的切换在途，丢弃本次即可。
		if sw.tun != nil {
			sw.tun.Retire()
		}
		log.Printf("[Pool] 优化切换请求积压，丢弃 %s", sw.addr)
	}
}

// applyOptSwitch 执行换主（manager 写侧，瞬时）。决策期间池状态可能已变化：
// 目标已是当前主（别人切过了）或热备已被换时丢弃请求。
func (p *Pool) applyOptSwitch(sw optSwitch) {
	if p.dialCtx.Err() != nil {
		if sw.tun != nil {
			sw.tun.Retire()
		}
		return
	}
	// 热备升主路径
	if sw.promoteBackup {
		bak := p.backup.Load()
		if bak == nil || bak.Addr() != sw.addr || !bak.Alive() {
			return // 热备已变化（可能被 reconcile 消费或失效）
		}
		// 只消费刚校验过的这条热备；不能 Swap 掉校验后被别处替换的新热备。
		if !p.backup.CompareAndSwap(bak, nil) {
			return
		}
		if old := p.primary.Swap(bak); old != nil {
			old.Retire()
		}
		log.Printf("[Pool] 优化延迟: 热备升主 %s", bak.Addr())
		go p.buildBackup()
		return
	}
	// 拨号新隧道路径
	if cur := p.Active(); cur != nil && cur.Addr() == sw.addr {
		sw.tun.Retire() // 决策期间别人已切到该节点，丢弃重复
		return
	}
	if old := p.primary.Swap(sw.tun); old != nil {
		old.Retire()
	}
	log.Printf("[Pool] 优化延迟: 已切换到 %s", sw.addr)
	go p.buildBackup()
}

func (p *Pool) reconcile() {
	if p.Active() != nil {
		// 2. 备保障：后台拨号，不阻塞 manager。
		if b := p.backup.Load(); b == nil || !b.Alive() {
			if b != nil {
				if p.backup.CompareAndSwap(b, nil) {
					b.Retire()
				}
			}
			go p.buildBackup()
		}
		return
	}

	// 1. 主保障：热备升主（零延迟，对齐旧项目 reconnectToBest 行为）。
	// 会话身份已跨节点稳定（F1：Proxy sessionKey 优先 v2 头 GUID|dst，
	// Backend 算好、Server 只透传；身份端口仅是旧头退化 key），
	// 切换无任何身份损失——立即恢复流量优先于「留在原节点」的一切考量。
	// 旧版「原节点优先重建 + WSAEACCES 宽限」的历史使命（保身份）已随会话
	// 解耦而消失，只剩切换延迟成本（宽限期间玩家数据断流，游戏心跳敏感时被踢）。
	// 无热备时 dialPrimary 按探测排序选点：单节点场景自然重试原节点；
	// WSAEACCES 类本机故障 dialPrimary 内不冷却节点，下个周期继续重试。
	old := p.primary.Swap(nil)
	if old != nil {
		log.Printf("[Pool] 主隧道 %s 不可用 closed=%v retired=%v",
			old.Addr(), old.SessionClosed(), old.Retired())
		old.Retire()
	}
	bak := p.backup.Swap(nil)
	if bak != nil && bak.Alive() {
		p.primary.Store(bak)
		log.Printf("[Pool] 热备升主 %s", bak.Addr())
		go p.buildBackup()
		return
	}
	if bak != nil {
		bak.Retire()
	}
	p.dialPrimary()
}

// dialPrimary 同步拨号建立主隧道。失败则下一 tick 由 reconcile 重试。
func (p *Pool) dialPrimary() {
	addr := p.pick("")
	if addr == "" {
		return
	}
	t, err := DialContext(p.dialCtx, addr)
	if err != nil {
		if p.dialCtx.Err() != nil {
			return
		}
		if isLocalAccessDenied(err) {
			log.Printf("[Pool] 拨号 %s 本机套接字被拒绝，下个周期再试: %v", addr, err)
			return
		}
		log.Printf("[Pool] 拨号 %s 失败: %v", addr, err)
		p.probe.Fail(addr)
		return
	}
	// manager 串行执行，此处主必为空；防御性再确认
	if cur := p.Active(); cur != nil {
		t.Retire()
		return
	}
	p.primary.Store(t)
	log.Printf("[Pool] 主隧道 %s", addr)
}

// buildBackup 后台拨号补建热备。同一时刻只允许一个。
func (p *Pool) buildBackup() {
	if !p.dialingBackup.CompareAndSwap(false, true) {
		return
	}
	defer p.dialingBackup.Store(false)

	primary := p.Active()
	exclude := excludeAddr(primary)
	addr := p.pick(exclude)
	if addr == "" {
		// ranked 里往往只剩当前主（刚 Fail 的旧主被踢出，还要等 30s 测速才回去）。
		// 热备必须立刻重拨另一个节点，拨不通就等下一轮 reconcile，不能干等到测速。
		addr = p.probe.otherNode(exclude)
	}
	if addr == "" {
		return
	}
	t, err := DialContext(p.dialCtx, addr)
	if err != nil {
		if p.dialCtx.Err() == nil && !isLocalAccessDenied(err) {
			// WSAEACCES 是本机端口问题，不是节点故障，不冷却该节点。
			p.probe.Fail(addr)
			log.Printf("[Pool] 热备拨号 %s 失败: %v", addr, err)
		}
		return
	}
	// 拨号期间主/备都可能变化。不能把与当前主同地址的连接放进热备，
	// 也不能覆盖已经由另一轮建好的健康热备。
	if active := p.Active(); active != nil && active.Addr() == t.Addr() {
		t.Retire()
		return
	}
	// 拨号期间备可能已被补上
	if cur := p.backup.Load(); cur != nil && cur.Alive() {
		t.Retire()
		return
	}
	if cur := p.backup.Swap(t); cur != nil {
		cur.Retire()
	}
	log.Printf("[Pool] 热备就绪 %s", addr)
}

// pick 从探测结果中选择目标节点，排除 exclude。
func (p *Pool) pick(exclude string) string {
	for _, a := range p.probe.Ranked() {
		if a != exclude {
			return a
		}
	}
	return ""
}

func excludeAddr(t *Tunnel) string {
	if t == nil {
		return ""
	}
	return t.Addr()
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
