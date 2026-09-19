package resume

import "sync"

// RingCap 覆盖 smux 流缓冲 + 隧道 socket 缓冲 + 黑洞窗口内的游戏流量。
// 这是上限，不预分配；在线会话多时不能每条连接固定占用数 MB。
// 必须不低于 Proxy 侧 heldSoftLimit（T8）：切换窗口内 held 可积累到 4MB，
// attachDrain 会把它全量 Append 进 downRing——容量不足时滚掉前段，玩家
// 实收水位（downRecv）追不上滚后的 Base，下一次握手 Reject → closeGame
// 拆线（日志表现为「续传窗口不足」）。取 4MB 而非硬限 8MB：held 触及
// 硬限的路径（parkHeldLocked）直接拆线、不进 Ring，无需覆盖。
const RingCap = 4 * 1024 * 1024
const ringInitCap = 64 * 1024

// Ring 按绝对字节偏移保存最近一段已写出数据，供换流重放。
type Ring struct {
	mu   sync.Mutex
	buf  []byte
	max  int
	base uint64 // buf[0] 对应的绝对偏移
	end  uint64 // 下一写入的绝对偏移
}

func NewRing(max int) *Ring {
	if max <= 0 {
		max = RingCap
	}
	return &Ring{max: max}
}

func (r *Ring) End() uint64 {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.end
}

func (r *Ring) Base() uint64 {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.base
}

func (r *Ring) growLocked(need int) {
	if need > r.max {
		need = r.max
	}
	if len(r.buf) >= need {
		return
	}
	n := len(r.buf)
	if n == 0 {
		n = ringInitCap
		if n > r.max {
			n = r.max
		}
	}
	for n < need {
		n *= 2
		if n >= r.max {
			n = r.max
			break
		}
	}
	next := make([]byte, n)
	copy(next, r.buf[:int(r.end-r.base)])
	r.buf = next
}

// Append 追加已写出的字节。超出容量时丢掉最旧的数据。
func (r *Ring) Append(p []byte) {
	if r == nil || len(p) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	total := len(p)
	if total >= r.max {
		r.growLocked(r.max)
		tail := p[total-r.max:]
		copy(r.buf, tail)
		// 绝对偏移按原始写入长度推进，不是按截断后保留的长度推进。
		r.end += uint64(total)
		r.base = r.end - uint64(len(tail))
		return
	}
	used := int(r.end - r.base)
	r.growLocked(used + total)
	if need := used + total - len(r.buf); need > 0 {
		copy(r.buf, r.buf[need:used])
		r.base += uint64(need)
		used -= need
	}
	copy(r.buf[used:], p)
	r.end += uint64(total)
}

// Slice 返回 [from, to) 的拷贝。from 小于仍保留的范围时从 base 起（部分续传）。
func (r *Ring) Slice(from, to uint64) []byte {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if to > r.end {
		to = r.end
	}
	if from < r.base {
		from = r.base
	}
	if from >= to {
		return nil
	}
	out := make([]byte, to-from)
	copy(out, r.buf[from-r.base:to-r.base])
	return out
}
