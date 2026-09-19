// Package resume 在 TCP 新流的 v2 头之后交换续传水位。
//
// 防火墙切断旧节点时，smux 还能把 Write 当成功（数据停在旧节点缓冲里）。
// Proxy 已经向游戏 TCP 回了 ACK，这些字节再也读不回来。
// 换流时用双方计数对齐：只重放「对端没收到」的那段，避免整段重复。
//
//	Backend → Proxy：已交给玩家的下行字节数
//	Proxy  → Backend：已交给游戏的上行字节数
//
// Server 只做透明拷贝，不必升级。Backend 与 Proxy 必须一起部署。
package resume

import (
	"bytes"
	"encoding/binary"
	"io"
)

// Magic 8 字节，放在 v2 头之后、游戏字节流之前。
var Magic = []byte("GSRSUM01")

const Size = 16

// Reject 是 Proxy 回报的不可续传标记（请求水位已滚出 Ring）。
// 继续使用缺字节的流会导致游戏协议错位，必须让本连接明确失败。
const Reject = ^uint64(0)

// Write 写出续传记录。
func Write(w io.Writer, n uint64) error {
	var b [Size]byte
	copy(b[:8], Magic)
	binary.BigEndian.PutUint64(b[8:], n)
	_, err := w.Write(b[:])
	return err
}

// Read 读一条续传记录。
// leftover 非空表示对端未升级（前 8 字节不是魔数），调用方必须把 leftover 当业务数据。
func Read(r io.Reader) (n uint64, leftover []byte, err error) {
	var b [Size]byte
	if _, err = io.ReadFull(r, b[:8]); err != nil {
		return 0, nil, err
	}
	if !bytes.Equal(b[:8], Magic) {
		out := make([]byte, 8)
		copy(out, b[:8])
		return 0, out, nil
	}
	if _, err = io.ReadFull(r, b[8:]); err != nil {
		return 0, nil, err
	}
	return binary.BigEndian.Uint64(b[8:]), nil, nil
}
