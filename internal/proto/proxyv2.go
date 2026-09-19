// Package proto 定义全链路共用的线路协议：
//
//	游戏 → Frontend(本地监听) → 管道 → Backend → smux隧道 → Server → 源站Proxy → 游戏
//
// 所有环节的地址交接统一使用 HAProxy PROXY protocol v2：
//   - TCP  : 每条连接/流一个 v2 头，后跟原始字节流
//   - UDP  : 每个数据报一个 v2 datagram 头，后跟 payload
//   - 帧封装: Frontend↔Backend 与 Backend↔Server 之间，UDP 以
//     [2B addrLen][addr][2B dataLen][data] 帧承载（见 udpframe.go），
//     addr 为玩家原始地址，帧流走 smux stream。
package proto

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
)

var v2Signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

const (
	V2SigLen = 12
	v2VerCmd = 0x21
	// v2VerCmdExit 内部扩展命令（v2, cmd=2）：玩家侧已断开，
	// 通告源站立刻关闭同 src|dst 的游戏会话，而不是当隧道切换空等。
	v2VerCmdExit = 0x22
	famTCPv4     = 0x11
	famTCPv6     = 0x12
	famUDPv4     = 0x21
	famUDPv6     = 0x22
	v2HdrLen     = 16
)

// ProtoExit 是 ReadHeader 对退出通告返回的协议名。
// 该头只有地址、没有后续字节流；Server 透传，Proxy 收到即 closeGame。
const ProtoExit = "exit"

// Addr PROXY v2 头携带的地址对。
// PID 是 4 字节玩家装机身份（盾侧 SHA1(MachineGuid)[:4]）；GUID 是完整
// MachineGuid（36 字符）。PID 只是 GUID 的截断，生日空间 2^32，多人在线
// 可撞（B9：撞 key → 撞身份端口 → 切节点端口漂移），TCP 会话 key 优先用
// 全长 GUID + 虚拟 dst，PID 保留作旧头兼容。两者追加在地址区尾部：IPv4 头 addrLen
// 12→16→52、IPv6 36→40→76。旧格式（12/36）解出零值 PID 和空 GUID，
// 向后兼容。Server/Proxy 把身份编进会话 key 区分玩家——本机回环地址
// （127.0.0.1:port）跨玩家可能完全相同，不能只靠它。
type Addr struct {
	Src  string
	Dst  string
	PID  [4]byte
	GUID string
}

func IsV2Signature(b []byte) bool {
	return len(b) >= V2SigLen && bytes.Equal(b[:V2SigLen], v2Signature)
}

// WriteHeader 向流写入 PROXY v2 头（TCP 场景）。
// pid/guid 是玩家装机身份（盾→Server 必带；Server→Proxy 仅 UDP 透传流
// 需要，TCP/exit 靠身份端口已含）。guid 非 36 字符按无 GUID 处理，
// pid 零值且无 GUID 时退化为无身份的旧布局。
func WriteHeader(w io.Writer, proto, srcAddr, dstAddr string, pid [4]byte, guid string) error {
	hdr, err := buildHeader(proto, srcAddr, dstAddr, pid, guid)
	if err != nil {
		return err
	}
	_, err = w.Write(hdr)
	return err
}

// ReadHeader 从流中读取 PROXY v2 头。
func ReadHeader(r io.Reader) (*Addr, string, error) {
	var prefix [16]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, "", err
	}
	if !IsV2Signature(prefix[:]) {
		return nil, "", fmt.Errorf("proxy v2: 签名无效")
	}
	addrLen := binary.BigEndian.Uint16(prefix[14:16])
	// 12/36 = 无身份（旧握手头）；16/40 = +PID；52/76 = +PID+GUID（B9）。
	if addrLen != 12 && addrLen != 16 && addrLen != 36 && addrLen != 40 && addrLen != 52 && addrLen != 76 {
		return nil, "", fmt.Errorf("proxy v2: addrLen=%d", addrLen)
	}
	addr := make([]byte, addrLen)
	if _, err := io.ReadFull(r, addr); err != nil {
		return nil, "", err
	}
	a, protoName, err := parseAddr(prefix[12], prefix[13], addr)
	return a, protoName, err
}

// BuildDatagram 构造不含 payload 的 UDP PROXY v2 头。pid/guid 语义同 WriteHeader。
func BuildDatagram(srcAddr, dstAddr string, pid [4]byte, guid string) ([]byte, error) {
	return buildHeader("udp", srcAddr, dstAddr, pid, guid)
}

// ParseDatagram 解析带 PROXY v2 头的 UDP 数据报。
func ParseDatagram(packet []byte) (*Addr, []byte, error) {
	if len(packet) < v2HdrLen {
		return nil, nil, fmt.Errorf("proxy v2 datagram 过短")
	}
	if !IsV2Signature(packet) {
		return nil, nil, fmt.Errorf("proxy v2 datagram 签名无效")
	}
	addrLen := int(binary.BigEndian.Uint16(packet[14:16]))
	total := v2HdrLen + addrLen
	if len(packet) < total {
		return nil, nil, fmt.Errorf("proxy v2 datagram 地址不完整")
	}
	a, _, err := parseAddr(packet[12], packet[13], packet[v2HdrLen:total])
	if err != nil {
		return nil, nil, err
	}
	return a, packet[total:], nil
}

// v2GuidLen GUID 定长：MachineGuid 标准 36 字符（8-4-4-4-12 带连字符）。
const v2GuidLen = 36

// identSuffix 地址区尾部身份后缀：GUID 可用则 PID+GUID（52/76 新布局），
// 否则 PID（16/40，含盾侧读不到注册表的零值退化），两者皆零则无后缀
// （12/36 旧布局，握手头）。
func identSuffix(pid [4]byte, guid string) []byte {
	guid = strings.TrimSpace(guid)
	if len(guid) != v2GuidLen {
		guid = ""
	}
	if guid == "" {
		if pid == ([4]byte{}) {
			return nil
		}
		return append([]byte(nil), pid[:]...)
	}
	out := make([]byte, 4+v2GuidLen)
	copy(out, pid[:])
	copy(out[4:], guid)
	return out
}

func buildHeader(proto, srcAddr, dstAddr string, pid [4]byte, guid string) ([]byte, error) {
	src, err := net.ResolveTCPAddr("tcp", srcAddr)
	if err != nil {
		return nil, fmt.Errorf("proxy v2 src %s: %w", srcAddr, err)
	}
	dst, err := net.ResolveTCPAddr("tcp", dstAddr)
	if err != nil {
		return nil, fmt.Errorf("proxy v2 dst %s: %w", dstAddr, err)
	}
	ident := identSuffix(pid, guid)
	src4, dst4 := src.IP.To4(), dst.IP.To4()
	exit := proto == ProtoExit
	tcp := proto == "tcp" || exit
	verCmd := byte(v2VerCmd)
	if exit {
		verCmd = v2VerCmdExit
	}
	if src4 != nil && dst4 != nil {
		fam := byte(famUDPv4)
		if tcp {
			fam = famTCPv4
		}
		hdr := make([]byte, 28, 28+len(ident))
		copy(hdr, v2Signature)
		hdr[12] = verCmd
		hdr[13] = fam
		binary.BigEndian.PutUint16(hdr[14:16], uint16(12+len(ident)))
		copy(hdr[16:20], src4)
		copy(hdr[20:24], dst4)
		binary.BigEndian.PutUint16(hdr[24:26], uint16(src.Port))
		binary.BigEndian.PutUint16(hdr[26:28], uint16(dst.Port))
		hdr = append(hdr, ident...)
		return hdr, nil
	}
	fam := byte(famUDPv6)
	if tcp {
		fam = famTCPv6
	}
	hdr := make([]byte, 52, 52+len(ident))
	copy(hdr, v2Signature)
	hdr[12] = verCmd
	hdr[13] = fam
	binary.BigEndian.PutUint16(hdr[14:16], uint16(36+len(ident)))
	copy(hdr[16:32], src.IP.To16())
	copy(hdr[32:48], dst.IP.To16())
	binary.BigEndian.PutUint16(hdr[48:50], uint16(src.Port))
	binary.BigEndian.PutUint16(hdr[50:52], uint16(dst.Port))
	hdr = append(hdr, ident...)
	return hdr, nil
}

func parseAddr(verCmd, fam byte, addr []byte) (*Addr, string, error) {
	if verCmd != v2VerCmd && verCmd != v2VerCmdExit {
		return nil, "", fmt.Errorf("proxy v2: ver/cmd 0x%02x", verCmd)
	}
	a := &Addr{}
	switch fam {
	case famTCPv4, famUDPv4:
		if len(addr) != 12 && len(addr) != 16 && len(addr) != 52 {
			return nil, "", fmt.Errorf("proxy v2: IPv4 长度 %d", len(addr))
		}
		a.Src = fmt.Sprintf("%s:%d", net.IP(addr[0:4]), binary.BigEndian.Uint16(addr[8:10]))
		a.Dst = fmt.Sprintf("%s:%d", net.IP(addr[4:8]), binary.BigEndian.Uint16(addr[10:12]))
		if len(addr) >= 16 {
			copy(a.PID[:], addr[12:16])
		}
		if len(addr) == 52 {
			a.GUID = string(addr[16:52])
		}
	case famTCPv6, famUDPv6:
		if len(addr) != 36 && len(addr) != 40 && len(addr) != 76 {
			return nil, "", fmt.Errorf("proxy v2: IPv6 长度 %d", len(addr))
		}
		a.Src = fmt.Sprintf("[%s]:%d", net.IP(addr[0:16]), binary.BigEndian.Uint16(addr[32:34]))
		a.Dst = fmt.Sprintf("[%s]:%d", net.IP(addr[16:32]), binary.BigEndian.Uint16(addr[34:36]))
		if len(addr) >= 40 {
			copy(a.PID[:], addr[36:40])
		}
		if len(addr) == 76 {
			a.GUID = string(addr[40:76])
		}
	default:
		return nil, "", fmt.Errorf("proxy v2: family 0x%02x", fam)
	}
	if fam == famTCPv4 || fam == famTCPv6 {
		if verCmd == v2VerCmdExit {
			return a, ProtoExit, nil
		}
		return a, "tcp", nil
	}
	if verCmd == v2VerCmdExit {
		return nil, "", fmt.Errorf("proxy v2: exit 只允许 TCP family")
	}
	return a, "udp", nil
}
