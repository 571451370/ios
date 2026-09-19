package protect

import (
	"encoding/binary"
	"net"
)

const udpMagic = 0x47535531 // GSU1

// 本机 UDP 重定向头：游戏 libc sendto ↔ SDK 监听之间约定，不进隧道。
func encodeUDPLocal(dst *net.UDPAddr, payload []byte) []byte {
	out := make([]byte, 10+len(payload))
	binary.BigEndian.PutUint32(out[0:4], udpMagic)
	ip := dst.IP.To4()
	if ip == nil {
		ip = net.IPv4zero
	}
	copy(out[4:8], ip)
	binary.BigEndian.PutUint16(out[8:10], uint16(dst.Port))
	copy(out[10:], payload)
	return out
}

func decodeUDPLocal(p []byte) (ip net.IP, port int, payload []byte, ok bool) {
	if len(p) < 10 || binary.BigEndian.Uint32(p[0:4]) != udpMagic {
		return nil, 0, nil, false
	}
	ip = net.IPv4(p[4], p[5], p[6], p[7])
	port = int(binary.BigEndian.Uint16(p[8:10]))
	return ip, port, p[10:], true
}
