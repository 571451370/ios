package proto

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	MaxAddrLen   = 256
	MaxDataLen   = 65535
	MaxFrameSize = 2 + MaxAddrLen + 2 + MaxDataLen
)

// WriteFrame 写一帧 UDP：[2B addrLen][addr][2B dataLen][data]。
func WriteFrame(w io.Writer, addr string, data []byte) error {
	if len(addr) > MaxAddrLen || len(data) > MaxDataLen {
		return fmt.Errorf("udpframe: 超长")
	}
	frame := make([]byte, 2+len(addr)+2+len(data))
	binary.BigEndian.PutUint16(frame[0:2], uint16(len(addr)))
	copy(frame[2:], addr)
	binary.BigEndian.PutUint16(frame[2+len(addr):], uint16(len(data)))
	copy(frame[4+len(addr):], data)
	return writeFull(w, frame)
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n > 0 {
			p = p[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// ReadFrame 读一帧，data 借用调用方提供的 buf。
func ReadFrame(r io.Reader, buf []byte) (addr string, data []byte, err error) {
	var nbuf [2]byte
	if _, err = io.ReadFull(r, nbuf[:]); err != nil {
		return
	}
	addrLen := int(binary.BigEndian.Uint16(nbuf[:]))
	if addrLen > MaxAddrLen {
		return "", nil, fmt.Errorf("udpframe: 地址过长")
	}
	if addrLen > 0 {
		ab := make([]byte, addrLen)
		if _, err = io.ReadFull(r, ab); err != nil {
			return
		}
		addr = string(ab)
	}
	if _, err = io.ReadFull(r, nbuf[:]); err != nil {
		return
	}
	dataLen := int(binary.BigEndian.Uint16(nbuf[:]))
	if dataLen > MaxDataLen || dataLen > len(buf) {
		return "", nil, fmt.Errorf("udpframe: 数据过长")
	}
	if _, err = io.ReadFull(r, buf[:dataLen]); err != nil {
		return
	}
	return addr, buf[:dataLen], nil
}
