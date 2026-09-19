package protect

import (
	"errors"
	"io"
	"net"
	"time"
)

var (
	errClosed    = errors.New("slot closed")
	errNoTunnel  = errors.New("no active tunnel")
	errResumeGap = errors.New("resume gap")
	errEmptyKey  = errors.New("接入码为空")
	errNoListen  = errors.New("LocalList 为空：游戏目标地址未配置")
)

func isWriteTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

func recoverConn(tag string) {
	if r := recover(); r != nil {
		logf("[%s] panic: %v", tag, r)
	}
}

func (e *engine) sleepBackoff() bool {
	select {
	case <-e.done:
		return false
	case <-time.After(retryInterval):
		return true
	}
}

func (e *engine) sleepUntil(deadline time.Time) bool {
	d := time.Until(deadline)
	if d <= 0 {
		return false
	}
	if d > retryInterval {
		d = retryInterval
	}
	select {
	case <-e.done:
		return false
	case <-time.After(d):
		return true
	}
}

func ioEOF(err error) bool {
	return err == io.EOF || errors.Is(err, io.EOF)
}
