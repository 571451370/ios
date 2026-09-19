// Package protect 是 iOS 游戏盾 SDK 的 Go 核心。
//
// 游戏进程内：本机 127.0.0.1 监听 +（仅 iOS）把本 App 的 libc socket
// 重定向到该监听。隧道/协议与 PC / Android 相同：smux + PROXY v2 + 续传。
package protect

import (
	"errors"
	"strings"
	"sync"
)

var (
	runMu   sync.Mutex
	running *engine
	lastErr string
)

// Start 加载身份、拉节点、开本机转发、安装 socket 重定向。
// accessKey 可以是接入码本身，或 JSON：{"access_key":"...","intercept_all":false}。
// filesDir 用 App 沙盒目录，用来持久化设备 GUID。
func Start(accessKey, filesDir string) int {
	runMu.Lock()
	defer runMu.Unlock()
	if running != nil {
		lastErr = "already started"
		return ErrStarted
	}
	key, interceptAll, err := parseAccessConfig(accessKey)
	if err != nil {
		lastErr = err.Error()
		return ErrConfig
	}
	e := newEngine(key, filesDir, interceptAll)
	if err := e.start(); err != nil {
		lastErr = err.Error()
		e.stop()
		if errors.Is(err, errNoListen) || errors.Is(err, errEmptyKey) {
			return ErrConfig
		}
		if isListenErr(err) {
			return ErrListen
		}
		return ErrAPI
	}
	running = e
	if err := hookInstall(e.tcpPort, e.udpPort); err != nil {
		running = nil
		hookUninstall()
		e.stop()
		lastErr = err.Error()
		return ErrHook
	}
	lastErr = ""
	go hookRescanLoop(e.done)
	logf("started tcp=127.0.0.1:%d udp=127.0.0.1:%d", e.tcpPort, e.udpPort)
	return ErrOK
}

// Running 报告 SDK 是否已 start。
func Running() bool {
	return currentEngine() != nil
}

// Stop 恢复 hook、关隧道、关本机监听。
func Stop() {
	runMu.Lock()
	e := running
	running = nil
	runMu.Unlock()
	hookUninstall()
	if e != nil {
		e.stop()
	}
}

// ErrorMessage 最近一次 Start 失败原因。
func ErrorMessage() string {
	runMu.Lock()
	defer runMu.Unlock()
	return lastErr
}

func currentEngine() *engine {
	runMu.Lock()
	defer runMu.Unlock()
	return running
}

func isListenErr(err error) bool {
	s := err.Error()
	return strings.Contains(s, "listen") || strings.Contains(s, "bind")
}
