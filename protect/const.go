package protect

import "time"

// 与 PC Backend 对齐的超时，切节点续传才接得上 Proxy。
const (
	writeDeadline         = 1 * time.Second
	handshakeDeadline     = 12 * time.Second
	retryInterval         = 200 * time.Millisecond
	retryBudget           = 35 * time.Second
	retiredPollInterval   = 200 * time.Millisecond
	resumeDrainDeadline   = 12 * time.Second
	configRefreshInterval = 5 * time.Second
	hookRescanInterval    = 2 * time.Second
)

// 给 Java / 游戏层的同步错误码。
const (
	ErrOK      = 0
	ErrStarted = 1
	ErrConfig  = 2
	ErrAPI     = 3
	ErrListen  = 4
	ErrHook    = 5
)
