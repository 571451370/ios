package protect

import (
	"io"
	"log"
	"os"
)

// sdkLogOff 默认关掉 SDK 日志，避免接入游戏后刷 Xcode / 设备控制台。
// 排障：把这里改成 false 再编，或运行前设环境变量 PROTECT_LOG=1。
const sdkLogOff = true

func init() {
	if os.Getenv("PROTECT_LOG") == "1" {
		log.SetFlags(log.LstdFlags | log.Lmicroseconds)
		return
	}
	if sdkLogOff {
		log.SetOutput(io.Discard)
	}
}

func logf(format string, args ...any) {
	log.Printf("[protect] "+format, args...)
}
