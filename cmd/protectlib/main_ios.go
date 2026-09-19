//go:build ios

package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	"iossdk/protect"
)

var errBuf [1024]byte
var errMu sync.Mutex

func iosFilesDir() string {
	home := os.Getenv("HOME")
	if home == "" {
		home = os.TempDir()
	}
	dir := filepath.Join(home, "Library", "Application Support", "Protect")
	_ = os.MkdirAll(dir, 0o755)
	return dir
}

//export protect_start
func protect_start(config *C.char) C.int {
	return C.int(protect.Start(C.GoString(config), iosFilesDir()))
}

//export protect_stop
func protect_stop() {
	protect.Stop()
}

//export protect_running
func protect_running() C.int {
	if protect.Running() {
		return 1
	}
	return 0
}

//export protect_error_message
func protect_error_message() *C.char {
	errMu.Lock()
	defer errMu.Unlock()
	s := protect.ErrorMessage()
	n := copy(errBuf[:len(errBuf)-1], s)
	errBuf[n] = 0
	return (*C.char)(unsafe.Pointer(&errBuf[0]))
}

func main() {}
