//go:build ios

package protect

/*
#cgo LDFLAGS: -ldl
#include "hook_ios.h"
*/
import "C"

import (
	"fmt"
	"net"
	"strconv"
	"time"
	"unsafe"
)

func hookInstall(tcpPort, udpPort int) error {
	if rc := C.protect_hook_install(C.int(tcpPort), C.int(udpPort)); rc != 0 {
		return fmt.Errorf("hook install rc=%d", int(rc))
	}
	return nil
}

func hookUninstall() {
	C.protect_hook_uninstall()
}

func hookRescanLoop(done <-chan struct{}) {
	t := time.NewTicker(hookRescanInterval)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			C.protect_hook_rescan()
		}
	}
}

//export goInterceptTCP
func goInterceptTCP(ip *C.char, port C.int) C.int {
	if currentShould("tcp", C.GoString(ip), int(port)) {
		return 1
	}
	return 0
}

//export goInterceptUDP
func goInterceptUDP(ip *C.char, port C.int) C.int {
	if currentShould("udp", C.GoString(ip), int(port)) {
		return 1
	}
	return 0
}

//export goRegisterTCP
func goRegisterTCP(localPort C.int, ip *C.char, port C.int) {
	if e := currentEngine(); e != nil {
		e.registerTCP(int(localPort), destAddr(C.GoString(ip), int(port)))
	}
}

//export goLookupTCP
func goLookupTCP(localPort C.int, ipBuf *C.char, ipLen C.int, port *C.int) C.int {
	e := currentEngine()
	if e == nil {
		return 0
	}
	dest, ok := e.lookupTCP(int(localPort))
	if !ok {
		return 0
	}
	host, p, err := net.SplitHostPort(dest)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	*port = C.int(n)
	src := []byte(host)
	dst := unsafe.Slice((*byte)(unsafe.Pointer(ipBuf)), int(ipLen))
	if len(src)+1 > len(dst) {
		return 0
	}
	copy(dst, src)
	dst[len(src)] = 0
	return 1
}

//export goRegisterUDP
func goRegisterUDP(localPort C.int, ip *C.char, port C.int) {
	if e := currentEngine(); e != nil {
		e.registerUDP(int(localPort), destAddr(C.GoString(ip), int(port)))
	}
}

//export goLookupUDP
func goLookupUDP(localPort C.int, ipBuf *C.char, ipLen C.int, port *C.int) C.int {
	e := currentEngine()
	if e == nil {
		return 0
	}
	dest, ok := e.lookupUDP(int(localPort))
	if !ok {
		return 0
	}
	host, p, err := net.SplitHostPort(dest)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	*port = C.int(n)
	src := []byte(host)
	dst := unsafe.Slice((*byte)(unsafe.Pointer(ipBuf)), int(ipLen))
	if len(src)+1 > len(dst) {
		return 0
	}
	copy(dst, src)
	dst[len(src)] = 0
	return 1
}

//export goUnregisterPort
func goUnregisterPort(localPort C.int) {
	if e := currentEngine(); e != nil {
		e.unregisterPort(int(localPort))
	}
}

func currentShould(network, ip string, port int) bool {
	e := currentEngine()
	if e == nil {
		return false
	}
	return e.shouldIntercept(network, ip, port)
}
