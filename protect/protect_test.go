package protect

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"iossdk/internal/shieldapi"
)

func TestParseAccessConfig(t *testing.T) {
	key, all, err := parseAccessConfig(`{"access_key":"abc","intercept_all":true}`)
	if err != nil || key != "abc" || !all {
		t.Fatalf("json: key=%q all=%v err=%v", key, all, err)
	}
	key, all, err = parseAccessConfig("plain-code")
	if err != nil || key != "plain-code" || all {
		t.Fatalf("plain: key=%q all=%v err=%v", key, all, err)
	}
	if _, _, err := parseAccessConfig(""); err == nil {
		t.Fatal("empty should fail")
	}
}

func TestIdentityGUIDPersists(t *testing.T) {
	dir := t.TempDir()
	g1, pid1, err := loadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !validGUID(g1) || pid1 == ([4]byte{}) {
		t.Fatalf("guid=%q pid=%x", g1, pid1)
	}
	g2, pid2, err := loadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if g1 != g2 || pid1 != pid2 {
		t.Fatalf("not stable %q vs %q", g1, g2)
	}
	b, _ := os.ReadFile(filepath.Join(dir, guidFile))
	if len(b) < 36 {
		t.Fatal("guid file missing")
	}
}

func TestMatchLocalVirtualIP(t *testing.T) {
	entries := []shieldapi.LocalEntry{
		{Protocol: "tcp", Address: "127.99.99.88:8211"},
		{Protocol: "udp", Address: "127.99.99.88:8211"},
	}
	if !matchLocal(entries, "tcp", "127.99.99.88", 8211) {
		t.Fatal("tcp virtual should match")
	}
	if matchLocal(entries, "tcp", "127.99.99.88", 8212) {
		t.Fatal("wrong port")
	}
	if !matchLocal(entries, "udp", "127.99.99.88", 8211) {
		t.Fatal("udp virtual should match")
	}
}

func TestUDPLocalCodec(t *testing.T) {
	dst := &net.UDPAddr{IP: net.IPv4(127, 99, 1, 1), Port: 8211}
	p := encodeUDPLocal(dst, []byte("hello"))
	ip, port, payload, ok := decodeUDPLocal(p)
	if !ok || port != 8211 || string(payload) != "hello" || ip.To4().String() != "127.99.1.1" {
		t.Fatalf("ip=%v port=%d payload=%q ok=%v", ip, port, payload, ok)
	}
	if _, _, _, ok := decodeUDPLocal([]byte("nope")); ok {
		t.Fatal("bad magic")
	}
}

func TestShouldIntercept(t *testing.T) {
	e := newEngine("k", t.TempDir(), false)
	e.setRules([]shieldapi.LocalEntry{{Protocol: "tcp", Address: "127.99.99.88:8211"}}, []string{"1.2.3.4:8877"})
	if !e.shouldIntercept("tcp", "127.99.99.88", 8211) {
		t.Fatal("want intercept virtual")
	}
	if e.shouldIntercept("tcp", "1.2.3.4", 8877) {
		t.Fatal("must bypass node")
	}
	e.tcpPort, e.udpPort = 40000, 40001
	if e.shouldIntercept("tcp", "127.0.0.1", 40000) {
		t.Fatal("must not intercept self")
	}
	e.interceptAll = true
	if !e.shouldIntercept("tcp", "8.8.8.8", 443) {
		t.Fatal("intercept_all public")
	}
	if e.shouldIntercept("tcp", "127.0.0.1", 80) {
		t.Fatal("intercept_all still skip 127.0.0.1")
	}
}

func TestUDPDownlinkHeaderIsDest(t *testing.T) {
	game := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50000}
	dest := &net.UDPAddr{IP: net.IPv4(127, 99, 99, 88), Port: 8211}
	pkt := encodeUDPLocal(dest, []byte("pong"))
	ip, port, payload, ok := decodeUDPLocal(pkt)
	if !ok || port != 8211 || ip.To4().String() != "127.99.99.88" || string(payload) != "pong" {
		t.Fatalf("downlink header must be game dest, got %s:%d %q", ip, port, payload)
	}
	_ = game
}

func TestTCPPeerMap(t *testing.T) {
	e := newEngine("k", t.TempDir(), false)
	e.registerTCP(51234, "127.99.99.88:8211")
	got, ok := e.lookupTCP(51234)
	if !ok || got != "127.99.99.88:8211" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
	e.unregisterPort(51234)
	if _, ok := e.lookupTCP(51234); ok {
		t.Fatal("unregister")
	}
}

func TestStartRejectsEmptyLocalList(t *testing.T) {
	t.Setenv("SHIELD_LOCAL_ONLY", "1")
	t.Setenv("SHIELD_LOCAL_LIST", "")
	t.Setenv("SHIELD_SERVER_LIST", "127.0.0.1:1")
	if code := Start("k", t.TempDir()); code != ErrConfig {
		t.Fatalf("code=%d err=%s", code, ErrorMessage())
	}
}

func TestStartStopLocalOnly(t *testing.T) {
	t.Setenv("SHIELD_LOCAL_ONLY", "1")
	t.Setenv("SHIELD_LOCAL_LIST", "tcp://127.99.99.88:8211,udp://127.99.99.88:8211")
	t.Setenv("SHIELD_SERVER_LIST", "127.0.0.1:1")
	dir := t.TempDir()
	if code := Start("k", dir); code != ErrOK {
		t.Fatalf("start=%d %s", code, ErrorMessage())
	}
	if !Running() {
		t.Fatal("running")
	}
	if Start("k", dir) != ErrStarted {
		t.Fatal("second start")
	}
	Stop()
	if Running() {
		t.Fatal("stopped")
	}
	if code := Start("k", dir); code != ErrOK {
		t.Fatalf("restart=%d %s", code, ErrorMessage())
	}
	Stop()
}
