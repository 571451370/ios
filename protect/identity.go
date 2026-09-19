package protect

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const guidFile = "gs_device.guid"

var ident struct {
	mu   sync.Mutex
	guid string
	pid  [4]byte
}

func loadIdentity(filesDir string) (string, [4]byte, error) {
	if strings.TrimSpace(filesDir) == "" {
		filesDir = os.TempDir()
	}
	if err := os.MkdirAll(filesDir, 0o755); err != nil {
		return "", [4]byte{}, err
	}
	p := filepath.Join(filesDir, guidFile)
	b, err := os.ReadFile(p)
	guid := strings.ToLower(strings.TrimSpace(string(b)))
	if err != nil || !validGUID(guid) {
		guid, err = newGUID()
		if err != nil {
			return "", [4]byte{}, err
		}
		if werr := os.WriteFile(p, []byte(guid+"\n"), 0o644); werr != nil {
			return "", [4]byte{}, werr
		}
	}
	sum := sha1.Sum([]byte("gameshield-player|" + guid))
	var pid [4]byte
	copy(pid[:], sum[:4])
	ident.mu.Lock()
	ident.guid, ident.pid = guid, pid
	ident.mu.Unlock()
	return guid, pid, nil
}

func currentIdent() (pid [4]byte, guid string) {
	ident.mu.Lock()
	defer ident.mu.Unlock()
	return ident.pid, ident.guid
}

func validGUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return false
			}
		}
	}
	return true
}

func newGUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	hexed := hex.EncodeToString(b[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", hexed[0:8], hexed[8:12], hexed[12:16], hexed[16:20], hexed[20:32]), nil
}
