package protect

import (
	"net"
	"strconv"
	"strings"

	"iossdk/internal/shieldapi"
)

func parseAccessConfig(raw string) (accessKey string, interceptAll bool, err error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", false, errEmptyKey
	}
	if s[0] != '{' {
		return s, false, nil
	}
	key := jsonString(s, "access_key")
	if key == "" {
		key = jsonString(s, "accessKey")
	}
	if key == "" {
		return "", false, errEmptyKey
	}
	all := jsonBool(s, "intercept_all") || jsonBool(s, "interceptAll")
	return key, all, nil
}

func jsonString(s, key string) string {
	pat := `"` + key + `"`
	i := strings.Index(s, pat)
	if i < 0 {
		return ""
	}
	rest := s[i+len(pat):]
	colon := strings.Index(rest, ":")
	if colon < 0 {
		return ""
	}
	rest = strings.TrimSpace(rest[colon+1:])
	if len(rest) < 2 || rest[0] != '"' {
		return ""
	}
	rest = rest[1:]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return ""
	}
	return rest[:end]
}

func jsonBool(s, key string) bool {
	pat := `"` + key + `"`
	i := strings.Index(s, pat)
	if i < 0 {
		return false
	}
	rest := strings.TrimSpace(s[i+len(pat):])
	if !strings.HasPrefix(rest, ":") {
		return false
	}
	rest = strings.TrimSpace(rest[1:])
	return strings.HasPrefix(rest, "true")
}

func matchLocal(entries []shieldapi.LocalEntry, network, ip string, port int) bool {
	want := net.JoinHostPort(ip, strconv.Itoa(port))
	n := strings.ToLower(network)
	for _, e := range entries {
		if e.Protocol != n {
			continue
		}
		if canonicalHostPort(e.Address) == canonicalHostPort(want) {
			return true
		}
	}
	return false
}

func canonicalHostPort(addr string) string {
	host, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return strings.TrimSpace(addr)
	}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			host = v4.String()
		} else {
			host = ip.String()
		}
	}
	return net.JoinHostPort(host, port)
}

func hostOf(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
