package protect

import (
	"net"
	"strconv"
	"sync"
	"time"

	"iossdk/internal/shieldapi"
	"iossdk/internal/tunnel"
)

type engine struct {
	accessKey    string
	interceptAll bool
	filesDir     string

	pool    *tunnel.Pool
	tcpLn   net.Listener
	udpConn *net.UDPConn
	tcpPort int
	udpPort int

	mu       sync.RWMutex
	entries  []shieldapi.LocalEntry
	bypassIP map[string]struct{}

	tcpPeers sync.Map // localPort(int) → dest host:port
	udpPeers sync.Map

	udpMu sync.Mutex
	udps  map[string]*udpFlow

	done   chan struct{}
	closed sync.Once
}

func newEngine(accessKey, filesDir string, interceptAll bool) *engine {
	return &engine{
		accessKey:    accessKey,
		filesDir:     filesDir,
		interceptAll: interceptAll,
		bypassIP:     map[string]struct{}{},
		udps:         map[string]*udpFlow{},
		done:         make(chan struct{}),
	}
}

func (e *engine) start() error {
	if _, _, err := loadIdentity(e.filesDir); err != nil {
		return err
	}
	cfg, err := shieldapi.FetchClientConfig(e.accessKey)
	if err != nil {
		return err
	}
	entries, err := shieldapi.ParseLocalList(cfg.LocalList)
	if err != nil {
		return err
	}
	if !e.interceptAll && len(entries) == 0 {
		return errNoListen
	}
	e.setRules(entries, cfg.ServerList)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	e.tcpLn = ln
	e.tcpPort = ln.Addr().(*net.TCPAddr).Port

	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		_ = ln.Close()
		return err
	}
	e.udpConn = uc
	e.udpPort = uc.LocalAddr().(*net.UDPAddr).Port

	e.pool = tunnel.New(cfg.ServerList)

	go e.acceptTCP()
	go e.readUDP()
	go e.refreshLoop()
	return nil
}

func (e *engine) stop() {
	e.closed.Do(func() { close(e.done) })
	if e.tcpLn != nil {
		_ = e.tcpLn.Close()
	}
	if e.udpConn != nil {
		_ = e.udpConn.Close()
	}
	e.closeUDP()
	if e.pool != nil {
		e.pool.Close()
	}
}

func (e *engine) setRules(entries []shieldapi.LocalEntry, nodes []string) {
	bypass := map[string]struct{}{}
	for _, n := range nodes {
		if h := hostOf(n); h != "" {
			bypass[h] = struct{}{}
		}
	}
	e.mu.Lock()
	e.entries = entries
	e.bypassIP = bypass
	e.mu.Unlock()
	if e.pool != nil {
		e.pool.Update(nodes)
	}
}

func (e *engine) refreshLoop() {
	t := time.NewTicker(configRefreshInterval)
	defer t.Stop()
	for {
		select {
		case <-e.done:
			return
		case <-t.C:
			cfg, err := shieldapi.FetchClientConfig(e.accessKey)
			if err != nil {
				logf("刷新配置失败: %v", err)
				continue
			}
			entries, err := shieldapi.ParseLocalList(cfg.LocalList)
			if err != nil {
				continue
			}
			e.setRules(entries, cfg.ServerList)
		}
	}
}

func (e *engine) acceptTCP() {
	defer recoverConn("acceptTCP")
	for {
		c, err := e.tcpLn.Accept()
		if err != nil {
			select {
			case <-e.done:
				return
			default:
				if !e.sleepBackoff() {
					return
				}
				continue
			}
		}
		ra, ok := c.RemoteAddr().(*net.TCPAddr)
		if !ok {
			_ = c.Close()
			continue
		}
		dest, ok := e.lookupTCP(ra.Port)
		if !ok {
			logf("[TCP] 未知连接 port=%d，关闭", ra.Port)
			_ = c.Close()
			continue
		}
		go e.handleTCP(c, dest)
	}
}

func (e *engine) readUDP() {
	defer recoverConn("readUDP")
	buf := make([]byte, protoMax)
	for {
		n, from, err := e.udpConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-e.done:
				return
			default:
				if !e.sleepBackoff() {
					return
				}
				continue
			}
		}
		ip, port, payload, ok := decodeUDPLocal(buf[:n])
		if !ok {
			if dest, found := e.lookupUDP(from.Port); found {
				h, pstr, err := net.SplitHostPort(dest)
				if err != nil {
					continue
				}
				p, _ := strconv.Atoi(pstr)
				ip = net.ParseIP(h)
				port = p
				payload = buf[:n]
			} else {
				continue
			}
		}
		if ip == nil {
			continue
		}
		if !e.shouldIntercept("udp", ip.String(), port) {
			continue
		}
		pkt := append([]byte(nil), payload...)
		go e.handleUDPPacket(from, ip, port, pkt)
	}
}

const protoMax = 65535

func (e *engine) shouldIntercept(network, ip string, port int) bool {
	if ip == "127.0.0.1" || ip == "::1" || ip == "0.0.0.0" {
		if port == e.tcpPort || port == e.udpPort {
			return false
		}
	}
	e.mu.RLock()
	_, bypass := e.bypassIP[ip]
	all := e.interceptAll
	entries := e.entries
	e.mu.RUnlock()
	if bypass {
		return false
	}
	if all {
		return ip != "127.0.0.1" && ip != "::1"
	}
	return matchLocal(entries, network, ip, port)
}

func destAddr(ip string, port int) string {
	return net.JoinHostPort(ip, strconv.Itoa(port))
}

func (e *engine) registerTCP(localPort int, dest string) {
	e.tcpPeers.Store(localPort, dest)
}

func (e *engine) lookupTCP(localPort int) (string, bool) {
	v, ok := e.tcpPeers.Load(localPort)
	if !ok {
		return "", false
	}
	return v.(string), true
}

func (e *engine) unregisterPort(localPort int) {
	e.tcpPeers.Delete(localPort)
	e.udpPeers.Delete(localPort)
}

func (e *engine) registerUDP(localPort int, dest string) {
	e.udpPeers.Store(localPort, dest)
}

func (e *engine) lookupUDP(localPort int) (string, bool) {
	v, ok := e.udpPeers.Load(localPort)
	if !ok {
		return "", false
	}
	return v.(string), true
}
