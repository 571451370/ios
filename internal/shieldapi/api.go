// Package shieldapi 封装盾管理端 API：
//   - 客户端配置（Frontend/Backend 共用）：高防节点列表 + 本地监听列表
//   - 节点规则（Server）：转发规则 + 带宽
//   - 设备统计上报（Backend）
//
// 支持环境变量覆盖用于本地联调（LOCAL_ONLY / SERVER_LIST / LOCAL_LIST / SERVER_RULES）。
package shieldapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	apiBaseDefault = "http://dunapi.62dns.com/api/shield"
	clientPath     = "/client/getconfig"
	serverPath     = "/server/getconfig"
	StatsReportURL = "http://dunapi.62dns.com/api/shield/stats/report"

	envAPIBase     = "SHIELD_API_BASE"
	envLocalOnly   = "SHIELD_LOCAL_ONLY"
	envLocalList   = "SHIELD_LOCAL_LIST"
	envServerList  = "SHIELD_SERVER_LIST"
	envServerRules = "SHIELD_SERVER_RULES"
)

// ClientConfig 客户端侧配置。
type ClientConfig struct {
	ServerList []string
	LocalList  []string
}

// Rule 服务端单条转发规则。
type Rule struct {
	Listen string `json:"listen"` // 玩家侧虚拟地址 (host:port)
	Source string `json:"source"` // 源站代理地址 (host)
	Proto  string `json:"proto"`
}

// RuleSet 一个接入码下的规则集。
type RuleSet struct {
	AccessCode string `json:"access_code"`
	Bandwidth  int    `json:"bandwidth"` // Mbps，0 = 不限
	Rules      []Rule `json:"rules"`
}

var httpClient = &http.Client{Timeout: 10 * time.Second}

func apiBase() string {
	if v := strings.TrimSpace(os.Getenv(envAPIBase)); v != "" {
		return strings.TrimRight(v, "/")
	}
	return apiBaseDefault
}

// FetchClientConfig 拉取客户端配置；带重试，API 失败时回退环境变量。
func FetchClientConfig(accessCode string) (*ClientConfig, error) {
	if os.Getenv(envLocalOnly) == "1" {
		return fromEnv(), nil
	}
	cfg, err := retry(3, func() (*ClientConfig, error) { return fetchClientOnce(accessCode) })
	if err != nil {
		if env := fromEnv(); len(env.ServerList) > 0 || len(env.LocalList) > 0 {
			return env, nil
		}
		return nil, err
	}
	applyEnv(cfg)
	if len(cfg.ServerList) == 0 && len(cfg.LocalList) == 0 {
		return nil, fmt.Errorf("API 返回空配置")
	}
	return cfg, nil
}

func fetchClientOnce(accessCode string) (*ClientConfig, error) {
	if accessCode == "" {
		return nil, fmt.Errorf("接入码为空")
	}
	u := fmt.Sprintf("%s%s?access_code=%s", apiBase(), clientPath, url.QueryEscape(accessCode))
	body, err := getJSON(u)
	if err != nil {
		return nil, err
	}
	var ar struct {
		Code int `json:"code"`
		Data struct {
			ServerList []string `json:"ServerList"`
			LocalList  []string `json:"LocalList"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &ar); err != nil {
		return nil, fmt.Errorf("解析配置: %w", err)
	}
	if ar.Code != 1 {
		return nil, fmt.Errorf("API code=%d", ar.Code)
	}
	return &ClientConfig{ServerList: ar.Data.ServerList, LocalList: ar.Data.LocalList}, nil
}

// FetchServerRules 拉取节点转发规则；带重试，失败时回退环境变量 JSON。
func FetchServerRules(nodeSecret string) ([]RuleSet, error) {
	if os.Getenv(envLocalOnly) == "1" {
		if cfgs := rulesFromEnv(); len(cfgs) > 0 {
			return cfgs, nil
		}
		return nil, fmt.Errorf("SHIELD_LOCAL_ONLY=1 但规则环境变量为空")
	}
	if nodeSecret == "" {
		return nil, fmt.Errorf("节点密钥为空")
	}
	rules, err := retry(3, func() ([]RuleSet, error) { return fetchRulesOnce(nodeSecret) })
	if err != nil {
		if cfgs := rulesFromEnv(); len(cfgs) > 0 {
			return cfgs, nil
		}
		return nil, err
	}
	return rules, nil
}

func fetchRulesOnce(nodeSecret string) ([]RuleSet, error) {
	u := fmt.Sprintf("%s%s?node_secret=%s", apiBase(), serverPath, url.QueryEscape(nodeSecret))
	body, err := getJSON(u)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Code int       `json:"code"`
		Data []RuleSet `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("解析服务端配置: %w; body=%q", err, clip(body, 200))
	}
	if resp.Code != 1 {
		return nil, fmt.Errorf("API code=%d", resp.Code)
	}
	return resp.Data, nil
}

// ---- 本地监听列表解析 ----

// LocalEntry 本地监听项。
type LocalEntry struct {
	Protocol string
	Address  string
}

// ParseLocalList 解析 "tcp://ip:port" 形式的监听列表。
func ParseLocalList(list []string) ([]LocalEntry, error) {
	entries := make([]LocalEntry, 0, len(list))
	for _, item := range list {
		u, err := url.Parse(item)
		if err != nil {
			return nil, fmt.Errorf("parse %q: %w", item, err)
		}
		proto := strings.ToLower(u.Scheme)
		if proto != "tcp" && proto != "udp" {
			return nil, fmt.Errorf("不支持协议 %q", u.Scheme)
		}
		if u.Host == "" {
			return nil, fmt.Errorf("%q 缺少 host", item)
		}
		entries = append(entries, LocalEntry{Protocol: proto, Address: u.Host})
	}
	return entries, nil
}

// ---- 环境变量回退 ----

func fromEnv() *ClientConfig {
	cfg := &ClientConfig{}
	if v := os.Getenv(envServerList); v != "" {
		cfg.ServerList = splitCSV(v)
	}
	if v := os.Getenv(envLocalList); v != "" {
		cfg.LocalList = splitCSV(v)
	}
	return cfg
}

func applyEnv(cfg *ClientConfig) {
	if parts := splitCSV(os.Getenv(envServerList)); len(parts) > 0 {
		cfg.ServerList = parts
	}
	if parts := splitCSV(os.Getenv(envLocalList)); len(parts) > 0 {
		cfg.LocalList = parts
	}
}

func rulesFromEnv() []RuleSet {
	raw := os.Getenv(envServerRules)
	if raw == "" {
		return nil
	}
	var cfgs []RuleSet
	if err := json.Unmarshal([]byte(raw), &cfgs); err != nil {
		return nil
	}
	return cfgs
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func retry[T any](n int, fn func() (T, error)) (T, error) {
	var last error
	var zero T
	for i := 0; i < n; i++ {
		if i > 0 {
			time.Sleep(time.Duration(1<<uint(i)) * time.Second)
		}
		v, err := fn()
		if err == nil {
			return v, nil
		}
		last = err
	}
	return zero, last
}

func getJSON(u string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	// 与旧项目一致：管理端/WAF 会拦 Go 默认 UA，返回 HTML，json.Unmarshal 失败。
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 API: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(clip(body, 200)))
	}
	return body, nil
}

func clip(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
