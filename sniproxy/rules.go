package sniproxy

import (
	"net"
	"strings"
	"sync"
	"time"
)

// Rule SNI代理规则
type Rule struct {
	ID            string    `json:"id"`
	SourceIP      string    `json:"source_ip"`       // 源IP或CIDR，空表示匹配所有
	SNIPattern    string    `json:"sni_pattern"`     // SNI模式，支持通配符*
	TargetAddress string    `json:"target_address"`  // 目标地址 (host:port)
	Transport     string    `json:"transport"`       // 传输类型: direct, socks5
	Priority      int       `json:"priority"`        // 优先级，数值越大优先级越高
	Enabled       bool      `json:"enabled"`         // 是否启用
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// RuleMatch 规则匹配结果
type RuleMatch struct {
	Rule          *Rule
	TargetAddress string
	Transport     string
}

// RuleTable 规则表管理器
type RuleTable struct {
	mu            sync.RWMutex
	rules         []*Rule
	defaultTarget string    // 默认目标地址
	defaultTransport string // 默认传输类型
}

// NewRuleTable 创建规则表
func NewRuleTable(defaultTransport string) *RuleTable {
	return &RuleTable{
		rules:            make([]*Rule, 0),
		defaultTransport: defaultTransport,
	}
}

// AddRule 添加规则
func (rt *RuleTable) AddRule(rule *Rule) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()
	rt.rules = append(rt.rules, rule)
	rt.sortRules()
}

// RemoveRule 移除规则
func (rt *RuleTable) RemoveRule(id string) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	for i, rule := range rt.rules {
		if rule.ID == id {
			rt.rules = append(rt.rules[:i], rt.rules[i+1:]...)
			return true
		}
	}
	return false
}

// UpdateRule 更新规则
func (rt *RuleTable) UpdateRule(id string, update func(*Rule)) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	for _, rule := range rt.rules {
		if rule.ID == id {
			update(rule)
			rule.UpdatedAt = time.Now()
			rt.sortRules()
			return true
		}
	}
	return false
}

// SetRules 批量设置规则（替换所有现有规则）
func (rt *RuleTable) SetRules(rules []*Rule) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	now := time.Now()
	for _, rule := range rules {
		if rule.CreatedAt.IsZero() {
			rule.CreatedAt = now
		}
		rule.UpdatedAt = now
	}

	rt.rules = rules
	rt.sortRules()
}

// GetRules 获取所有规则
func (rt *RuleTable) GetRules() []*Rule {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	result := make([]*Rule, len(rt.rules))
	copy(result, rt.rules)
	return result
}

// Match 匹配规则
func (rt *RuleTable) Match(sourceIP net.IP, sni string) *RuleMatch {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	for _, rule := range rt.rules {
		if !rule.Enabled {
			continue
		}

		// 匹配源IP
		if rule.SourceIP != "" && !rt.matchSourceIP(sourceIP, rule.SourceIP) {
			continue
		}

		// 匹配SNI
		if rule.SNIPattern != "" && !rt.matchSNI(sni, rule.SNIPattern) {
			continue
		}

		// 确定目标地址
		targetAddr := rule.TargetAddress
		if targetAddr == "" {
			// 如果规则未指定目标，使用原始SNI作为目标
			targetAddr = sni + ":443"
		}

		transport := rule.Transport
		if transport == "" {
			transport = rt.defaultTransport
		}

		return &RuleMatch{
			Rule:          rule,
			TargetAddress: targetAddr,
			Transport:     transport,
		}
	}

	// 没有匹配的规则，返回默认
	return &RuleMatch{
		Rule:          nil,
		TargetAddress: sni + ":443",
		Transport:     rt.defaultTransport,
	}
}

// matchSourceIP 匹配源IP
func (rt *RuleTable) matchSourceIP(ip net.IP, pattern string) bool {
	// 检查是否为CIDR
	if strings.Contains(pattern, "/") {
		_, ipNet, err := net.ParseCIDR(pattern)
		if err != nil {
			return false
		}
		return ipNet.Contains(ip)
	}

	// 直接IP比较
	patternIP := net.ParseIP(pattern)
	if patternIP == nil {
		return false
	}
	return ip.Equal(patternIP)
}

// matchSNI 匹配SNI模式
func (rt *RuleTable) matchSNI(sni, pattern string) bool {
	// 完全匹配
	if pattern == sni {
		return true
	}

	// 通配符匹配
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // 去掉*，保留.
		return strings.HasSuffix(sni, suffix)
	}

	// 前缀通配符
	if strings.HasSuffix(pattern, "*") {
		prefix := pattern[:len(pattern)-1]
		return strings.HasPrefix(sni, prefix)
	}

	return false
}

// sortRules 按优先级排序规则（高优先级在前）
func (rt *RuleTable) sortRules() {
	for i := 0; i < len(rt.rules)-1; i++ {
		for j := i + 1; j < len(rt.rules); j++ {
			if rt.rules[j].Priority > rt.rules[i].Priority {
				rt.rules[i], rt.rules[j] = rt.rules[j], rt.rules[i]
			}
		}
	}
}
