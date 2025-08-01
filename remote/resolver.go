package remote

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/DnsUnlock/DnsNode/config"
	"github.com/miekg/dns"
)

// DomainMapping 表示来自远程源的域名到DNS记录映射
type DomainMapping struct {
	Domain     string   `json:"domain"`
	RecordType string   `json:"record_type,omitempty"` // DNS记录类型: A, AAAA, CNAME, MX, TXT等
	RecordData string   `json:"record_data,omitempty"` // 非A/AAAA记录的通用记录数据
	IPs        []string `json:"ips,omitempty"`         // 与A/AAAA记录的向后兼容性
	Priority   int      `json:"priority,omitempty"`    // 用于MX记录
	TTL        int      `json:"ttl,omitempty"`
}

// RemoteResponse 表示来自远程API的响应
type RemoteResponse struct {
	Mappings []DomainMapping `json:"mappings"`
	Updated  time.Time       `json:"updated"`
}

// DNSRecord 表示通用DNS记录
type DNSRecord struct {
	Type     uint16
	Data     string
	Priority int
	TTL      int
}

// Resolver 处理远程DNS解析
type Resolver struct {
	config      *config.Config
	client      *http.Client
	cache       *Cache
	mappings    map[string][]DNSRecord
	mappingsMu  sync.RWMutex
	stopChan    chan struct{}
	refreshDone chan struct{}
}

// NewResolver 创建一个新的远程解析器
func NewResolver(cfg *config.Config) (*Resolver, error) {
	r := &Resolver{
		config:      cfg,
		mappings:    make(map[string][]DNSRecord),
		stopChan:    make(chan struct{}),
		refreshDone: make(chan struct{}),
		client: &http.Client{
			Timeout: cfg.RemoteAPI.Timeout,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}

	// 如果启用则初始化缓存
	if cfg.Cache.Enabled {
		r.cache = NewCacheWithOptions(cfg.Cache.Path, cfg.Cache.SyncPolicy, cfg.Cache.MaxSize, cfg.Cache.DefaultTTL, cfg.Cache.CleanupInterval)
	}

	return r, nil
}

// Start 启动远程解析器
func (r *Resolver) Start() error {
	// 初始获取
	if err := r.fetchMappings(); err != nil {
		log.Printf("Warning: Initial remote mappings fetch failed: %v", err)
	}

	// 启动刷新协程
	go r.refreshLoop()

	return nil
}

// Stop 停止远程解析器
func (r *Resolver) Stop() {
	close(r.stopChan)
	<-r.refreshDone
	
	if r.cache != nil {
		r.cache.Stop()
	}
}

// refreshLoop 定时从远程刷新映射
func (r *Resolver) refreshLoop() {
	defer close(r.refreshDone)
	
	ticker := time.NewTicker(r.config.RemoteAPI.RefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := r.fetchMappings(); err != nil {
				log.Printf("Failed to refresh remote mappings: %v", err)
			}
		case <-r.stopChan:
			return
		}
	}
}

// fetchMappings 从远程API获取域名映射
func (r *Resolver) fetchMappings() error {
	req, err := http.NewRequest("GET", r.config.RemoteAPI.URL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// 添加请求头
	for k, v := range r.config.RemoteAPI.Headers {
		req.Header.Set(k, v)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var remoteResp RemoteResponse
	if err := json.NewDecoder(resp.Body).Decode(&remoteResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	// 更新映射
	newMappings := make(map[string][]DNSRecord)
	for _, mapping := range remoteResp.Mappings {
		var records []DNSRecord
		
		// 确定记录类型
		var recordType uint16
		if mapping.RecordType != "" {
			// 如果提供则使用显式记录类型
			switch mapping.RecordType {
			case "A":
				recordType = dns.TypeA
			case "AAAA":
				recordType = dns.TypeAAAA
			case "CNAME":
				recordType = dns.TypeCNAME
			case "MX":
				recordType = dns.TypeMX
			case "TXT":
				recordType = dns.TypeTXT
			case "NS":
				recordType = dns.TypeNS
			case "SOA":
				recordType = dns.TypeSOA
			case "PTR":
				recordType = dns.TypePTR
			case "SRV":
				recordType = dns.TypeSRV
			default:
				log.Printf("Unknown record type: %s for domain %s", mapping.RecordType, mapping.Domain)
				continue
			}
			
			// 对于非IP记录类型，使用RecordData字段
			if mapping.RecordData != "" {
				records = append(records, DNSRecord{
					Type:     recordType,
					Data:     mapping.RecordData,
					Priority: mapping.Priority,
					TTL:      mapping.TTL,
				})
			}
		}
		
		// 处理向后兼容性 - 如果提供IP，创建A/AAAA记录
		if len(mapping.IPs) > 0 {
			for _, ipStr := range mapping.IPs {
				if ip := net.ParseIP(ipStr); ip != nil {
					if ip.To4() != nil {
						records = append(records, DNSRecord{
							Type: dns.TypeA,
							Data: ipStr,
							TTL:  mapping.TTL,
						})
					} else {
						records = append(records, DNSRecord{
							Type: dns.TypeAAAA,
							Data: ipStr,
							TTL:  mapping.TTL,
						})
					}
				}
			}
		}
		
		if len(records) > 0 {
			newMappings[mapping.Domain] = records
		}
	}

	r.mappingsMu.Lock()
	r.mappings = newMappings
	r.mappingsMu.Unlock()

	if r.config.Debug {
		log.Printf("Updated %d domain mappings from remote", len(newMappings))
	}

	return nil
}

// Resolve 使用远程映射解析域名
func (r *Resolver) Resolve(ctx context.Context, domain string, qtype uint16) ([]net.IP, error) {
	// 如果启用先检查缓存
	if r.cache != nil {
		if ips, found := r.cache.Get(domain, qtype); found {
			return ips, nil
		}
	}

	// 检查远程映射
	r.mappingsMu.RLock()
	records, found := r.mappings[domain]
	r.mappingsMu.RUnlock()

	if !found {
		return nil, fmt.Errorf("domain not found in remote mappings")
	}

	// 根据查询类型过滤记录并为A/AAAA记录提取IP
	var result []net.IP
	for _, record := range records {
		if record.Type == qtype {
			// 对于A和AAAA记录，解析并返图IP
			if qtype == dns.TypeA || qtype == dns.TypeAAAA {
				if ip := net.ParseIP(record.Data); ip != nil {
					result = append(result, ip)
				}
			}
			// 对于其他记录类型，我们需要不同的返回类型
			// 此方法目前仅处理基于IP的记录
		}
	}

	// 如果启用缓存则缓存结果
	if r.cache != nil && len(result) > 0 {
		r.cache.Set(domain, qtype, result)
	}

	return result, nil
}

// ResolveRecord 将域名解析为DNS记录（用于非IP记录的新方法）
func (r *Resolver) ResolveRecord(ctx context.Context, domain string, qtype uint16) ([]DNSRecord, error) {
	// 检查远程映射
	r.mappingsMu.RLock()
	records, found := r.mappings[domain]
	r.mappingsMu.RUnlock()

	if !found {
		return nil, fmt.Errorf("domain not found in remote mappings")
	}

	// 根据查询类型过滤记录
	var result []DNSRecord
	for _, record := range records {
		if record.Type == qtype {
			result = append(result, record)
		}
	}

	return result, nil
}