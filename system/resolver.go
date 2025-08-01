package system

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/DnsUnlock/DnsNode/config"
	"github.com/miekg/dns"
)

// Resolver 处理系统DNS解析
type Resolver struct {
	config      *config.Config
	clients     map[string]*dns.Client
	clientsMu   sync.RWMutex
	resolver    *net.Resolver
	dotClients  map[string]*DoTClient
	dohClients  map[string]*DoHClient
}

// NewResolver 创建一个新的系统解析器
func NewResolver(cfg *config.Config) (*Resolver, error) {
	r := &Resolver{
		config:     cfg,
		clients:    make(map[string]*dns.Client),
		dotClients: make(map[string]*DoTClient),
		dohClients: make(map[string]*DoHClient),
	}

	// 为每个服务器初始化DNS客户端
	for _, server := range cfg.SystemDNS.Servers {
		if cfg.SystemDNS.UseDoT {
			// 创建DoT客户端
			r.dotClients[server] = NewDoTClient(server, cfg.SystemDNS.Timeout)
		} else if cfg.SystemDNS.UseDoH {
			// 创建DoH客户端
			// 假设服务器是DoH的完整URL
			r.dohClients[server] = NewDoHClient(server, cfg.SystemDNS.Timeout, false)
		} else {
			// 创建标准DNS客户端
			client := &dns.Client{
				Timeout: cfg.SystemDNS.Timeout,
				Net:     "udp",
			}
			if cfg.SystemDNS.UseTCP {
				client.Net = "tcp"
			}
			r.clients[server] = client
		}
	}

	// 同时设置标净的net.Resolver作为回退
	r.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: cfg.SystemDNS.Timeout,
			}
			return d.DialContext(ctx, network, address)
		},
	}

	return r, nil
}

// Resolve 使用系统DNS解析域名
func (r *Resolver) Resolve(ctx context.Context, domain string, qtype uint16) ([]net.IP, error) {
	// 尝试每个配置的DNS服务器
	for _, server := range r.config.SystemDNS.Servers {
		ips, err := r.queryServer(ctx, server, domain, qtype)
		if err == nil && len(ips) > 0 {
			return ips, nil
		}
	}

	// 对A/AAAA查询回退到标准解析器
	if qtype == dns.TypeA || qtype == dns.TypeAAAA {
		return r.fallbackResolve(ctx, domain)
	}

	return nil, fmt.Errorf("failed to resolve domain")
}

// queryServer 查询特定DNS服务器
func (r *Resolver) queryServer(ctx context.Context, server, domain string, qtype uint16) ([]net.IP, error) {
	// 创建DNS消息
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	m.RecursionDesired = true

	var resp *dns.Msg
	var err error

	// 检查是否为DoT服务器
	if dotClient, ok := r.dotClients[server]; ok {
		resp, err = dotClient.Query(ctx, m)
	} else if dohClient, ok := r.dohClients[server]; ok {
		// 检查是否为DoH服务器
		resp, err = dohClient.Query(ctx, m)
	} else {
		// 标准DNS查询
		r.clientsMu.RLock()
		client, ok := r.clients[server]
		r.clientsMu.RUnlock()
		
		if !ok {
			return nil, fmt.Errorf("client not found for server %s", server)
		}
		
		resp, _, err = client.ExchangeContext(ctx, m, server)
	}

	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("query failed with rcode: %s", dns.RcodeToString[resp.Rcode])
	}

	// 从响应中提取IP地址
	var ips []net.IP
	for _, ans := range resp.Answer {
		switch rr := ans.(type) {
		case *dns.A:
			ips = append(ips, rr.A)
		case *dns.AAAA:
			ips = append(ips, rr.AAAA)
		}
	}

	return ips, nil
}

// fallbackResolve 使用标净的net.Resolver
func (r *Resolver) fallbackResolve(ctx context.Context, domain string) ([]net.IP, error) {
	// 设置超时上下文
	ctx, cancel := context.WithTimeout(ctx, r.config.SystemDNS.Timeout)
	defer cancel()

	ips, err := r.resolver.LookupIPAddr(ctx, domain)
	if err != nil {
		return nil, err
	}

	result := make([]net.IP, len(ips))
	for i, ip := range ips {
		result[i] = ip.IP
	}

	return result, nil
}

// Close 关闭所有DNS客户端
func (r *Resolver) Close() error {
	// DNS客户端不需要显式关闭
	return nil
}