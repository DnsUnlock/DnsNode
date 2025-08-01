package dns

import (
	"context"
	"log"
	"time"

	"github.com/miekg/dns"
)

// Handler 实现DNS请求处理器
type Handler struct {
	server   *Server
	limiter  chan struct{}
}

// NewHandler 创建一个新的DNS处理器
func NewHandler(server *Server) *Handler {
	return &Handler{
		server:  server,
		limiter: make(chan struct{}, server.config.MaxConcurrentQueries),
	}
}

// ServeDNS 处理DNS请求
func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	// 限速
	select {
	case h.limiter <- struct{}{}:
		defer func() { <-h.limiter }()
	default:
		// 并发请求过多
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		return
	}
	// 创建响应消息
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = true
	m.Authoritative = false
	m.RecursionAvailable = true

	// 处理每个问题
	for _, q := range r.Question {
		if h.server.config.Debug {
			log.Printf("Query: %s %s", q.Name, dns.TypeToString[q.Qtype])
		}

		// 创建带超时的上下文
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		// 根据查询类型处理
		switch q.Qtype {
		case dns.TypeA, dns.TypeAAAA:
			h.handleAQuery(ctx, m, q)
		case dns.TypeCNAME:
			h.handleCNAMEQuery(ctx, m, q)
		case dns.TypeTXT:
			h.handleTXTQuery(ctx, m, q)
		default:
			// 对于不支持的类型，返回NOTIMP
			m.Rcode = dns.RcodeNotImplemented
		}
	}

	// 发送响应
	if err := w.WriteMsg(m); err != nil {
		if h.server.config.Debug {
			log.Printf("Failed to write response: %v", err)
		}
	}
}

// handleAQuery 处理A和AAAA查询
func (h *Handler) handleAQuery(ctx context.Context, m *dns.Msg, q dns.Question) {
	domain := q.Name
	
	// 如果存在尾部点则删除
	if len(domain) > 0 && domain[len(domain)-1] == '.' {
		domain = domain[:len(domain)-1]
	}

	// 解析域名
	ips, err := h.server.Resolve(ctx, domain, q.Qtype)
	if err != nil {
		if h.server.config.Debug {
			log.Printf("Failed to resolve %s: %v", domain, err)
		}
		m.Rcode = dns.RcodeNameError
		return
	}

	// 添加答案
	for _, ip := range ips {
		var rr dns.RR
		if q.Qtype == dns.TypeA && ip.To4() != nil {
			rr = &dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: ip,
			}
		} else if q.Qtype == dns.TypeAAAA && ip.To4() == nil {
			rr = &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				AAAA: ip,
			}
		}
		
		if rr != nil {
			m.Answer = append(m.Answer, rr)
		}
	}

	// 如果没有添加答案，设置NXDOMAIN
	if len(m.Answer) == 0 {
		m.Rcode = dns.RcodeNameError
	}
}

// handleCNAMEQuery 处理CNAME查询
func (h *Handler) handleCNAMEQuery(ctx context.Context, m *dns.Msg, q dns.Question) {
	// 目前，我们不处理CNAME查询
	// 这可以扩展以支持来自远程源的CNAME记录
	m.Rcode = dns.RcodeNameError
}

// handleTXTQuery 处理TXT查询，包括版本查询
func (h *Handler) handleTXTQuery(ctx context.Context, m *dns.Msg, q dns.Question) {
	// 检查是否为版本查询
	if q.Name == "version.bind." || q.Name == "version.server." {
		// 返回服务器名称/版本
		rr := &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassCHAOS,
				Ttl:    0,
			},
			Txt: []string{h.server.config.ServerName},
		}
		m.Answer = append(m.Answer, rr)
		return
	}
	
	// 对于其他TXT查询，返回NXDOMAIN
	m.Rcode = dns.RcodeNameError
}