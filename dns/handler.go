package dns

import (
	"context"
	"encoding/base64"
	"log"
	"net"
	"time"

	"github.com/DnsUnlock/DnsNode/remote"
	"github.com/miekg/dns"
)

// Handler 实现DNS请求处理器
type Handler struct {
	server  *Server
	limiter chan struct{}
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
	select {
	case h.limiter <- struct{}{}:
		defer func() { <-h.limiter }()
	default:
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		return
	}

	sourceIP := extractSourceIP(w.RemoteAddr())

	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = true
	m.Authoritative = false
	m.RecursionAvailable = true

	for _, q := range r.Question {
		if h.server.config.Debug {
			log.Printf("Query from %s: %s %s", sourceIP, q.Name, dns.TypeToString[q.Qtype])
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		switch q.Qtype {
		case dns.TypeA, dns.TypeAAAA:
			h.handleAQuery(ctx, m, q, sourceIP)
		case dns.TypeCNAME:
			h.handleCNAMEQuery(m, q, sourceIP)
		case dns.TypeTXT:
			h.handleTXTQuery(m, q, sourceIP)
		case dns.TypeMX:
			h.handleMXQuery(m, q, sourceIP)
		case dns.TypeHTTPS:
			h.handleHTTPSQuery(m, q, sourceIP)
		case dns.TypeNS:
			h.handleNSQuery(m, q, sourceIP)
		default:
			m.Rcode = dns.RcodeNotImplemented
		}
	}

	if err := w.WriteMsg(m); err != nil {
		if h.server.config.Debug {
			log.Printf("Failed to write response: %v", err)
		}
	}
}

func extractSourceIP(addr net.Addr) net.IP {
	switch v := addr.(type) {
	case *net.UDPAddr:
		return v.IP
	case *net.TCPAddr:
		return v.IP
	default:
		host, _, _ := net.SplitHostPort(addr.String())
		return net.ParseIP(host)
	}
}

// handleAQuery 处理A和AAAA查询
func (h *Handler) handleAQuery(ctx context.Context, m *dns.Msg, q dns.Question, sourceIP net.IP) {
	domain := normalizeDomain(q.Name)

	ips, err := h.server.ResolveWithSource(ctx, domain, q.Qtype, sourceIP)
	if err != nil {
		if h.server.config.Debug {
			log.Printf("Failed to resolve %s: %v", domain, err)
		}
		m.Rcode = dns.RcodeNameError
		return
	}

	for _, ip := range ips {
		var rr dns.RR
		if q.Qtype == dns.TypeA && ip.To4() != nil {
			rr = &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   ip,
			}
		} else if q.Qtype == dns.TypeAAAA && ip.To4() == nil {
			rr = &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
				AAAA: ip,
			}
		}
		if rr != nil {
			m.Answer = append(m.Answer, rr)
		}
	}

	if len(m.Answer) == 0 {
		m.Rcode = dns.RcodeNameError
	}
}

// handleCNAMEQuery 处理CNAME查询
func (h *Handler) handleCNAMEQuery(m *dns.Msg, q dns.Question, sourceIP net.IP) {
	domain := normalizeDomain(q.Name)

	if h.server.recordStore == nil {
		m.Rcode = dns.RcodeNameError
		return
	}

	record := h.server.recordStore.Query(domain, remote.TypeCNAME, sourceIP)
	if record == nil || record.CNAME == "" {
		m.Rcode = dns.RcodeNameError
		return
	}

	target := record.CNAME
	if len(target) > 0 && target[len(target)-1] != '.' {
		target += "."
	}

	rr := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: uint32(record.TTL)},
		Target: target,
	}
	m.Answer = append(m.Answer, rr)
}

// handleTXTQuery 处理TXT查询
func (h *Handler) handleTXTQuery(m *dns.Msg, q dns.Question, sourceIP net.IP) {
	// 版本查询
	if q.Name == "version.bind." || q.Name == "version.server." {
		rr := &dns.TXT{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS, Ttl: 0},
			Txt: []string{h.server.config.ServerName},
		}
		m.Answer = append(m.Answer, rr)
		return
	}

	domain := normalizeDomain(q.Name)

	if h.server.recordStore == nil {
		m.Rcode = dns.RcodeNameError
		return
	}

	record := h.server.recordStore.Query(domain, remote.TypeTXT, sourceIP)
	if record == nil || len(record.Values) == 0 {
		m.Rcode = dns.RcodeNameError
		return
	}

	rr := &dns.TXT{
		Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: uint32(record.TTL)},
		Txt: record.Values,
	}
	m.Answer = append(m.Answer, rr)
}

// handleMXQuery 处理MX查询
func (h *Handler) handleMXQuery(m *dns.Msg, q dns.Question, sourceIP net.IP) {
	domain := normalizeDomain(q.Name)

	if h.server.recordStore == nil {
		m.Rcode = dns.RcodeNameError
		return
	}

	record := h.server.recordStore.Query(domain, remote.TypeMX, sourceIP)
	if record == nil || len(record.MX) == 0 {
		m.Rcode = dns.RcodeNameError
		return
	}

	for _, mx := range record.MX {
		host := mx.Host
		if len(host) > 0 && host[len(host)-1] != '.' {
			host += "."
		}

		rr := &dns.MX{
			Hdr:        dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: uint32(record.TTL)},
			Preference: uint16(mx.Priority),
			Mx:         host,
		}
		m.Answer = append(m.Answer, rr)
	}
}

// handleNSQuery 处理NS查询
func (h *Handler) handleNSQuery(m *dns.Msg, q dns.Question, sourceIP net.IP) {
	domain := normalizeDomain(q.Name)

	if h.server.recordStore == nil {
		m.Rcode = dns.RcodeNameError
		return
	}

	record := h.server.recordStore.Query(domain, remote.TypeNS, sourceIP)
	if record == nil || len(record.Values) == 0 {
		m.Rcode = dns.RcodeNameError
		return
	}

	for _, ns := range record.Values {
		if len(ns) > 0 && ns[len(ns)-1] != '.' {
			ns += "."
		}

		rr := &dns.NS{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: uint32(record.TTL)},
			Ns:  ns,
		}
		m.Answer = append(m.Answer, rr)
	}
}

// handleHTTPSQuery 处理HTTPS查询
func (h *Handler) handleHTTPSQuery(m *dns.Msg, q dns.Question, sourceIP net.IP) {
	domain := normalizeDomain(q.Name)

	if h.server.recordStore == nil {
		m.Rcode = dns.RcodeNameError
		return
	}

	record := h.server.recordStore.Query(domain, remote.TypeHTTPS, sourceIP)
	if record == nil || len(record.HTTPS) == 0 {
		m.Rcode = dns.RcodeNameError
		return
	}

	for _, https := range record.HTTPS {
		rr := h.buildHTTPSRecord(q.Name, uint32(record.TTL), https)
		if rr != nil {
			m.Answer = append(m.Answer, rr)
		}
	}
}

// buildHTTPSRecord 构建HTTPS记录
func (h *Handler) buildHTTPSRecord(name string, ttl uint32, v remote.HTTPSValue) *dns.HTTPS {
	target := v.Target
	if target == "" {
		target = "."
	} else if target[len(target)-1] != '.' {
		target += "."
	}

	rr := &dns.HTTPS{
		SVCB: dns.SVCB{
			Hdr:      dns.RR_Header{Name: name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: ttl},
			Priority: uint16(v.Priority),
			Target:   target,
		},
	}

	if len(v.ALPN) > 0 {
		rr.Value = append(rr.Value, &dns.SVCBAlpn{Alpn: v.ALPN})
	}
	if v.NoDefALPN {
		rr.Value = append(rr.Value, &dns.SVCBNoDefaultAlpn{})
	}
	if v.Port > 0 {
		rr.Value = append(rr.Value, &dns.SVCBPort{Port: uint16(v.Port)})
	}

	if len(v.IPv4Hint) > 0 {
		var ips []net.IP
		for _, s := range v.IPv4Hint {
			if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
				ips = append(ips, ip.To4())
			}
		}
		if len(ips) > 0 {
			rr.Value = append(rr.Value, &dns.SVCBIPv4Hint{Hint: ips})
		}
	}

	if len(v.IPv6Hint) > 0 {
		var ips []net.IP
		for _, s := range v.IPv6Hint {
			if ip := net.ParseIP(s); ip != nil && ip.To4() == nil {
				ips = append(ips, ip)
			}
		}
		if len(ips) > 0 {
			rr.Value = append(rr.Value, &dns.SVCBIPv6Hint{Hint: ips})
		}
	}

	if v.ECH != "" {
		if data, err := base64.StdEncoding.DecodeString(v.ECH); err == nil {
			rr.Value = append(rr.Value, &dns.SVCBECHConfig{ECH: data})
		}
	}

	return rr
}

func normalizeDomain(domain string) string {
	if len(domain) > 0 && domain[len(domain)-1] == '.' {
		return domain[:len(domain)-1]
	}
	return domain
}
