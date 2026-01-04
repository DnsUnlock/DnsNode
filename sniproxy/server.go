package sniproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DnsUnlock/DnsNode/config"
	"github.com/DnsUnlock/DnsNode/sniproxy/transport"
)

// Server SNI代理服务器
type Server struct {
	config        *config.Config
	httpListener  net.Listener
	httpsListener net.Listener
	ruleTable     *RuleTable
	stats         *StatsCollector
	directDialer  transport.Dialer
	socks5Dialer  transport.Dialer
	connCounter   int64
	stopChan      chan struct{}
	wg            sync.WaitGroup
	httpMux       *http.ServeMux
	acmeHandler   http.Handler // ACME HTTP-01 挑战处理器
	dohHandler    http.Handler // DoH 处理器
	tlsConfig     *tls.Config
}

// NewServer 创建SNI代理服务器
func NewServer(cfg *config.Config) (*Server, error) {
	dialerConfig := transport.DefaultDialerConfig()
	dialerConfig.ConnectTimeout = cfg.SNIProxy.ReadTimeout
	dialerConfig.ReadTimeout = cfg.SNIProxy.ReadTimeout
	dialerConfig.WriteTimeout = cfg.SNIProxy.WriteTimeout

	s := &Server{
		config:       cfg,
		ruleTable:    NewRuleTable(cfg.SNIProxy.DefaultTransport),
		stats:        NewStatsCollector(&NoopReporter{}),
		directDialer: transport.NewDirectDialer(dialerConfig),
		stopChan:     make(chan struct{}),
		httpMux:      http.NewServeMux(),
	}

	// 如果配置了SOCKS5代理
	if cfg.SNIProxy.SOCKS5.Address != "" {
		s.socks5Dialer = transport.NewSOCKS5Dialer(
			dialerConfig,
			cfg.SNIProxy.SOCKS5.Address,
			cfg.SNIProxy.SOCKS5.Username,
			cfg.SNIProxy.SOCKS5.Password,
		)
	}

	return s, nil
}

// SetACMEHandler 设置ACME挑战处理器
func (s *Server) SetACMEHandler(handler http.Handler) {
	s.acmeHandler = handler
}

// SetDoHHandler 设置DoH处理器
func (s *Server) SetDoHHandler(handler http.Handler) {
	s.dohHandler = handler
}

// SetTLSConfig 设置TLS配置（用于DoH）
func (s *Server) SetTLSConfig(tlsConfig *tls.Config) {
	s.tlsConfig = tlsConfig
}

// SetStatsReporter 设置统计上报器
func (s *Server) SetStatsReporter(reporter StatsReporter) {
	s.stats = NewStatsCollector(reporter)
}

// GetRuleTable 获取规则表
func (s *Server) GetRuleTable() *RuleTable {
	return s.ruleTable
}

// GetStats 获取统计收集器
func (s *Server) GetStats() *StatsCollector {
	return s.stats
}

// Start 启动服务器
func (s *Server) Start() error {
	var err error

	// 启动HTTP监听器 (80端口)
	s.httpListener, err = net.Listen("tcp", fmt.Sprintf(":%d", s.config.SNIProxy.HTTPPort))
	if err != nil {
		return fmt.Errorf("failed to listen on HTTP port: %w", err)
	}

	// 启动HTTPS监听器 (443端口)
	s.httpsListener, err = net.Listen("tcp", fmt.Sprintf(":%d", s.config.SNIProxy.HTTPSPort))
	if err != nil {
		s.httpListener.Close()
		return fmt.Errorf("failed to listen on HTTPS port: %w", err)
	}

	// 启动HTTP服务
	s.wg.Add(1)
	go s.serveHTTP()

	// 启动HTTPS/SNI代理服务
	s.wg.Add(1)
	go s.serveHTTPS()

	if s.config.Debug {
		log.Printf("SNI Proxy started on HTTP:%d HTTPS:%d",
			s.config.SNIProxy.HTTPPort, s.config.SNIProxy.HTTPSPort)
	}

	return nil
}

// Stop 停止服务器
func (s *Server) Stop() error {
	close(s.stopChan)

	if s.httpListener != nil {
		s.httpListener.Close()
	}
	if s.httpsListener != nil {
		s.httpsListener.Close()
	}

	s.wg.Wait()

	if s.directDialer != nil {
		s.directDialer.Close()
	}
	if s.socks5Dialer != nil {
		s.socks5Dialer.Close()
	}

	return nil
}

// serveHTTP 处理HTTP连接（用于ACME挑战和HTTP代理）
func (s *Server) serveHTTP() {
	defer s.wg.Done()

	for {
		conn, err := s.httpListener.Accept()
		if err != nil {
			select {
			case <-s.stopChan:
				return
			default:
				if s.config.Debug {
					log.Printf("HTTP accept error: %v", err)
				}
				continue
			}
		}

		go s.handleHTTPConnection(conn)
	}
}

// serveHTTPS 处理HTTPS连接
func (s *Server) serveHTTPS() {
	defer s.wg.Done()

	for {
		conn, err := s.httpsListener.Accept()
		if err != nil {
			select {
			case <-s.stopChan:
				return
			default:
				if s.config.Debug {
					log.Printf("HTTPS accept error: %v", err)
				}
				continue
			}
		}

		go s.handleHTTPSConnection(conn)
	}
}

// handleHTTPConnection 处理HTTP连接
func (s *Server) handleHTTPConnection(conn net.Conn) {
	defer conn.Close()

	// 设置超时
	conn.SetDeadline(time.Now().Add(s.config.SNIProxy.ReadTimeout))

	// 读取HTTP请求以判断是ACME挑战还是普通HTTP请求
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	// 检查是否为ACME挑战请求
	if s.acmeHandler != nil && isACMEChallenge(buf[:n]) {
		s.handleACMEChallenge(conn, buf[:n])
		return
	}

	// 处理普通HTTP代理请求
	s.handleHTTPProxy(conn, buf[:n])
}

// handleHTTPSConnection 处理HTTPS连接
func (s *Server) handleHTTPSConnection(conn net.Conn) {
	defer conn.Close()

	connID := s.generateConnID()
	sourceIP := extractIP(conn.RemoteAddr())

	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(s.config.SNIProxy.ReadTimeout))

	// 解析SNI
	sni, clientHello, err := PeekClientHello(conn)
	if err != nil {
		if s.config.Debug {
			log.Printf("Failed to parse SNI from %s: %v", sourceIP, err)
		}
		return
	}

	// 检查是否需要处理DoH请求
	if s.shouldHandleDoH(sni) {
		s.handleDoHConnection(conn, clientHello)
		return
	}

	// 匹配规则
	match := s.ruleTable.Match(net.ParseIP(sourceIP), sni)

	// 记录统计
	stats := s.stats.StartConnection(connID, sourceIP, sni, match.TargetAddress, match.Transport)

	// 选择传输层
	dialer := s.selectDialer(match.Transport)

	// 连接到目标
	ctx, cancel := context.WithTimeout(context.Background(), s.config.SNIProxy.ReadTimeout)
	defer cancel()

	targetConn, err := dialer.Dial(ctx, "tcp", match.TargetAddress)
	if err != nil {
		s.stats.EndConnection(connID, err)
		if s.config.Debug {
			log.Printf("Failed to connect to %s: %v", match.TargetAddress, err)
		}
		return
	}
	defer targetConn.Close()

	// 发送已读取的ClientHello
	if _, err := targetConn.Write(clientHello); err != nil {
		s.stats.EndConnection(connID, err)
		return
	}

	// 重置超时
	conn.SetDeadline(time.Time{})
	targetConn.SetDeadline(time.Time{})

	// 双向转发
	var wg sync.WaitGroup
	wg.Add(2)

	var totalRead, totalWritten int64

	go func() {
		defer wg.Done()
		n, _ := io.Copy(targetConn, conn)
		atomic.AddInt64(&totalWritten, n)
		targetConn.(*net.TCPConn).CloseWrite()
	}()

	go func() {
		defer wg.Done()
		n, _ := io.Copy(conn, targetConn)
		atomic.AddInt64(&totalRead, n)
		conn.(*net.TCPConn).CloseWrite()
	}()

	wg.Wait()

	// 更新统计
	s.stats.UpdateBytes(connID, totalRead, totalWritten)
	s.stats.EndConnection(connID, nil)

	if s.config.Debug {
		log.Printf("Connection %s -> %s completed: read=%d written=%d",
			sourceIP, match.TargetAddress, stats.BytesRead, stats.BytesWritten)
	}
}

// handleDoHConnection 处理DoH连接
func (s *Server) handleDoHConnection(conn net.Conn, clientHello []byte) {
	if s.dohHandler == nil || s.tlsConfig == nil {
		return
	}

	// 创建一个预读连接
	prefixConn := &prefixConn{
		Conn:   conn,
		prefix: clientHello,
	}

	// 创建TLS连接
	tlsConn := tls.Server(prefixConn, s.tlsConfig)
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		if s.config.Debug {
			log.Printf("DoH TLS handshake failed: %v", err)
		}
		return
	}

	// 使用HTTP处理
	// 这里需要实现HTTP/1.1或HTTP/2处理
	// 简化实现：直接使用http.Serve
	http.Serve(&singleConnListener{conn: tlsConn}, s.dohHandler)
}

// handleACMEChallenge 处理ACME挑战
func (s *Server) handleACMEChallenge(conn net.Conn, data []byte) {
	// 创建预读连接
	prefixConn := &prefixConn{
		Conn:   conn,
		prefix: data,
	}

	// 使用HTTP处理ACME挑战
	http.Serve(&singleConnListener{conn: prefixConn}, s.acmeHandler)
}

// handleHTTPProxy 处理HTTP代理
func (s *Server) handleHTTPProxy(conn net.Conn, data []byte) {
	// 解析HTTP请求获取Host
	host := extractHostFromHTTP(data)
	if host == "" {
		return
	}

	connID := s.generateConnID()
	sourceIP := extractIP(conn.RemoteAddr())

	// 匹配规则
	match := s.ruleTable.Match(net.ParseIP(sourceIP), host)
	target := host + ":80"
	if match.TargetAddress != "" {
		target = match.TargetAddress
	}

	// 记录统计
	s.stats.StartConnection(connID, sourceIP, host, target, match.Transport)

	// 选择传输层
	dialer := s.selectDialer(match.Transport)

	// 连接到目标
	ctx, cancel := context.WithTimeout(context.Background(), s.config.SNIProxy.ReadTimeout)
	defer cancel()

	targetConn, err := dialer.Dial(ctx, "tcp", target)
	if err != nil {
		s.stats.EndConnection(connID, err)
		return
	}
	defer targetConn.Close()

	// 发送已读取的数据
	if _, err := targetConn.Write(data); err != nil {
		s.stats.EndConnection(connID, err)
		return
	}

	// 双向转发
	var wg sync.WaitGroup
	wg.Add(2)

	var totalRead, totalWritten int64

	go func() {
		defer wg.Done()
		n, _ := io.Copy(targetConn, conn)
		atomic.AddInt64(&totalWritten, n)
	}()

	go func() {
		defer wg.Done()
		n, _ := io.Copy(conn, targetConn)
		atomic.AddInt64(&totalRead, n)
	}()

	wg.Wait()

	s.stats.UpdateBytes(connID, totalRead, totalWritten)
	s.stats.EndConnection(connID, nil)
}

// selectDialer 选择传输层
func (s *Server) selectDialer(transportType string) transport.Dialer {
	switch transportType {
	case "socks5":
		if s.socks5Dialer != nil {
			return s.socks5Dialer
		}
	}
	return s.directDialer
}

// shouldHandleDoH 判断是否应该处理DoH请求
func (s *Server) shouldHandleDoH(sni string) bool {
	// 检查SNI是否匹配DoH域名
	// 这需要从配置或ACME模块获取域名列表
	return s.dohHandler != nil && s.config.DoH.Enabled
}

// generateConnID 生成连接ID
func (s *Server) generateConnID() string {
	id := atomic.AddInt64(&s.connCounter, 1)
	return fmt.Sprintf("conn-%d-%d", time.Now().UnixNano(), id)
}

// extractIP 从地址中提取IP
func extractIP(addr net.Addr) string {
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		return tcpAddr.IP.String()
	}
	host, _, _ := net.SplitHostPort(addr.String())
	return host
}

// isACMEChallenge 检查是否为ACME挑战请求
func isACMEChallenge(data []byte) bool {
	// 检查是否包含 /.well-known/acme-challenge/
	return len(data) > 50 && string(data[:4]) == "GET " &&
		contains(data, []byte("/.well-known/acme-challenge/"))
}

// extractHostFromHTTP 从HTTP请求中提取Host
func extractHostFromHTTP(data []byte) string {
	// 简单解析HTTP头获取Host
	lines := splitLines(data)
	for _, line := range lines {
		if len(line) > 6 && (line[0] == 'H' || line[0] == 'h') {
			if contains(line, []byte("Host:")) || contains(line, []byte("host:")) {
				host := line[5:]
				// 去除空格
				for len(host) > 0 && host[0] == ' ' {
					host = host[1:]
				}
				// 去除端口
				for i, b := range host {
					if b == ':' || b == '\r' || b == '\n' {
						return string(host[:i])
					}
				}
				return string(host)
			}
		}
	}
	return ""
}

func contains(data, pattern []byte) bool {
	for i := 0; i <= len(data)-len(pattern); i++ {
		if string(data[i:i+len(pattern)]) == string(pattern) {
			return true
		}
	}
	return false
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			lines = append(lines, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}

// prefixConn 预读连接包装器
type prefixConn struct {
	net.Conn
	prefix []byte
	read   bool
}

func (c *prefixConn) Read(b []byte) (int, error) {
	if !c.read && len(c.prefix) > 0 {
		c.read = true
		n := copy(b, c.prefix)
		if n < len(c.prefix) {
			c.prefix = c.prefix[n:]
			c.read = false
		}
		return n, nil
	}
	return c.Conn.Read(b)
}

// singleConnListener 单连接监听器
type singleConnListener struct {
	conn   net.Conn
	served bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.served {
		return nil, io.EOF
	}
	l.served = true
	return l.conn, nil
}

func (l *singleConnListener) Close() error   { return nil }
func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }
