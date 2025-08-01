package dns

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/DnsUnlock/DnsNode/config"
	"github.com/miekg/dns"
)

// DoHServer 表示DNS-over-HTTPS服务器
type DoHServer struct {
	config   *config.Config
	server   *http.Server
	handler  *Handler
	mux      *http.ServeMux
}

// NewDoHServer 创建一个新的DNS-over-HTTPS服务器
func NewDoHServer(cfg *config.Config, handler *Handler) (*DoHServer, error) {
	s := &DoHServer{
		config:  cfg,
		handler: handler,
		mux:     http.NewServeMux(),
	}

	// 设置HTTP路由
	s.mux.HandleFunc(cfg.DoH.Path, s.handleDoH)
	s.mux.HandleFunc("/health", s.handleHealth)

	// 创建HTTPS服务器
	s.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.DoH.Port),
		Handler:      s.mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return s, nil
}

// Start 启动DoH服务器
func (s *DoHServer) Start() error {
	go func() {
		if s.config.Debug {
			log.Printf("DNS-over-HTTPS server starting on :%d%s", s.config.DoH.Port, s.config.DoH.Path)
		}
		
		if err := s.server.ListenAndServeTLS(s.config.DoH.CertFile, s.config.DoH.KeyFile); err != nil && err != http.ErrServerClosed {
			log.Printf("DoH server error: %v", err)
		}
	}()
	return nil
}

// Stop 停止DoH服务器
func (s *DoHServer) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}

// handleDoH 处理DNS-over-HTTPS请求
func (s *DoHServer) handleDoH(w http.ResponseWriter, r *http.Request) {
	var msg *dns.Msg
	var err error

	switch r.Method {
	case http.MethodGet:
		msg, err = s.handleGETRequest(r)
	case http.MethodPost:
		msg, err = s.handlePOSTRequest(r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err != nil {
		if s.config.Debug {
			log.Printf("DoH request error: %v", err)
		}
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// 创建自定义的ResponseWriter来捕获DNS响应
	dnsWriter := &dohResponseWriter{
		responseMsg: new(dns.Msg),
	}

	// 处理DNS查询
	s.handler.ServeDNS(dnsWriter, msg)

	// 打包响应
	respData, err := dnsWriter.responseMsg.Pack()
	if err != nil {
		if s.config.Debug {
			log.Printf("Failed to pack DNS response: %v", err)
		}
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 设置响应头
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Content-Length", strconv.Itoa(len(respData)))
	w.Header().Set("Cache-Control", "no-cache, no-store")

	// 写入响应
	w.Write(respData)
}

// handleGETRequest 处理带有base64url编码DNS消息的GET请求
func (s *DoHServer) handleGETRequest(r *http.Request) (*dns.Msg, error) {
	dnsParam := r.URL.Query().Get("dns")
	if dnsParam == "" {
		return nil, fmt.Errorf("missing 'dns' parameter")
	}

	// 解码base64url
	data, err := base64.RawURLEncoding.DecodeString(dnsParam)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64url: %w", err)
	}

	// 解包DNS消息
	msg := new(dns.Msg)
	if err := msg.Unpack(data); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS message: %w", err)
	}

	return msg, nil
}

// handlePOSTRequest 处理在请求体中包含DNS消息的POST请求
func (s *DoHServer) handlePOSTRequest(r *http.Request) (*dns.Msg, error) {
	if r.Header.Get("Content-Type") != "application/dns-message" {
		return nil, fmt.Errorf("invalid content type")
	}

	// 读取请求体
	body, err := io.ReadAll(io.LimitReader(r.Body, 65536)) // 64KB限制
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}

	// 解包DNS消息
	msg := new(dns.Msg)
	if err := msg.Unpack(body); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS message: %w", err)
	}

	return msg, nil
}

// handleHealth 处理健康检查请求
func (s *DoHServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// dohResponseWriter 为DoH实现dns.ResponseWriter接口
type dohResponseWriter struct {
	responseMsg *dns.Msg
}

func (w *dohResponseWriter) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: 443}
}

func (w *dohResponseWriter) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

func (w *dohResponseWriter) WriteMsg(m *dns.Msg) error {
	w.responseMsg = m
	return nil
}

func (w *dohResponseWriter) Write([]byte) (int, error) {
	return 0, fmt.Errorf("not implemented")
}

func (w *dohResponseWriter) Close() error {
	return nil
}

func (w *dohResponseWriter) TsigStatus() error {
	return nil
}

func (w *dohResponseWriter) TsigTimersOnly(bool) {}

func (w *dohResponseWriter) Hijack() {}

func (w *dohResponseWriter) Network() string {
	return "tcp"
}