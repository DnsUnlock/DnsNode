package dns

import (
	"crypto/tls"
	"fmt"
	"log"
	"time"

	"github.com/DnsUnlock/DnsNode/config"
	"github.com/miekg/dns"
)

// DoTServer 表示DNS-over-TLS服务器
type DoTServer struct {
	config    *config.Config
	server    *dns.Server
	handler   *Handler
	tlsConfig *tls.Config
}

// NewDoTServer 创建一个新的DNS-over-TLS服务器
func NewDoTServer(cfg *config.Config, handler *Handler) (*DoTServer, error) {
	// 加载TLS证书
	cert, err := tls.LoadX509KeyPair(cfg.DoT.CertFile, cfg.DoT.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
	}

	s := &DoTServer{
		config:    cfg,
		handler:   handler,
		tlsConfig: tlsConfig,
	}

	// 创建DNS-over-TLS服务器
	s.server = &dns.Server{
		Addr:         fmt.Sprintf(":%d", cfg.DoT.Port),
		Net:          "tcp-tls",
		Handler:      handler,
		TLSConfig:    tlsConfig,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		NotifyStartedFunc: func() {
			if cfg.Debug {
				log.Printf("DNS-over-TLS server started on :%d", cfg.DoT.Port)
			}
		},
	}

	return s, nil
}

// Start 启动DoT服务器
func (s *DoTServer) Start() error {
	go func() {
		if err := s.server.ListenAndServe(); err != nil {
			log.Printf("DoT server error: %v", err)
		}
	}()
	return nil
}

// Stop 停止DoT服务器
func (s *DoTServer) Stop() error {
	return s.server.Shutdown()
}