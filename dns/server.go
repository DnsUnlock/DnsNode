package dns

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/DnsUnlock/DnsNode/config"
	"github.com/DnsUnlock/DnsNode/remote"
	"github.com/DnsUnlock/DnsNode/system"
	"github.com/DnsUnlock/DnsNode/tls"
	"github.com/miekg/dns"
)

// Server 表示DNS服务器
type Server struct {
	config         *config.Config
	udpServer      *dns.Server
	tcpServer      *dns.Server
	dotServer      *DoTServer
	dohServer      *DoHServer
	handler        *Handler
	remoteResolver *remote.Resolver
	systemResolver *system.Resolver
	certManager    *tls.CertificateManager
	stopChan       chan struct{}
	wg             sync.WaitGroup
}

// NewServer 创建一个新的DNS服务器实例
func NewServer(cfg *config.Config) (*Server, error) {
	s := &Server{
		config:   cfg,
		stopChan: make(chan struct{}),
	}

	// 如果启用则初始化远程解析器
	if cfg.RemoteAPI.Enabled {
		remoteResolver, err := remote.NewResolver(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create remote resolver: %w", err)
		}
		s.remoteResolver = remoteResolver
	}

	// 如果启用则初始化系统解析器
	if cfg.SystemDNS.Enabled {
		systemResolver, err := system.NewResolver(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create system resolver: %w", err)
		}
		s.systemResolver = systemResolver
	}

	// 如果DoT或DoH启用则初始化证书管理器
	if cfg.DoT.Enabled || cfg.DoH.Enabled {
		certManager := tls.NewCertificateManager(cfg)
		if err := certManager.EnsureCertificates(); err != nil {
			return nil, fmt.Errorf("failed to ensure certificates: %w", err)
		}
		s.certManager = certManager
	}

	// 创建DNS处理器
	s.handler = NewHandler(s)

	// 如果启用则创建DoT服务器
	if cfg.DoT.Enabled {
		dotServer, err := NewDoTServer(cfg, s.handler)
		if err != nil {
			return nil, fmt.Errorf("failed to create DoT server: %w", err)
		}
		s.dotServer = dotServer
	}

	// 如果启用则创建DoH服务器
	if cfg.DoH.Enabled {
		dohServer, err := NewDoHServer(cfg, s.handler)
		if err != nil {
			return nil, fmt.Errorf("failed to create DoH server: %w", err)
		}
		s.dohServer = dohServer
	}

	// 创建UDP服务器
	s.udpServer = &dns.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Net:          "udp",
		Handler:      s.handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		NotifyStartedFunc: func() {
			if cfg.Debug {
				log.Printf("UDP DNS server started on :%d", cfg.Port)
			}
		},
	}

	// 创建TCP服务器
	s.tcpServer = &dns.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Net:          "tcp",
		Handler:      s.handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		NotifyStartedFunc: func() {
			if cfg.Debug {
				log.Printf("TCP DNS server started on :%d", cfg.Port)
			}
		},
	}

	return s, nil
}

// Start 启动DNS服务器
func (s *Server) Start() error {
	// 如果启用则启动远程解析器
	if s.remoteResolver != nil {
		if err := s.remoteResolver.Start(); err != nil {
			return fmt.Errorf("failed to start remote resolver: %w", err)
		}
	}

	// 启动UDP服务器
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.udpServer.ListenAndServe(); err != nil {
			log.Printf("UDP server error: %v", err)
		}
	}()

	// 启动TCP服务器
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.tcpServer.ListenAndServe(); err != nil {
			log.Printf("TCP server error: %v", err)
		}
	}()

	// 如果启用则启动DoT服务器
	if s.dotServer != nil {
		if err := s.dotServer.Start(); err != nil {
			return fmt.Errorf("failed to start DoT server: %w", err)
		}
	}

	// 如果启用则启动DoH服务器
	if s.dohServer != nil {
		if err := s.dohServer.Start(); err != nil {
			return fmt.Errorf("failed to start DoH server: %w", err)
		}
	}

	return nil
}

// Stop 停止DNS服务器
func (s *Server) Stop() error {
	close(s.stopChan)

	// 如果运行中则停止远程解析器
	if s.remoteResolver != nil {
		s.remoteResolver.Stop()
	}

	// 关闭服务器
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.udpServer.ShutdownContext(ctx); err != nil {
		log.Printf("Error shutting down UDP server: %v", err)
	}

	if err := s.tcpServer.ShutdownContext(ctx); err != nil {
		log.Printf("Error shutting down TCP server: %v", err)
	}

	// 如果运行中则停止DoT服务器
	if s.dotServer != nil {
		if err := s.dotServer.Stop(); err != nil {
			log.Printf("Error stopping DoT server: %v", err)
		}
	}

	// 如果运行中则停止DoH服务器
	if s.dohServer != nil {
		if err := s.dohServer.Stop(); err != nil {
			log.Printf("Error stopping DoH server: %v", err)
		}
	}

	// 等待所有goroutine结束
	s.wg.Wait()

	return nil
}

// Resolve 解析DNS查询
func (s *Server) Resolve(ctx context.Context, domain string, qtype uint16) ([]net.IP, error) {
	// 如果启用先尝试远程解析器
	if s.remoteResolver != nil {
		ips, err := s.remoteResolver.Resolve(ctx, domain, qtype)
		if err == nil && len(ips) > 0 {
			if s.config.Debug {
				log.Printf("Resolved %s from remote: %v", domain, ips)
			}
			return ips, nil
		}
	}

	// 回退到系统解析器
	if s.systemResolver != nil {
		ips, err := s.systemResolver.Resolve(ctx, domain, qtype)
		if err == nil && len(ips) > 0 {
			if s.config.Debug {
				log.Printf("Resolved %s from system: %v", domain, ips)
			}
			return ips, nil
		}
		if err != nil && s.config.Debug {
			log.Printf("System resolver error for %s: %v", domain, err)
		}
	}

	return nil, fmt.Errorf("no resolver available or domain not found")
}