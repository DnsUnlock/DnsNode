package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/DnsUnlock/DnsNode/acme"
	"github.com/DnsUnlock/DnsNode/config"
	"github.com/DnsUnlock/DnsNode/dns"
	"github.com/DnsUnlock/DnsNode/dpanel"
	"github.com/DnsUnlock/DnsNode/remote"
	"github.com/DnsUnlock/DnsNode/sniproxy"
)

var (
	apiURL = flag.String("api", "", "Dpanel API URL (required)")
	apiKey = flag.String("apikey", "", "Dpanel API Key (required)")
	debug  = flag.Bool("debug", false, "Enable debug mode")
)

func main() {
	flag.Parse()

	// 验证必需参数
	if *apiURL == "" || *apiKey == "" {
		fmt.Println("Usage: DnsNode -api <API_URL> -apikey <API_KEY> [-debug]")
		fmt.Println()
		fmt.Println("Required flags:")
		fmt.Println("  -api      Dpanel API URL (e.g., https://dpanel.example.com)")
		fmt.Println("  -apikey   Dpanel API Key")
		fmt.Println()
		fmt.Println("Optional flags:")
		fmt.Println("  -debug    Enable debug mode")
		os.Exit(1)
	}

	log.Printf("Starting DnsNode...")
	log.Printf("Connecting to Dpanel: %s", *apiURL)

	// 创建本地配置
	localConfig := &config.LocalConfig{
		API:    *apiURL,
		APIKey: *apiKey,
		Debug:  *debug,
	}

	// 创建 Dpanel 客户端
	dpanelClient := dpanel.NewClient(localConfig)

	// 用于存储服务实例
	var dnsServer *dns.Server
	var sniServer *sniproxy.Server
	var acmeManager *acme.Manager

	// 设置配置更新回调
	dpanelClient.SetConfigCallback(func(cfg *config.Config) {
		// 应用调试模式
		cfg.Debug = *debug || cfg.Debug

		log.Printf("Received config from Dpanel: %s (port: %d)", cfg.ServerName, cfg.Port)

		// 如果服务尚未启动，创建并启动
		if dnsServer == nil {
			var err error

			// 创建DNS服务器
			dnsServer, err = dns.NewServer(cfg)
			if err != nil {
				log.Fatalf("Failed to create DNS server: %v", err)
			}

			// 创建ACME管理器（如果启用）
			if cfg.ACME.Enabled {
				acmeManager, err = acme.NewManager(cfg)
				if err != nil {
					log.Printf("Warning: Failed to create ACME manager: %v", err)
				}
			}

			// 创建SNI代理（如果启用）
			if cfg.SNIProxy.Enabled {
				sniServer, err = sniproxy.NewServer(cfg)
				if err != nil {
					log.Fatalf("Failed to create SNI proxy: %v", err)
				}

				if acmeManager != nil {
					sniServer.SetACMEHandler(acmeManager.GetHTTPHandler())
					sniServer.SetTLSConfig(acmeManager.GetTLSConfig())
				}
			}

			// 启动服务
			if err := dnsServer.Start(); err != nil {
				log.Fatalf("Failed to start DNS server: %v", err)
			}
			log.Printf("DNS server started on port %d", cfg.Port)

			if acmeManager != nil {
				if err := acmeManager.Start(); err != nil {
					log.Printf("Warning: Failed to start ACME manager: %v", err)
				} else {
					log.Println("ACME certificate manager started")
				}
			}

			if sniServer != nil {
				if err := sniServer.Start(); err != nil {
					log.Fatalf("Failed to start SNI proxy: %v", err)
				}
				log.Printf("SNI Proxy started on HTTP:%d HTTPS:%d",
					cfg.SNIProxy.HTTPPort, cfg.SNIProxy.HTTPSPort)
			}
		}
		// TODO: 实现配置热更新
	})

	// 设置DNS记录更新回调
	dpanelClient.SetDNSCallback(func(records []*remote.DNSRecord) {
		if dnsServer != nil {
			recordStore := dnsServer.GetRecordStore()
			if recordStore != nil {
				recordStore.SetBatch(records)
				log.Printf("DNS records updated: %d records", len(records))
			}
		}
	})

	// 设置SNI规则更新回调
	dpanelClient.SetSNICallback(func(rules []*sniproxy.Rule) {
		if sniServer != nil {
			ruleTable := sniServer.GetRuleTable()
			if ruleTable != nil {
				ruleTable.SetRules(rules)
				log.Printf("SNI rules updated: %d rules", len(rules))
			}
		}
	})

	// 启动 Dpanel 客户端
	ctx := context.Background()
	if err := dpanelClient.Start(ctx); err != nil {
		log.Fatalf("Failed to connect to Dpanel: %v", err)
	}

	log.Printf("Connected to Dpanel successfully (transport: %s, session: %s)",
		dpanelClient.ActiveTransport(), dpanelClient.SessionID())

	if *debug {
		log.Println("Debug mode enabled")
	}

	// 等待中断信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("\nShutting down services...")

	// 停止 Dpanel 客户端
	dpanelClient.Stop()

	// 停止SNI代理
	if sniServer != nil {
		if err := sniServer.Stop(); err != nil {
			log.Printf("Error stopping SNI proxy: %v", err)
		}
	}

	// 停止ACME管理器
	if acmeManager != nil {
		if err := acmeManager.Stop(); err != nil {
			log.Printf("Error stopping ACME manager: %v", err)
		}
	}

	// 停止DNS服务器
	if dnsServer != nil {
		if err := dnsServer.Stop(); err != nil {
			log.Printf("Error stopping DNS server: %v", err)
		}
	}

	log.Println("All services stopped")
}
