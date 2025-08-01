package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/DnsUnlock/DnsNode/config"
	"github.com/DnsUnlock/DnsNode/dns"
)

var (
	configFile = flag.String("config", "config.yaml", "Path to configuration file")
	port       = flag.Int("port", 53, "DNS server port")
	debug      = flag.Bool("debug", false, "Enable debug mode")
)

func main() {
	flag.Parse()

	// 加载配置
	cfg, err := config.Load(*configFile)
	if err != nil {
		log.Printf("Warning: Failed to load config file: %v, using defaults", err)
		cfg = config.Default()
	}

	// 使用命令行标志覆盖
	if *port != 53 {
		cfg.Port = *port
	}
	if *debug {
		cfg.Debug = true
	}

	// 创建DNS服务器
	server, err := dns.NewServer(cfg)
	if err != nil {
		log.Fatalf("Failed to create DNS server: %v", err)
	}

	// 启动服务器
	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start DNS server: %v", err)
	}

	fmt.Printf("%s started on port %d\n", cfg.ServerName, cfg.Port)
	if cfg.Debug {
		fmt.Println("Debug mode enabled")
	}

	// 等待中断信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\nShutting down DNS server...")
	if err := server.Stop(); err != nil {
		log.Printf("Error stopping server: %v", err)
	}
	fmt.Println("DNS server stopped")
}