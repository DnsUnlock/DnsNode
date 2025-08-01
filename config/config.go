package config

import (
	"encoding/json"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config 表示DNS服务器配置
type Config struct {
	ServerName          string        `yaml:"server_name" json:"server_name"`
	Port                int           `yaml:"port" json:"port"`
	Debug               bool          `yaml:"debug" json:"debug"`
	RemoteAPI           RemoteAPI     `yaml:"remote_api" json:"remote_api"`
	Cache               CacheConfig   `yaml:"cache" json:"cache"`
	SystemDNS           SystemDNS     `yaml:"system_dns" json:"system_dns"`
	MaxConcurrentQueries int          `yaml:"max_concurrent_queries" json:"max_concurrent_queries"`
	DoT                 DoTConfig     `yaml:"dot" json:"dot"`
	DoH                 DoHConfig     `yaml:"doh" json:"doh"`
	TLS                 TLSConfig     `yaml:"tls" json:"tls"`
}

// RemoteAPI 获取域名到IP映射的配置
type RemoteAPI struct {
	Enabled     bool          `yaml:"enabled" json:"enabled"`
	URL         string        `yaml:"url" json:"url"`                 // 已弃用: 使用WSURL或HTTPURL
	WSURL       string        `yaml:"ws_url" json:"ws_url"`            // 主WebSocket URL
	HTTPURL     string        `yaml:"http_url" json:"http_url"`        // 回退HTTP URL
	Timeout     time.Duration `yaml:"timeout" json:"timeout"`
	RefreshInterval time.Duration `yaml:"refresh_interval" json:"refresh_interval"`
	Headers     map[string]string `yaml:"headers" json:"headers"`
}

// CacheConfig DNS查询结果的缓存配置
type CacheConfig struct {
	Enabled         bool          `yaml:"enabled" json:"enabled"`
	MaxSize         int           `yaml:"max_size" json:"max_size"`
	DefaultTTL      time.Duration `yaml:"default_ttl" json:"default_ttl"`
	CleanupInterval time.Duration `yaml:"cleanup_interval" json:"cleanup_interval"`
	Path            string        `yaml:"path" json:"path"`               // BuntDB文件路径或":memory:"表示内存
	SyncPolicy      string        `yaml:"sync_policy" json:"sync_policy"` // 同步策略: "always", "everysecond", 或 "never"
}

// SystemDNS 回退DNS解析的配置
type SystemDNS struct {
	Enabled   bool     `yaml:"enabled" json:"enabled"`
	Servers   []string `yaml:"servers" json:"servers"`
	Timeout   time.Duration `yaml:"timeout" json:"timeout"`
	UseTCP    bool     `yaml:"use_tcp" json:"use_tcp"`
	UseDoT    bool     `yaml:"use_dot" json:"use_dot"`
	UseDoH    bool     `yaml:"use_doh" json:"use_doh"`
}

// DoTConfig DNS-over-TLS的配置
type DoTConfig struct {
	Enabled  bool   `yaml:"enabled" json:"enabled"`
	Port     int    `yaml:"port" json:"port"`
	CertFile string `yaml:"cert_file" json:"cert_file"`
	KeyFile  string `yaml:"key_file" json:"key_file"`
}

// DoHConfig DNS-over-HTTPS的配置
type DoHConfig struct {
	Enabled  bool   `yaml:"enabled" json:"enabled"`
	Port     int    `yaml:"port" json:"port"`
	Path     string `yaml:"path" json:"path"`
	CertFile string `yaml:"cert_file" json:"cert_file"`
	KeyFile  string `yaml:"key_file" json:"key_file"`
}

// TLSConfig TLS证书管理的配置
type TLSConfig struct {
	// 目前不需要配置 - 必须提供证书
}

// Default 返回默认配置
func Default() *Config {
	return &Config{
		ServerName: "DnsNode",
		Port:  53,
		Debug: false,
		RemoteAPI: RemoteAPI{
			Enabled:         true,
			URL:             "", // 已弃用
			WSURL:           "ws://example.com/api/dns-mappings",
			HTTPURL:         "https://example.com/api/dns-mappings",
			Timeout:         5 * time.Second,
			RefreshInterval: 5 * time.Minute,
			Headers:         make(map[string]string),
		},
		Cache: CacheConfig{
			Enabled:         true,
			MaxSize:         10000,
			DefaultTTL:      5 * time.Minute,
			CleanupInterval: 10 * time.Minute,
			Path:            ":memory:",
			SyncPolicy:      "everysecond",
		},
		SystemDNS: SystemDNS{
			Enabled: true,
			Servers: []string{
				"8.8.8.8:53",
				"8.8.4.4:53",
				"1.1.1.1:53",
			},
			Timeout: 3 * time.Second,
			UseTCP:  false,
		},
		MaxConcurrentQueries: 1000,
		DoT: DoTConfig{
			Enabled:  false,
			Port:     853,
			CertFile: "cert.pem",
			KeyFile:  "key.pem",
		},
		DoH: DoHConfig{
			Enabled:  false,
			Port:     443,
			Path:     "/dns-query",
			CertFile: "cert.pem",
			KeyFile:  "key.pem",
		},
		TLS: TLSConfig{},
	}
}

// Load 从文件加载配置
func Load(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	cfg := Default()
	
	// 先尝试YAML
	if err := yaml.Unmarshal(data, cfg); err != nil {
		// 如果YAML失败则尝试JSON
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, err
		}
	}

	return cfg, nil
}