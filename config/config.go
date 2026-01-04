package config

import (
	"encoding/json"
	"time"
)

// LocalConfig 本地启动参数（通过命令行传入）
type LocalConfig struct {
	API    string // Dpanel API 地址
	APIKey string // Dpanel API Key
	Debug  bool   // 调试模式
}

// Config 表示完整的服务配置（从 Dpanel 获取）
type Config struct {
	ServerName           string          `json:"server_name"`
	Port                 int             `json:"port"`
	Debug                bool            `json:"debug"`
	Cache                CacheConfig     `json:"cache"`
	SystemDNS            SystemDNS       `json:"system_dns"`
	MaxConcurrentQueries int             `json:"max_concurrent_queries"`
	DoT                  DoTConfig       `json:"dot"`
	DoH                  DoHConfig       `json:"doh"`
	SNIProxy             SNIProxyConfig  `json:"sni_proxy"`
	ACME                 ACMEConfig      `json:"acme"`
}

// CacheConfig DNS查询结果的缓存配置
type CacheConfig struct {
	Enabled         bool          `json:"enabled"`
	MaxSize         int           `json:"max_size"`
	DefaultTTL      time.Duration `json:"default_ttl"`
	CleanupInterval time.Duration `json:"cleanup_interval"`
}

// SystemDNS 回退DNS解析的配置
type SystemDNS struct {
	Enabled bool     `json:"enabled"`
	Servers []string `json:"servers"`
	Timeout time.Duration `json:"timeout"`
	UseTCP  bool     `json:"use_tcp"`
	UseDoT  bool     `json:"use_dot"`
	UseDoH  bool     `json:"use_doh"`
}

// DoTConfig DNS-over-TLS的配置
type DoTConfig struct {
	Enabled  bool   `json:"enabled"`
	Port     int    `json:"port"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

// DoHConfig DNS-over-HTTPS的配置
type DoHConfig struct {
	Enabled  bool   `json:"enabled"`
	Port     int    `json:"port"`
	Path     string `json:"path"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

// SNIProxyConfig SNI代理的配置
type SNIProxyConfig struct {
	Enabled          bool          `json:"enabled"`
	HTTPPort         int           `json:"http_port"`
	HTTPSPort        int           `json:"https_port"`
	ReadTimeout      time.Duration `json:"read_timeout"`
	WriteTimeout     time.Duration `json:"write_timeout"`
	IdleTimeout      time.Duration `json:"idle_timeout"`
	MaxConnections   int           `json:"max_connections"`
	DefaultTransport string        `json:"default_transport"`
	SOCKS5           SOCKS5Config  `json:"socks5"`
}

// SOCKS5Config SOCKS5代理配置
type SOCKS5Config struct {
	Address  string `json:"address"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// ACMEConfig ACME证书自动申请配置
type ACMEConfig struct {
	Enabled     bool     `json:"enabled"`
	Email       string   `json:"email"`
	Directory   string   `json:"directory"`
	CertDir     string   `json:"cert_dir"`
	Domains     []string `json:"domains"`
	RenewBefore int      `json:"renew_before"`
	UseStaging  bool     `json:"use_staging"`
}

// Default 返回默认配置
func Default() *Config {
	return &Config{
		ServerName: "DnsNode",
		Port:       53,
		Debug:      false,
		Cache: CacheConfig{
			Enabled:         true,
			MaxSize:         10000,
			DefaultTTL:      5 * time.Minute,
			CleanupInterval: 10 * time.Minute,
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
		SNIProxy: SNIProxyConfig{
			Enabled:          false,
			HTTPPort:         80,
			HTTPSPort:        443,
			ReadTimeout:      30 * time.Second,
			WriteTimeout:     30 * time.Second,
			IdleTimeout:      120 * time.Second,
			MaxConnections:   10000,
			DefaultTransport: "direct",
			SOCKS5:           SOCKS5Config{},
		},
		ACME: ACMEConfig{
			Enabled:     false,
			Directory:   "https://acme-v02.api.letsencrypt.org/directory",
			CertDir:     "./certs",
			RenewBefore: 30,
			UseStaging:  false,
		},
	}
}

// FromJSON 从JSON解析配置
func FromJSON(data []byte) (*Config, error) {
	cfg := Default()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// ToJSON 将配置序列化为JSON
func (c *Config) ToJSON() ([]byte, error) {
	return json.Marshal(c)
}
