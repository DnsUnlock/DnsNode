package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/DnsUnlock/DnsNode/config"
)

// Manager ACME证书管理器
type Manager struct {
	config       *config.Config
	challenges   sync.Map // token -> authorization
	certs        sync.Map // domain -> *tls.Certificate
	certDir      string
	accountKey   crypto.Signer
	httpHandler  http.Handler
	renewTicker  *time.Ticker
	stopChan     chan struct{}
}

// Challenge HTTP-01 挑战数据
type Challenge struct {
	Token        string
	KeyAuth      string
	Domain       string
	ExpiresAt    time.Time
}

// NewManager 创建ACME管理器
func NewManager(cfg *config.Config) (*Manager, error) {
	m := &Manager{
		config:   cfg,
		certDir:  cfg.ACME.CertDir,
		stopChan: make(chan struct{}),
	}

	// 确保证书目录存在
	if err := os.MkdirAll(m.certDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create cert directory: %w", err)
	}

	// 加载或创建账户密钥
	if err := m.loadOrCreateAccountKey(); err != nil {
		return nil, fmt.Errorf("failed to setup account key: %w", err)
	}

	// 创建HTTP挑战处理器
	m.httpHandler = http.HandlerFunc(m.handleHTTPChallenge)

	// 加载已有证书
	m.loadExistingCerts()

	return m, nil
}

// Start 启动证书管理器
func (m *Manager) Start() error {
	// 启动证书续期检查
	m.renewTicker = time.NewTicker(12 * time.Hour)
	go m.renewLoop()

	// 首次检查并申请缺失的证书
	go m.checkAndRequestCerts()

	return nil
}

// Stop 停止证书管理器
func (m *Manager) Stop() error {
	close(m.stopChan)
	if m.renewTicker != nil {
		m.renewTicker.Stop()
	}
	return nil
}

// GetHTTPHandler 获取HTTP-01挑战处理器
func (m *Manager) GetHTTPHandler() http.Handler {
	return m.httpHandler
}

// GetCertificate 获取域名证书（用于tls.Config.GetCertificate）
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if cert, ok := m.certs.Load(hello.ServerName); ok {
		return cert.(*tls.Certificate), nil
	}

	// 尝试通配符匹配
	domain := hello.ServerName
	for {
		idx := indexOf(domain, '.')
		if idx < 0 {
			break
		}
		wildcardDomain := "*" + domain[idx:]
		if cert, ok := m.certs.Load(wildcardDomain); ok {
			return cert.(*tls.Certificate), nil
		}
		domain = domain[idx+1:]
	}

	return nil, fmt.Errorf("no certificate for %s", hello.ServerName)
}

// handleHTTPChallenge 处理HTTP-01挑战
func (m *Manager) handleHTTPChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 检查路径
	const challengePath = "/.well-known/acme-challenge/"
	if len(r.URL.Path) <= len(challengePath) {
		http.NotFound(w, r)
		return
	}

	token := r.URL.Path[len(challengePath):]

	// 查找挑战
	if challenge, ok := m.challenges.Load(token); ok {
		ch := challenge.(*Challenge)
		if time.Now().Before(ch.ExpiresAt) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(ch.KeyAuth))
			return
		}
		// 已过期,删除
		m.challenges.Delete(token)
	}

	http.NotFound(w, r)
}

// RegisterChallenge 注册HTTP-01挑战
func (m *Manager) RegisterChallenge(token, keyAuth, domain string) {
	m.challenges.Store(token, &Challenge{
		Token:     token,
		KeyAuth:   keyAuth,
		Domain:    domain,
		ExpiresAt: time.Now().Add(10 * time.Minute),
	})
}

// loadOrCreateAccountKey 加载或创建账户密钥
func (m *Manager) loadOrCreateAccountKey() error {
	keyPath := filepath.Join(m.certDir, "account.key")

	// 尝试加载已有密钥
	if data, err := os.ReadFile(keyPath); err == nil {
		block, _ := pem.Decode(data)
		if block != nil && block.Type == "EC PRIVATE KEY" {
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err == nil {
				m.accountKey = key
				return nil
			}
		}
	}

	// 创建新密钥
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	// 保存密钥
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}

	pemBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	}

	if err := os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		return err
	}

	m.accountKey = key
	return nil
}

// loadExistingCerts 加载已有证书
func (m *Manager) loadExistingCerts() {
	entries, err := os.ReadDir(m.certDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if len(name) > 4 && name[len(name)-4:] == ".crt" {
			domain := name[:len(name)-4]
			certPath := filepath.Join(m.certDir, name)
			keyPath := filepath.Join(m.certDir, domain+".key")

			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				log.Printf("Failed to load certificate for %s: %v", domain, err)
				continue
			}

			m.certs.Store(domain, &cert)
			log.Printf("Loaded certificate for %s", domain)
		}
	}
}

// renewLoop 证书续期循环
func (m *Manager) renewLoop() {
	for {
		select {
		case <-m.renewTicker.C:
			m.checkAndRenewCerts()
		case <-m.stopChan:
			return
		}
	}
}

// checkAndRequestCerts 检查并申请缺失的证书
func (m *Manager) checkAndRequestCerts() {
	for _, domain := range m.config.ACME.Domains {
		if _, ok := m.certs.Load(domain); !ok {
			log.Printf("Requesting certificate for %s", domain)
			if err := m.RequestCertificate(context.Background(), domain); err != nil {
				log.Printf("Failed to request certificate for %s: %v", domain, err)
			}
		}
	}
}

// checkAndRenewCerts 检查并续期即将过期的证书
func (m *Manager) checkAndRenewCerts() {
	renewBefore := time.Duration(m.config.ACME.RenewBefore) * 24 * time.Hour

	m.certs.Range(func(key, value any) bool {
		domain := key.(string)
		cert := value.(*tls.Certificate)

		if cert.Leaf == nil {
			return true
		}

		// 检查是否需要续期
		if time.Until(cert.Leaf.NotAfter) < renewBefore {
			log.Printf("Renewing certificate for %s (expires: %v)", domain, cert.Leaf.NotAfter)
			if err := m.RequestCertificate(context.Background(), domain); err != nil {
				log.Printf("Failed to renew certificate for %s: %v", domain, err)
			}
		}

		return true
	})
}

// RequestCertificate 申请证书（简化实现，需要完整ACME客户端）
func (m *Manager) RequestCertificate(ctx context.Context, domain string) error {
	// TODO: 实现完整的ACME协议
	// 1. 创建账户（如果需要）
	// 2. 创建订单
	// 3. 获取授权
	// 4. 完成HTTP-01挑战
	// 5. 提交CSR
	// 6. 下载证书

	// 这里是占位实现，实际需要完整的ACME客户端
	return errors.New("ACME certificate request not fully implemented - use external tool like certbot")
}

// SaveCertificate 保存证书
func (m *Manager) SaveCertificate(domain string, certPEM, keyPEM []byte) error {
	certPath := filepath.Join(m.certDir, domain+".crt")
	keyPath := filepath.Join(m.certDir, domain+".key")

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return err
	}

	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return err
	}

	// 加载到内存
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}

	// 解析证书以获取过期时间
	if cert.Leaf == nil && len(cert.Certificate) > 0 {
		cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}

	m.certs.Store(domain, &cert)
	return nil
}

// GetTLSConfig 获取TLS配置
func (m *Manager) GetTLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: m.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	}
}

func indexOf(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
