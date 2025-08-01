package tls

import (
	"crypto/tls"
	"fmt"
	"os"

	"github.com/DnsUnlock/DnsNode/config"
)

// CertificateManager 管理TLS证书
type CertificateManager struct {
	config *config.Config
}

// NewCertificateManager 创建一个新的证书管理器
func NewCertificateManager(cfg *config.Config) *CertificateManager {
	return &CertificateManager{
		config: cfg,
	}
}

// EnsureCertificates 确保TLS证书存在
func (cm *CertificateManager) EnsureCertificates() error {
	// 检查证书是否存在
	if !cm.certificatesExist() {
		return fmt.Errorf("TLS certificates not found at specified paths")
	}
	return nil
}

// certificatesExist 检查证书文件是否存在
func (cm *CertificateManager) certificatesExist() bool {
	// 检查DoT证书
	if cm.config.DoT.Enabled {
		if _, err := os.Stat(cm.config.DoT.CertFile); os.IsNotExist(err) {
			return false
		}
		if _, err := os.Stat(cm.config.DoT.KeyFile); os.IsNotExist(err) {
			return false
		}
	}

	// 检查DoH证书
	if cm.config.DoH.Enabled {
		if _, err := os.Stat(cm.config.DoH.CertFile); os.IsNotExist(err) {
			return false
		}
		if _, err := os.Stat(cm.config.DoH.KeyFile); os.IsNotExist(err) {
			return false
		}
	}

	return true
}


// LoadCertificate 加载TLS证书
func (cm *CertificateManager) LoadCertificate(certFile, keyFile string) (tls.Certificate, error) {
	return tls.LoadX509KeyPair(certFile, keyFile)
}