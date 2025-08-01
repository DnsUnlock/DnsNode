package system

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// DoTClient 表示DNS-over-TLS客户端
type DoTClient struct {
	server    string
	tlsConfig *tls.Config
	timeout   time.Duration
}

// NewDoTClient 创建一个新的DNS-over-TLS客户端
func NewDoTClient(server string, timeout time.Duration) *DoTClient {
	return &DoTClient{
		server:  server,
		timeout: timeout,
		tlsConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: extractServerName(server),
		},
	}
}

// Query 通过TLS执行DNS查询
func (c *DoTClient) Query(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	// 创建带超时的拨号器
	dialer := &net.Dialer{
		Timeout: c.timeout,
	}

	// 拨号建立TLS连接
	conn, err := tls.DialWithDialer(dialer, "tcp", c.server, c.tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to dial DoT server: %w", err)
	}
	defer conn.Close()

	// 创建DNS连接
	dnsConn := &dns.Conn{Conn: conn}
	defer dnsConn.Close()

	// 从上下文设置截止时间
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}

	// 发送查询
	if err := dnsConn.WriteMsg(msg); err != nil {
		return nil, fmt.Errorf("failed to write DNS message: %w", err)
	}

	// 读取响应
	resp, err := dnsConn.ReadMsg()
	if err != nil {
		return nil, fmt.Errorf("failed to read DNS response: %w", err)
	}

	return resp, nil
}

// extractServerName 从服务器地址中提取主机名用于TLS SNI
func extractServerName(server string) string {
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		// 如果分割失败，假设整个字符串是主机名
		return server
	}
	return host
}