package transport

import (
	"context"
	"net"
)

// DirectDialer 直连传输层
type DirectDialer struct {
	config DialerConfig
	dialer *net.Dialer
}

// NewDirectDialer 创建直连传输层
func NewDirectDialer(config DialerConfig) *DirectDialer {
	return &DirectDialer{
		config: config,
		dialer: &net.Dialer{
			Timeout:   config.ConnectTimeout,
			KeepAlive: config.KeepAlive,
		},
	}
}

// Dial 建立直连
func (d *DirectDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dialer.DialContext(ctx, network, address)
}

// Name 返回传输层名称
func (d *DirectDialer) Name() string {
	return "direct"
}

// Close 关闭传输层资源
func (d *DirectDialer) Close() error {
	return nil
}
