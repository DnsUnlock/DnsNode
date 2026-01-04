package transport

import (
	"context"
	"net"
	"time"
)

// Dialer 定义传输层的抽象接口
type Dialer interface {
	// Dial 建立到目标地址的连接
	Dial(ctx context.Context, network, address string) (net.Conn, error)
	// Name 返回传输层名称
	Name() string
	// Close 关闭传输层资源
	Close() error
}

// DialerConfig 传输层配置
type DialerConfig struct {
	ConnectTimeout time.Duration
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	KeepAlive      time.Duration
}

// DefaultDialerConfig 默认传输层配置
func DefaultDialerConfig() DialerConfig {
	return DialerConfig{
		ConnectTimeout: 10 * time.Second,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		KeepAlive:      30 * time.Second,
	}
}

// ConnWrapper 连接包装器,用于统计流量
type ConnWrapper struct {
	net.Conn
	BytesRead    int64
	BytesWritten int64
	onRead       func(n int)
	onWrite      func(n int)
}

// NewConnWrapper 创建连接包装器
func NewConnWrapper(conn net.Conn, onRead, onWrite func(n int)) *ConnWrapper {
	return &ConnWrapper{
		Conn:    conn,
		onRead:  onRead,
		onWrite: onWrite,
	}
}

// Read 读取数据并统计
func (c *ConnWrapper) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.BytesRead += int64(n)
		if c.onRead != nil {
			c.onRead(n)
		}
	}
	return n, err
}

// Write 写入数据并统计
func (c *ConnWrapper) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.BytesWritten += int64(n)
		if c.onWrite != nil {
			c.onWrite(n)
		}
	}
	return n, err
}
