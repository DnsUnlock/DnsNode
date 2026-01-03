// Package transport 定义传输层接口
package transport

import (
	"context"
	"errors"
	"time"

	"github.com/DnsUnlock/DnsNode/protocol/message"
)

// 错误定义
var (
	ErrConnectionClosed = errors.New("connection closed")
	ErrNotConnected     = errors.New("not connected")
	ErrInvalidMessage   = errors.New("invalid message")
	ErrSendFailed       = errors.New("send failed")
)

// State 连接状态
type State uint8

const (
	StateDisconnected State = iota
	StateConnecting
	StateConnected
	StateClosed
)

// Config 传输配置
type Config struct {
	Address              string
	ConnectTimeout       time.Duration
	ReadTimeout          time.Duration
	WriteTimeout         time.Duration
	HeartbeatInterval    time.Duration
	BufferSize           int
	CompressionEnabled   bool
	CompressionThreshold int
}

// DefaultConfig 默认配置
func DefaultConfig() *Config {
	return &Config{
		ConnectTimeout:       10 * time.Second,
		ReadTimeout:          30 * time.Second,
		WriteTimeout:         10 * time.Second,
		HeartbeatInterval:    30 * time.Second,
		BufferSize:           4096,
		CompressionEnabled:   true,
		CompressionThreshold: 1024,
	}
}

// Transport 传输层接口
type Transport interface {
	Connect(ctx context.Context) error
	Close() error
	Send(ctx context.Context, envelope *message.Envelope) error
	Receive(ctx context.Context) (*message.Envelope, error)
	State() State
	IsHealthy() bool
}
