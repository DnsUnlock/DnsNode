// Package channel 提供基于 Channel 的消息分发机制
package channel

import (
	"context"
	"errors"
	"sync"

	"github.com/DnsUnlock/DnsNode/protocol/message"
)

// 常见错误
var (
	ErrChannelNotFound = errors.New("channel not found")
	ErrChannelClosed   = errors.New("channel closed")
	ErrChannelFull     = errors.New("channel buffer full")
)

// Handler 消息处理函数
type Handler func(envelope *message.Envelope) error

// Channel 消息通道
type Channel struct {
	name     string
	msgType  message.MessageType
	buffer   chan *message.Envelope
	handlers []Handler
	mu       sync.RWMutex
	closed   bool
}

// NewChannel 创建消息通道
func NewChannel(name string, msgType message.MessageType, bufferSize int) *Channel {
	if bufferSize <= 0 {
		bufferSize = 100
	}
	return &Channel{
		name:    name,
		msgType: msgType,
		buffer:  make(chan *message.Envelope, bufferSize),
	}
}

// Send 发送消息到通道
func (c *Channel) Send(envelope *message.Envelope) error {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return ErrChannelClosed
	}
	c.mu.RUnlock()

	select {
	case c.buffer <- envelope:
		return nil
	default:
		return ErrChannelFull
	}
}

// Receive 接收消息
func (c *Channel) Receive(ctx context.Context) (*message.Envelope, error) {
	select {
	case env := <-c.buffer:
		return env, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Chan 获取底层 channel
func (c *Channel) Chan() <-chan *message.Envelope {
	return c.buffer
}

// AddHandler 添加消息处理器
func (c *Channel) AddHandler(h Handler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.handlers = append(c.handlers, h)
}

// Process 处理消息
func (c *Channel) Process(envelope *message.Envelope) error {
	c.mu.RLock()
	handlers := make([]Handler, len(c.handlers))
	copy(handlers, c.handlers)
	c.mu.RUnlock()

	for _, h := range handlers {
		if err := h(envelope); err != nil {
			return err
		}
	}
	return nil
}

// Close 关闭通道
func (c *Channel) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.buffer)
	}
}

// Name 获取通道名称
func (c *Channel) Name() string {
	return c.name
}

// Type 获取消息类型
func (c *Channel) Type() message.MessageType {
	return c.msgType
}
