package channel

import (
	"context"
	"log"
	"sync"

	"github.com/DnsUnlock/DnsNode/protocol/message"
	"github.com/DnsUnlock/DnsNode/protocol/transport"
)

// Router 消息路由器
type Router struct {
	manager   *transport.Manager
	channels  map[message.MessageType]*Channel
	namedChan map[string]*Channel
	defaultCh *Channel
	mu        sync.RWMutex
	done      chan struct{}
	started   bool
}

// NewRouter 创建消息路由器
func NewRouter(manager *transport.Manager) *Router {
	return &Router{
		manager:   manager,
		channels:  make(map[message.MessageType]*Channel),
		namedChan: make(map[string]*Channel),
		done:      make(chan struct{}),
	}
}

// RegisterChannel 注册消息通道
func (r *Router) RegisterChannel(ch *Channel) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.channels[ch.msgType] = ch
	r.namedChan[ch.name] = ch
}

// RegisterTypeChannel 按类型注册通道
func (r *Router) RegisterTypeChannel(msgType message.MessageType, bufSize int) *Channel {
	ch := NewChannel(msgType.String(), msgType, bufSize)
	r.RegisterChannel(ch)
	return ch
}

// SetDefaultChannel 设置默认通道
func (r *Router) SetDefaultChannel(ch *Channel) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.defaultCh = ch
}

// GetChannel 获取消息通道
func (r *Router) GetChannel(msgType message.MessageType) *Channel {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if ch, ok := r.channels[msgType]; ok {
		return ch
	}
	return r.defaultCh
}

// GetChannelByName 按名称获取通道
func (r *Router) GetChannelByName(name string) *Channel {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.namedChan[name]
}

// Start 启动路由器
func (r *Router) Start(ctx context.Context) error {
	r.mu.Lock()
	if r.started {
		r.mu.Unlock()
		return nil
	}
	r.started = true
	r.done = make(chan struct{})
	r.mu.Unlock()

	go r.dispatchLoop(ctx)
	go r.processLoop(ctx)

	return nil
}

// Stop 停止路由器
func (r *Router) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started {
		return
	}
	r.started = false
	close(r.done)

	// 关闭所有通道
	for _, ch := range r.channels {
		ch.Close()
	}
}

// dispatchLoop 消息分发循环
func (r *Router) dispatchLoop(ctx context.Context) {
	recvChan := r.manager.ReceiveChan()

	for {
		select {
		case envelope := <-recvChan:
			if envelope == nil {
				continue
			}
			r.dispatch(envelope)
		case <-r.done:
			return
		case <-ctx.Done():
			return
		}
	}
}

// dispatch 分发消息
func (r *Router) dispatch(envelope *message.Envelope) {
	ch := r.GetChannel(envelope.Type)
	if ch == nil {
		log.Printf("No channel for message type: %v", envelope.Type)
		return
	}

	if err := ch.Send(envelope); err != nil {
		log.Printf("Failed to send to channel: %v", err)
	}
}

// processLoop 处理循环
func (r *Router) processLoop(ctx context.Context) {
	r.mu.RLock()
	channels := make([]*Channel, 0, len(r.channels))
	for _, ch := range r.channels {
		channels = append(channels, ch)
	}
	r.mu.RUnlock()

	var wg sync.WaitGroup
	for _, ch := range channels {
		wg.Add(1)
		go func(c *Channel) {
			defer wg.Done()
			r.processChannel(ctx, c)
		}(ch)
	}

	wg.Wait()
}

// processChannel 处理单个通道
func (r *Router) processChannel(ctx context.Context, ch *Channel) {
	for {
		select {
		case envelope := <-ch.buffer:
			if envelope == nil {
				return
			}
			if err := ch.Process(envelope); err != nil {
				log.Printf("Handler error: %v", err)
			}
		case <-r.done:
			return
		case <-ctx.Done():
			return
		}
	}
}

// Send 通过路由器发送消息
func (r *Router) Send(ctx context.Context, envelope *message.Envelope) error {
	return r.manager.Send(ctx, envelope)
}

// Request 发送请求并等待响应
func (r *Router) Request(ctx context.Context, envelope *message.Envelope) (*message.Envelope, error) {
	// 设置为请求类型
	envelope.Type = message.MsgTypeRequest

	// 创建响应通道
	respChan := make(chan *message.Envelope, 1)

	// 注册临时处理器
	correlationID := envelope.ID
	r.mu.Lock()
	if respCh, ok := r.channels[message.MsgTypeResponse]; ok {
		respCh.AddHandler(func(env *message.Envelope) error {
			if env.CorrelationID == correlationID {
				select {
				case respChan <- env:
				default:
				}
			}
			return nil
		})
	}
	r.mu.Unlock()

	// 发送请求
	if err := r.manager.Send(ctx, envelope); err != nil {
		return nil, err
	}

	// 等待响应
	select {
	case resp := <-respChan:
		return resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
