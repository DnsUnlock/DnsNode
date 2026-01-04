package transport

import (
	"context"
	"errors"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DnsUnlock/DnsNode/protocol/message"
)

// TransportType 传输类型
type TransportType uint8

const (
	TransportAuto TransportType = iota
	TransportWebSocket
	TransportGRPC
	TransportHTTP
)

// String 返回传输类型的字符串表示
func (t TransportType) String() string {
	switch t {
	case TransportWebSocket:
		return "websocket"
	case TransportGRPC:
		return "grpc"
	case TransportHTTP:
		return "http"
	default:
		return "auto"
	}
}

// ManagerConfig 连接管理器配置
type ManagerConfig struct {
	WSAddress           string        // WebSocket 地址
	GRPCAddress         string        // gRPC 地址
	HTTPAddress         string        // HTTP 地址
	MaxRetries          int           // 最大重试次数
	RetryDelay          time.Duration // 重试延迟
	HealthCheckInterval time.Duration // 健康检查间隔
	FailoverThreshold   int           // 触发故障转移的连续失败次数
}

// DefaultManagerConfig 默认管理器配置
func DefaultManagerConfig() *ManagerConfig {
	return &ManagerConfig{
		MaxRetries:          3,
		RetryDelay:          time.Second,
		HealthCheckInterval: 10 * time.Second,
		FailoverThreshold:   3,
	}
}

// Manager 连接管理器
type Manager struct {
	config          *ManagerConfig
	wsTransport     *WebSocketTransport
	grpcTransport   *GRPCTransport
	httpTransport   *HTTPTransport
	activeTransport atomic.Pointer[Transport]
	activeType      atomic.Int32

	mu             sync.RWMutex
	failCount      map[TransportType]int
	preferredOrder []TransportType

	recvChan chan *message.Envelope
	sendChan chan *sendRequest
	done     chan struct{}
	started  atomic.Bool
}

type sendRequest struct {
	envelope *message.Envelope
	result   chan error
}

// NewManager 创建连接管理器
func NewManager(config *ManagerConfig) *Manager {
	if config == nil {
		config = DefaultManagerConfig()
	}

	m := &Manager{
		config:    config,
		failCount: make(map[TransportType]int),
		preferredOrder: []TransportType{
			TransportWebSocket,
			TransportGRPC,
			TransportHTTP,
		},
		recvChan: make(chan *message.Envelope, 100),
		sendChan: make(chan *sendRequest, 100),
		done:     make(chan struct{}),
	}

	// 初始化传输层
	if config.WSAddress != "" {
		wsConfig := DefaultConfig()
		wsConfig.Address = config.WSAddress
		m.wsTransport = NewWebSocketTransport(wsConfig)
	}

	if config.GRPCAddress != "" {
		grpcConfig := DefaultConfig()
		grpcConfig.Address = config.GRPCAddress
		m.grpcTransport = NewGRPCTransport(grpcConfig)
	}

	if config.HTTPAddress != "" {
		httpConfig := DefaultConfig()
		httpConfig.Address = config.HTTPAddress
		m.httpTransport = NewHTTPTransport(httpConfig)
	}

	return m
}

// Start 启动连接管理器
func (m *Manager) Start(ctx context.Context) error {
	if m.started.Load() {
		return nil
	}

	// 尝试按优先顺序连接
	if err := m.connect(ctx); err != nil {
		return err
	}

	m.started.Store(true)
	m.done = make(chan struct{})

	go m.receiveLoop()
	go m.sendLoop()
	go m.healthCheckLoop()

	return nil
}

// Stop 停止连接管理器
func (m *Manager) Stop() error {
	if !m.started.Load() {
		return nil
	}

	m.started.Store(false)
	close(m.done)

	var errs []error
	if m.wsTransport != nil {
		if err := m.wsTransport.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if m.grpcTransport != nil {
		if err := m.grpcTransport.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if m.httpTransport != nil {
		if err := m.httpTransport.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// connect 连接到服务器
func (m *Manager) connect(ctx context.Context) error {
	for _, transportType := range m.preferredOrder {
		transport := m.getTransport(transportType)
		if transport == nil {
			continue
		}

		if err := (*transport).Connect(ctx); err == nil {
			m.activeTransport.Store(transport)
			m.activeType.Store(int32(transportType))
			log.Printf("Connected via %v", transportType)
			return nil
		}
	}

	return errors.New("all transports failed to connect")
}

// getTransport 获取指定类型的传输层
func (m *Manager) getTransport(t TransportType) *Transport {
	var transport Transport
	switch t {
	case TransportWebSocket:
		if m.wsTransport != nil {
			transport = m.wsTransport
		}
	case TransportGRPC:
		if m.grpcTransport != nil {
			transport = m.grpcTransport
		}
	case TransportHTTP:
		if m.httpTransport != nil {
			transport = m.httpTransport
		}
	}
	if transport == nil {
		return nil
	}
	return &transport
}

// Send 发送消息
func (m *Manager) Send(ctx context.Context, envelope *message.Envelope) error {
	req := &sendRequest{
		envelope: envelope,
		result:   make(chan error, 1),
	}

	select {
	case m.sendChan <- req:
		select {
		case err := <-req.result:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	case <-ctx.Done():
		return ctx.Err()
	case <-m.done:
		return ErrConnectionClosed
	}
}

// Receive 接收消息
func (m *Manager) Receive(ctx context.Context) (*message.Envelope, error) {
	select {
	case env := <-m.recvChan:
		return env, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-m.done:
		return nil, ErrConnectionClosed
	}
}

// ReceiveChan 获取接收 channel
func (m *Manager) ReceiveChan() <-chan *message.Envelope {
	return m.recvChan
}

// sendLoop 发送循环
func (m *Manager) sendLoop() {
	for {
		select {
		case req := <-m.sendChan:
			err := m.doSend(req.envelope)
			req.result <- err
		case <-m.done:
			return
		}
	}
}

// doSend 执行发送
func (m *Manager) doSend(envelope *message.Envelope) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 使用活跃传输
	active := m.activeTransport.Load()
	if active == nil {
		return ErrNotConnected
	}

	activeType := TransportType(m.activeType.Load())
	err := (*active).Send(ctx, envelope)
	if err != nil {
		m.recordFailure(activeType)
		// 尝试故障转移
		if m.shouldFailover(activeType) {
			m.failover(ctx)
		}
	} else {
		m.recordSuccess(activeType)
	}

	return err
}

// receiveLoop 接收循环
func (m *Manager) receiveLoop() {
	for {
		select {
		case <-m.done:
			return
		default:
			active := m.activeTransport.Load()
			if active == nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			activeType := TransportType(m.activeType.Load())
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			env, err := (*active).Receive(ctx)
			cancel()

			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					continue
				}
				m.recordFailure(activeType)
				if m.shouldFailover(activeType) {
					m.failover(context.Background())
				}
				continue
			}

			m.recordSuccess(activeType)
			select {
			case m.recvChan <- env:
			default:
				// 丢弃
			}
		}
	}
}

// healthCheckLoop 健康检查循环
func (m *Manager) healthCheckLoop() {
	ticker := time.NewTicker(m.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			active := m.activeTransport.Load()
			if active == nil || !(*active).IsHealthy() {
				m.failover(context.Background())
			}
		case <-m.done:
			return
		}
	}
}

// recordFailure 记录失败
func (m *Manager) recordFailure(t TransportType) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failCount[t]++
}

// recordSuccess 记录成功
func (m *Manager) recordSuccess(t TransportType) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failCount[t] = 0
}

// shouldFailover 是否应该故障转移
func (m *Manager) shouldFailover(t TransportType) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.failCount[t] >= m.config.FailoverThreshold
}

// failover 故障转移
func (m *Manager) failover(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()

	currentType := TransportType(m.activeType.Load())

	// 尝试其他传输
	for _, t := range m.preferredOrder {
		if t == currentType {
			continue
		}

		transport := m.getTransport(t)
		if transport == nil {
			continue
		}

		if err := (*transport).Connect(ctx); err == nil {
			m.activeTransport.Store(transport)
			m.activeType.Store(int32(t))
			m.failCount[t] = 0
			log.Printf("Failover to %v", t)
			return
		}
	}
}

// ActiveTransport 获取当前活跃传输类型
func (m *Manager) ActiveTransport() TransportType {
	return TransportType(m.activeType.Load())
}
