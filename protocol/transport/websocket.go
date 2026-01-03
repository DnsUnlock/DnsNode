package transport

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DnsUnlock/DnsNode/protocol/compress"
	"github.com/DnsUnlock/DnsNode/protocol/message"
	"github.com/gorilla/websocket"
)

// WebSocketTransport WebSocket 传输实现
type WebSocketTransport struct {
	config     *Config
	conn       *websocket.Conn
	state      atomic.Int32
	codec      *message.Codec
	compressor *compress.GzipCompressor
	mu         sync.RWMutex
	writeMu    sync.Mutex
	done       chan struct{}
	dialer     *websocket.Dialer
}

// NewWebSocketTransport 创建 WebSocket 传输
func NewWebSocketTransport(config *Config) *WebSocketTransport {
	if config == nil {
		config = DefaultConfig()
	}

	wt := &WebSocketTransport{
		config:     config,
		codec:      message.NewCodec(),
		compressor: compress.NewGzipCompressor(config.CompressionThreshold, -1),
		done:       make(chan struct{}),
		dialer: &websocket.Dialer{
			HandshakeTimeout: config.ConnectTimeout,
			ReadBufferSize:   config.BufferSize,
			WriteBufferSize:  config.BufferSize,
		},
	}
	wt.state.Store(int32(StateDisconnected))
	return wt
}

// Connect 建立连接
func (t *WebSocketTransport) Connect(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if State(t.state.Load()) == StateConnected {
		return nil
	}

	t.state.Store(int32(StateConnecting))

	conn, _, err := t.dialer.DialContext(ctx, t.config.Address, http.Header{})
	if err != nil {
		t.state.Store(int32(StateDisconnected))
		return err
	}

	conn.SetReadLimit(message.MaxFrameSize)
	t.conn = conn
	t.state.Store(int32(StateConnected))
	t.done = make(chan struct{})

	return nil
}

// Close 关闭连接
func (t *WebSocketTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn == nil {
		return nil
	}

	t.state.Store(int32(StateClosed))
	close(t.done)

	t.conn.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		time.Now().Add(time.Second),
	)
	return t.conn.Close()
}

// Send 发送消息
func (t *WebSocketTransport) Send(ctx context.Context, envelope *message.Envelope) error {
	if State(t.state.Load()) != StateConnected {
		return ErrNotConnected
	}

	// 传输层处理压缩
	compressed := false
	originalPayload := envelope.Payload
	if t.config.CompressionEnabled && t.compressor.ShouldCompress(len(envelope.Payload)) {
		if compressedData, err := t.compressor.Compress(envelope.Payload); err == nil {
			envelope.Payload = compressedData
			compressed = true
		}
	}

	data, err := t.codec.Encode(envelope, compressed)
	// 恢复原始 payload（避免修改调用者的数据）
	envelope.Payload = originalPayload
	if err != nil {
		return err
	}

	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(t.config.WriteTimeout)
	}
	t.conn.SetWriteDeadline(deadline)

	return t.conn.WriteMessage(websocket.BinaryMessage, data)
}

// Receive 接收消息
func (t *WebSocketTransport) Receive(ctx context.Context) (*message.Envelope, error) {
	if State(t.state.Load()) != StateConnected {
		return nil, ErrNotConnected
	}

	t.mu.RLock()
	conn := t.conn
	t.mu.RUnlock()

	if conn == nil {
		return nil, ErrNotConnected
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(t.config.ReadTimeout)
	}
	conn.SetReadDeadline(deadline)

	msgType, data, err := conn.ReadMessage()
	if err != nil {
		return nil, err
	}

	if msgType != websocket.BinaryMessage {
		return nil, ErrInvalidMessage
	}

	envelope, compressed, err := t.codec.Decode(data)
	if err != nil {
		return nil, err
	}

	// 传输层处理解压
	if compressed {
		if decompressed, err := t.compressor.Decompress(envelope.Payload); err == nil {
			envelope.Payload = decompressed
		}
	}

	return envelope, nil
}

// State 获取状态
func (t *WebSocketTransport) State() State {
	return State(t.state.Load())
}

// IsHealthy 健康检查
func (t *WebSocketTransport) IsHealthy() bool {
	return State(t.state.Load()) == StateConnected
}
