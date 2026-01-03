package transport

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/DnsUnlock/DnsNode/protocol/compress"
	"github.com/DnsUnlock/DnsNode/protocol/message"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// GRPCTransport gRPC 传输实现
type GRPCTransport struct {
	config     *Config
	conn       *grpc.ClientConn
	state      atomic.Int32
	codec      *message.Codec
	compressor *compress.GzipCompressor
	mu         sync.RWMutex
	sendMu     sync.Mutex
	done       chan struct{}
	recvChan   chan *message.Envelope
}

// NewGRPCTransport 创建 gRPC 传输
func NewGRPCTransport(config *Config) *GRPCTransport {
	if config == nil {
		config = DefaultConfig()
	}

	gt := &GRPCTransport{
		config:     config,
		codec:      message.NewCodec(),
		compressor: compress.NewGzipCompressor(config.CompressionThreshold, -1),
		done:       make(chan struct{}),
		recvChan:   make(chan *message.Envelope, 100),
	}
	gt.state.Store(int32(StateDisconnected))
	return gt
}

// Connect 建立连接
func (t *GRPCTransport) Connect(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if State(t.state.Load()) == StateConnected {
		return nil
	}

	t.state.Store(int32(StateConnecting))

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                t.config.HeartbeatInterval,
			Timeout:             t.config.ReadTimeout,
			PermitWithoutStream: true,
		}),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(message.MaxFrameSize),
			grpc.MaxCallSendMsgSize(message.MaxFrameSize),
		),
	}

	conn, err := grpc.DialContext(ctx, t.config.Address, opts...)
	if err != nil {
		t.state.Store(int32(StateDisconnected))
		return err
	}

	t.conn = conn
	t.state.Store(int32(StateConnected))
	t.done = make(chan struct{})

	return nil
}

// Close 关闭连接
func (t *GRPCTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn == nil {
		return nil
	}

	t.state.Store(int32(StateClosed))
	close(t.done)

	return t.conn.Close()
}

// Send 发送消息
func (t *GRPCTransport) Send(ctx context.Context, envelope *message.Envelope) error {
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
	envelope.Payload = originalPayload
	if err != nil {
		return err
	}

	t.sendMu.Lock()
	defer t.sendMu.Unlock()

	t.mu.RLock()
	conn := t.conn
	t.mu.RUnlock()

	if conn == nil {
		return ErrNotConnected
	}

	return conn.Invoke(ctx, "/protocol.Transport/Send", data, new([]byte))
}

// Receive 接收消息
func (t *GRPCTransport) Receive(ctx context.Context) (*message.Envelope, error) {
	if State(t.state.Load()) != StateConnected {
		return nil, ErrNotConnected
	}

	select {
	case env := <-t.recvChan:
		return env, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.done:
		return nil, ErrConnectionClosed
	}
}

// State 获取状态
func (t *GRPCTransport) State() State {
	return State(t.state.Load())
}

// IsHealthy 健康检查
func (t *GRPCTransport) IsHealthy() bool {
	return State(t.state.Load()) == StateConnected
}
