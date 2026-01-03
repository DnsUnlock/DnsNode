package transport

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DnsUnlock/DnsNode/protocol/compress"
	"github.com/DnsUnlock/DnsNode/protocol/message"
)

// HTTPTransport HTTP 降级传输实现
type HTTPTransport struct {
	config     *Config
	client     *http.Client
	state      atomic.Int32
	codec      *message.Codec
	compressor *compress.GzipCompressor
	mu         sync.RWMutex
	done       chan struct{}
	pollChan   chan *message.Envelope
	sessionID  string
}

// NewHTTPTransport 创建 HTTP 传输
func NewHTTPTransport(config *Config) *HTTPTransport {
	if config == nil {
		config = DefaultConfig()
	}

	ht := &HTTPTransport{
		config: config,
		client: &http.Client{
			Timeout: config.ReadTimeout,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		codec:      message.NewCodec(),
		compressor: compress.NewGzipCompressor(config.CompressionThreshold, -1),
		done:       make(chan struct{}),
		pollChan:   make(chan *message.Envelope, 100),
	}
	ht.state.Store(int32(StateDisconnected))
	return ht
}

// Connect 建立 HTTP 连接（验证服务器可达性）
func (t *HTTPTransport) Connect(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if State(t.state.Load()) == StateConnected {
		return nil
	}

	t.state.Store(int32(StateConnecting))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.config.Address+"/health", nil)
	if err != nil {
		t.state.Store(int32(StateDisconnected))
		return err
	}

	resp, err := t.client.Do(req)
	if err != nil {
		t.state.Store(int32(StateDisconnected))
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.state.Store(int32(StateDisconnected))
		return ErrConnectionClosed
	}

	t.sessionID = message.GenerateID()
	t.state.Store(int32(StateConnected))
	t.done = make(chan struct{})

	go t.pollLoop()

	return nil
}

// Close 关闭连接
func (t *HTTPTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if State(t.state.Load()) == StateClosed {
		return nil
	}

	t.state.Store(int32(StateClosed))
	close(t.done)

	return nil
}

// Send 发送消息 (POST)
func (t *HTTPTransport) Send(ctx context.Context, envelope *message.Envelope) error {
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.config.Address+"/send", bytes.NewReader(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Session-ID", t.sessionID)
	req.Header.Set("X-Message-ID", envelope.ID)

	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return ErrSendFailed
	}

	return nil
}

// Receive 接收消息
func (t *HTTPTransport) Receive(ctx context.Context) (*message.Envelope, error) {
	if State(t.state.Load()) != StateConnected {
		return nil, ErrNotConnected
	}

	select {
	case env := <-t.pollChan:
		return env, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.done:
		return nil, ErrConnectionClosed
	}
}

// pollLoop 长轮询循环
func (t *HTTPTransport) pollLoop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-t.done:
			return
		case <-ticker.C:
			t.poll()
		}
	}
}

// poll 执行单次轮询
func (t *HTTPTransport) poll() {
	ctx, cancel := context.WithTimeout(context.Background(), t.config.ReadTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.config.Address+"/poll", nil)
	if err != nil {
		return
	}

	req.Header.Set("X-Session-ID", t.sessionID)

	resp, err := t.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return
	}

	if resp.StatusCode != http.StatusOK {
		return
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	if resp.Header.Get("Content-Encoding") == "base64" {
		data, err = base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			return
		}
	}

	envelope, compressed, err := t.codec.Decode(data)
	if err != nil {
		return
	}

	// 传输层处理解压
	if compressed {
		if decompressed, err := t.compressor.Decompress(envelope.Payload); err == nil {
			envelope.Payload = decompressed
		}
	}

	select {
	case t.pollChan <- envelope:
	default:
	}
}

// State 获取当前状态
func (t *HTTPTransport) State() State {
	return State(t.state.Load())
}

// IsHealthy 检查连接健康状态
func (t *HTTPTransport) IsHealthy() bool {
	return State(t.state.Load()) == StateConnected
}
