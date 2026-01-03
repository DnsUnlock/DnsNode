// Package protocol 提供 NODE 和 Dpanel 之间的通信协议
package protocol

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/DnsUnlock/DnsNode/protocol/channel"
	"github.com/DnsUnlock/DnsNode/protocol/message"
	"github.com/DnsUnlock/DnsNode/protocol/transport"
)

// 错误定义
var (
	ErrAuthFailed  = errors.New("authentication failed")
	ErrAuthTimeout = errors.New("authentication timeout")
)

// ClientConfig 客户端配置
type ClientConfig struct {
	WSEndpoint     string        // WebSocket 端点
	GRPCEndpoint   string        // gRPC 端点
	HTTPEndpoint   string        // HTTP 端点
	ClientID       string        // 客户端ID
	AuthToken      string        // 认证令牌
	NodeType       string        // 节点类型 (node/panel)
	Version        string        // 客户端版本
	ConnectTimeout time.Duration // 连接超时
	RequestTimeout time.Duration // 请求超时
}

// DefaultClientConfig 默认客户端配置
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		Version:        "1.0.0",
		NodeType:       "node",
		ConnectTimeout: 10 * time.Second,
		RequestTimeout: 30 * time.Second,
	}
}

// Client 协议客户端
type Client struct {
	config    *ClientConfig
	manager   *transport.Manager
	router    *channel.Router
	sessionID string
	started   bool
}

// NewClient 创建客户端
func NewClient(config *ClientConfig) *Client {
	if config == nil {
		config = DefaultClientConfig()
	}

	managerConfig := &transport.ManagerConfig{
		WSAddress:           config.WSEndpoint,
		GRPCAddress:         config.GRPCEndpoint,
		HTTPAddress:         config.HTTPEndpoint,
		MaxRetries:          3,
		RetryDelay:          time.Second,
		HealthCheckInterval: 10 * time.Second,
		FailoverThreshold:   3,
	}

	manager := transport.NewManager(managerConfig)
	router := channel.NewRouter(manager)

	return &Client{
		config:  config,
		manager: manager,
		router:  router,
	}
}

// Connect 连接到服务器
func (c *Client) Connect(ctx context.Context) error {
	if c.started {
		return nil
	}

	// 启动连接管理器
	if err := c.manager.Start(ctx); err != nil {
		return err
	}

	// 注册默认通道
	c.setupChannels()

	// 启动路由器
	if err := c.router.Start(ctx); err != nil {
		return err
	}

	// 执行认证 (5秒超时)
	authCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := c.authenticate(authCtx); err != nil {
		c.Close()
		return err
	}

	c.started = true
	return nil
}

// setupChannels 设置默认通道
func (c *Client) setupChannels() {
	c.router.RegisterTypeChannel(message.MsgTypeHeartbeat, 10)
	c.router.RegisterTypeChannel(message.MsgTypeData, 1000)
	c.router.RegisterTypeChannel(message.MsgTypeRequest, 100)
	c.router.RegisterTypeChannel(message.MsgTypeResponse, 100)
	c.router.RegisterTypeChannel(message.MsgTypeEvent, 100)
	c.router.RegisterTypeChannel(message.MsgTypeCommand, 50)
	c.router.RegisterTypeChannel(message.MsgTypeError, 50)

	defaultCh := channel.NewChannel("default", message.MsgTypeData, 100)
	c.router.SetDefaultChannel(defaultCh)
}

// authenticate 执行认证
func (c *Client) authenticate(ctx context.Context) error {
	req := &message.AuthRequest{
		ClientID:  c.config.ClientID,
		Token:     c.config.AuthToken,
		Version:   c.config.Version,
		NodeType:  c.config.NodeType,
		Timestamp: time.Now().Unix(),
	}

	payload, _ := json.Marshal(req)
	envelope := message.NewEnvelope(message.MsgTypeAuth, payload)
	envelope.From = c.config.ClientID

	resp, err := c.router.Request(ctx, envelope)
	if err != nil {
		return ErrAuthTimeout
	}

	var authResp message.AuthResponse
	if err := json.Unmarshal(resp.Payload, &authResp); err != nil {
		return err
	}

	if !authResp.Success {
		return ErrAuthFailed
	}

	c.sessionID = authResp.SessionID
	return nil
}

// Close 关闭连接
func (c *Client) Close() error {
	if !c.started {
		return nil
	}
	c.started = false
	c.router.Stop()
	return c.manager.Stop()
}

// Send 发送数据
func (c *Client) Send(ctx context.Context, msgType message.MessageType, data interface{}) error {
	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}

	envelope := message.NewEnvelope(msgType, payload)
	envelope.From = c.config.ClientID
	return c.router.Send(ctx, envelope)
}

// SendTo 发送给指定目标
func (c *Client) SendTo(ctx context.Context, to string, msgType message.MessageType, data interface{}) error {
	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}

	envelope := message.NewEnvelope(msgType, payload)
	envelope.From = c.config.ClientID
	envelope.To = to
	envelope.Target = message.TargetSingle
	return c.router.Send(ctx, envelope)
}

// Broadcast 广播消息
func (c *Client) Broadcast(ctx context.Context, msgType message.MessageType, data interface{}) error {
	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}

	envelope := message.NewEnvelope(msgType, payload)
	envelope.From = c.config.ClientID
	envelope.Target = message.TargetBroadcast
	return c.router.Send(ctx, envelope)
}

// Request 发送请求并等待响应
func (c *Client) Request(ctx context.Context, data interface{}) (*message.Envelope, error) {
	payload, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	envelope := message.NewEnvelope(message.MsgTypeRequest, payload)
	envelope.From = c.config.ClientID
	return c.router.Request(ctx, envelope)
}

// Subscribe 订阅消息类型
func (c *Client) Subscribe(msgType message.MessageType, handler channel.Handler) {
	ch := c.router.GetChannel(msgType)
	if ch != nil {
		ch.AddHandler(handler)
	}
}

// GetChannel 获取消息通道
func (c *Client) GetChannel(msgType message.MessageType) *channel.Channel {
	return c.router.GetChannel(msgType)
}

// ActiveTransport 获取当前活跃传输协议
func (c *Client) ActiveTransport() transport.TransportType {
	return c.manager.ActiveTransport()
}

// SessionID 获取会话ID
func (c *Client) SessionID() string {
	return c.sessionID
}
