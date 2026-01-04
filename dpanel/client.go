// Package dpanel 提供与 Dpanel 服务器的通信功能
package dpanel

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/DnsUnlock/DnsNode/config"
	"github.com/DnsUnlock/DnsNode/protocol"
	"github.com/DnsUnlock/DnsNode/protocol/channel"
	"github.com/DnsUnlock/DnsNode/protocol/message"
	"github.com/DnsUnlock/DnsNode/remote"
	"github.com/DnsUnlock/DnsNode/sniproxy"
)

// 业务消息类型（基于 protocol 的 Data 消息扩展）
const (
	ActionGetConfig     = "get_config"
	ActionGetDNSRecords = "get_dns_records"
	ActionGetSNIRules   = "get_sni_rules"
	ActionReportStats   = "report_stats"
	ActionConfigPush    = "config_push"
	ActionDNSPush       = "dns_push"
	ActionSNIPush       = "sni_push"
)

// DataMessage 业务数据消息
type DataMessage struct {
	Action string          `json:"action"`
	Data   json.RawMessage `json:"data,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// Client Dpanel 客户端
type Client struct {
	protoClient *protocol.Client
	config      *config.Config
	configMu    sync.RWMutex
	localConfig *config.LocalConfig

	// 回调函数
	onConfig func(*config.Config)
	onDNS    func([]*remote.DNSRecord)
	onSNI    func([]*sniproxy.Rule)

	stopChan chan struct{}
	started  bool
}

// NewClient 创建 Dpanel 客户端
func NewClient(localCfg *config.LocalConfig) *Client {
	// 构建连接端点
	wsEndpoint := buildWSEndpoint(localCfg.API)
	grpcEndpoint := buildGRPCEndpoint(localCfg.API)

	protoConfig := &protocol.ClientConfig{
		WSEndpoint:     wsEndpoint,
		GRPCEndpoint:   grpcEndpoint,
		HTTPEndpoint:   localCfg.API + "/api/node/connect",
		ClientID:       "", // 由服务器分配或后续设置
		AuthToken:      localCfg.APIKey,
		NodeType:       "node",
		Version:        "1.0.0",
		ConnectTimeout: 10 * time.Second,
		RequestTimeout: 30 * time.Second,
	}

	return &Client{
		protoClient: protocol.NewClient(protoConfig),
		localConfig: localCfg,
		stopChan:    make(chan struct{}),
	}
}

// buildWSEndpoint 构建 WebSocket 端点
func buildWSEndpoint(apiURL string) string {
	wsURL := apiURL
	if len(wsURL) > 5 && wsURL[:5] == "https" {
		wsURL = "wss" + wsURL[5:]
	} else if len(wsURL) > 4 && wsURL[:4] == "http" {
		wsURL = "ws" + wsURL[4:]
	}
	return wsURL + "/api/node/connect"
}

// buildGRPCEndpoint 构建 gRPC 端点
func buildGRPCEndpoint(apiURL string) string {
	// 从 API URL 提取 host:port，gRPC 使用不同的端口
	// 例如: https://dpanel.example.com -> dpanel.example.com:9090
	grpcURL := apiURL
	// 去除协议前缀
	if len(grpcURL) > 8 && grpcURL[:8] == "https://" {
		grpcURL = grpcURL[8:]
	} else if len(grpcURL) > 7 && grpcURL[:7] == "http://" {
		grpcURL = grpcURL[7:]
	}
	// 去除路径部分
	for i, c := range grpcURL {
		if c == '/' {
			grpcURL = grpcURL[:i]
			break
		}
	}
	// 去除端口号（如果有），添加 gRPC 端口
	for i, c := range grpcURL {
		if c == ':' {
			grpcURL = grpcURL[:i]
			break
		}
	}
	return grpcURL + ":9090"
}

// SetConfigCallback 设置配置更新回调
func (c *Client) SetConfigCallback(fn func(*config.Config)) {
	c.onConfig = fn
}

// SetDNSCallback 设置DNS记录更新回调
func (c *Client) SetDNSCallback(fn func([]*remote.DNSRecord)) {
	c.onDNS = fn
}

// SetSNICallback 设置SNI规则更新回调
func (c *Client) SetSNICallback(fn func([]*sniproxy.Rule)) {
	c.onSNI = fn
}

// GetConfig 获取当前配置
func (c *Client) GetConfig() *config.Config {
	c.configMu.RLock()
	defer c.configMu.RUnlock()
	return c.config
}

// Start 启动客户端
func (c *Client) Start(ctx context.Context) error {
	if c.started {
		return nil
	}

	// 注册消息处理器
	c.setupHandlers()

	// 连接到服务器
	if err := c.protoClient.Connect(ctx); err != nil {
		return err
	}

	c.started = true

	// 请求初始数据
	if err := c.requestInitialData(ctx); err != nil {
		log.Printf("Warning: failed to get initial data: %v", err)
	}

	// 启动心跳
	go c.heartbeatLoop()

	return nil
}

// Stop 停止客户端
func (c *Client) Stop() error {
	if !c.started {
		return nil
	}

	close(c.stopChan)
	c.started = false
	return c.protoClient.Close()
}

// setupHandlers 设置消息处理器
func (c *Client) setupHandlers() {
	// 处理数据消息
	c.protoClient.Subscribe(message.MsgTypeData, func(env *message.Envelope) error {
		return c.handleDataMessage(env)
	})

	// 处理事件消息（服务器推送）
	c.protoClient.Subscribe(message.MsgTypeEvent, func(env *message.Envelope) error {
		return c.handleEventMessage(env)
	})

	// 处理命令消息
	c.protoClient.Subscribe(message.MsgTypeCommand, func(env *message.Envelope) error {
		return c.handleCommandMessage(env)
	})
}

// handleDataMessage 处理数据消息
func (c *Client) handleDataMessage(env *message.Envelope) error {
	var dataMsg DataMessage
	if err := json.Unmarshal(env.Payload, &dataMsg); err != nil {
		return err
	}

	if dataMsg.Error != "" {
		log.Printf("Error from server: %s", dataMsg.Error)
		return nil
	}

	switch dataMsg.Action {
	case ActionConfigPush:
		return c.handleConfigUpdate(dataMsg.Data)
	case ActionDNSPush:
		return c.handleDNSUpdate(dataMsg.Data)
	case ActionSNIPush:
		return c.handleSNIUpdate(dataMsg.Data)
	}

	return nil
}

// handleEventMessage 处理事件消息
func (c *Client) handleEventMessage(env *message.Envelope) error {
	var dataMsg DataMessage
	if err := json.Unmarshal(env.Payload, &dataMsg); err != nil {
		return err
	}

	switch dataMsg.Action {
	case ActionConfigPush:
		return c.handleConfigUpdate(dataMsg.Data)
	case ActionDNSPush:
		return c.handleDNSUpdate(dataMsg.Data)
	case ActionSNIPush:
		return c.handleSNIUpdate(dataMsg.Data)
	}

	return nil
}

// handleCommandMessage 处理命令消息
func (c *Client) handleCommandMessage(env *message.Envelope) error {
	// 可以处理服务器发来的命令，如重载配置等
	if c.localConfig.Debug {
		log.Printf("Received command: %s", string(env.Payload))
	}
	return nil
}

// handleConfigUpdate 处理配置更新
func (c *Client) handleConfigUpdate(data json.RawMessage) error {
	var cfg config.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}

	c.configMu.Lock()
	c.config = &cfg
	c.configMu.Unlock()

	if c.onConfig != nil {
		c.onConfig(&cfg)
	}

	if c.localConfig.Debug {
		log.Println("Config updated from Dpanel")
	}

	return nil
}

// handleDNSUpdate 处理 DNS 记录更新
func (c *Client) handleDNSUpdate(data json.RawMessage) error {
	var records []*remote.DNSRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return err
	}

	if c.onDNS != nil {
		c.onDNS(records)
	}

	if c.localConfig.Debug {
		log.Printf("DNS records updated: %d records", len(records))
	}

	return nil
}

// handleSNIUpdate 处理 SNI 规则更新
func (c *Client) handleSNIUpdate(data json.RawMessage) error {
	var rules []*sniproxy.Rule
	if err := json.Unmarshal(data, &rules); err != nil {
		return err
	}

	if c.onSNI != nil {
		c.onSNI(rules)
	}

	if c.localConfig.Debug {
		log.Printf("SNI rules updated: %d rules", len(rules))
	}

	return nil
}

// requestInitialData 请求初始数据
func (c *Client) requestInitialData(ctx context.Context) error {
	// 获取配置
	if err := c.fetchConfig(ctx); err != nil {
		return err
	}

	// 获取 DNS 记录
	if err := c.fetchDNSRecords(ctx); err != nil {
		log.Printf("Warning: failed to fetch DNS records: %v", err)
	}

	// 获取 SNI 规则
	if err := c.fetchSNIRules(ctx); err != nil {
		log.Printf("Warning: failed to fetch SNI rules: %v", err)
	}

	return nil
}

// fetchConfig 获取配置
func (c *Client) fetchConfig(ctx context.Context) error {
	dataMsg := DataMessage{Action: ActionGetConfig}
	resp, err := c.request(ctx, dataMsg)
	if err != nil {
		return err
	}

	return c.handleConfigUpdate(resp.Data)
}

// fetchDNSRecords 获取 DNS 记录
func (c *Client) fetchDNSRecords(ctx context.Context) error {
	dataMsg := DataMessage{Action: ActionGetDNSRecords}
	resp, err := c.request(ctx, dataMsg)
	if err != nil {
		return err
	}

	return c.handleDNSUpdate(resp.Data)
}

// fetchSNIRules 获取 SNI 规则
func (c *Client) fetchSNIRules(ctx context.Context) error {
	dataMsg := DataMessage{Action: ActionGetSNIRules}
	resp, err := c.request(ctx, dataMsg)
	if err != nil {
		return err
	}

	return c.handleSNIUpdate(resp.Data)
}

// request 发送请求并等待响应
func (c *Client) request(ctx context.Context, dataMsg DataMessage) (*DataMessage, error) {
	resp, err := c.protoClient.Request(ctx, dataMsg)
	if err != nil {
		return nil, err
	}

	var respData DataMessage
	if err := json.Unmarshal(resp.Payload, &respData); err != nil {
		return nil, err
	}

	if respData.Error != "" {
		return nil, &ServerError{Message: respData.Error}
	}

	return &respData, nil
}

// ReportStats 上报统计信息
func (c *Client) ReportStats(stats interface{}) error {
	data, err := json.Marshal(stats)
	if err != nil {
		return err
	}

	dataMsg := DataMessage{
		Action: ActionReportStats,
		Data:   data,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return c.protoClient.Send(ctx, message.MsgTypeData, dataMsg)
}

// heartbeatLoop 心跳循环
func (c *Client) heartbeatLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			heartbeat := message.Heartbeat{
				Timestamp: time.Now().Unix(),
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			c.protoClient.Send(ctx, message.MsgTypeHeartbeat, heartbeat)
			cancel()

		case <-c.stopChan:
			return
		}
	}
}

// ActiveTransport 获取当前活跃的传输协议
func (c *Client) ActiveTransport() string {
	return c.protoClient.ActiveTransport().String()
}

// SessionID 获取会话ID
func (c *Client) SessionID() string {
	return c.protoClient.SessionID()
}

// ServerError 服务器错误
type ServerError struct {
	Message string
}

func (e *ServerError) Error() string {
	return e.Message
}

// 为 channel.Handler 提供类型别名，方便外部使用
type Handler = channel.Handler
