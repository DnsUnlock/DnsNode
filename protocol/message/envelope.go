// Package message 定义通信协议的消息结构体
package message

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// MessageType 消息类型
type MessageType uint8

const (
	MsgTypeUnknown   MessageType = 0
	MsgTypeHeartbeat MessageType = 1  // 心跳包
	MsgTypeAuth      MessageType = 2  // 认证消息
	MsgTypeData      MessageType = 10 // 普通数据
	MsgTypeRequest   MessageType = 11 // 请求
	MsgTypeResponse  MessageType = 12 // 响应
	MsgTypeEvent     MessageType = 20 // 事件通知
	MsgTypeCommand   MessageType = 21 // 命令
	MsgTypeBroadcast MessageType = 30 // 广播消息
	MsgTypeError     MessageType = 99 // 错误消息
)

// TargetType 目标类型
type TargetType uint8

const (
	TargetSingle    TargetType = 0 // 单个客户端
	TargetBroadcast TargetType = 1 // 广播所有客户端
	TargetGroup     TargetType = 2 // 指定分组
)

// Envelope 消息载体
type Envelope struct {
	ID            string            `json:"id"`             // 消息ID
	Type          MessageType       `json:"type"`           // 消息类型
	From          string            `json:"from,omitempty"` // 发送者ID
	To            string            `json:"to,omitempty"`   // 目标ID (客户端ID/分组名)
	Target        TargetType        `json:"target"`         // 目标类型
	CorrelationID string            `json:"cid,omitempty"`  // 关联ID (请求/响应配对)
	Timestamp     int64             `json:"ts"`             // 时间戳
	Payload       []byte            `json:"data"`           // 数据载荷
	Meta          map[string]string `json:"meta,omitempty"` // 扩展元数据
}

// NewEnvelope 创建新消息
func NewEnvelope(msgType MessageType, payload []byte) *Envelope {
	return &Envelope{
		ID:        GenerateID(),
		Type:      msgType,
		Target:    TargetSingle,
		Timestamp: time.Now().UnixMilli(),
		Payload:   payload,
	}
}

// NewRequest 创建请求消息
func NewRequest(payload []byte) *Envelope {
	return NewEnvelope(MsgTypeRequest, payload)
}

// NewResponse 创建响应消息
func NewResponse(correlationID string, payload []byte) *Envelope {
	e := NewEnvelope(MsgTypeResponse, payload)
	e.CorrelationID = correlationID
	return e
}

// NewBroadcast 创建广播消息
func NewBroadcast(payload []byte) *Envelope {
	e := NewEnvelope(MsgTypeBroadcast, payload)
	e.Target = TargetBroadcast
	return e
}

// NewGroupMessage 创建分组消息
func NewGroupMessage(group string, payload []byte) *Envelope {
	e := NewEnvelope(MsgTypeData, payload)
	e.Target = TargetGroup
	e.To = group
	return e
}

// ToClient 发送给指定客户端
func (e *Envelope) ToClient(clientID string) *Envelope {
	e.To = clientID
	e.Target = TargetSingle
	return e
}

// ToGroup 发送给指定分组
func (e *Envelope) ToGroup(group string) *Envelope {
	e.To = group
	e.Target = TargetGroup
	return e
}

// Broadcast 设置为广播
func (e *Envelope) Broadcast() *Envelope {
	e.Target = TargetBroadcast
	return e
}

// WithMeta 添加元数据
func (e *Envelope) WithMeta(key, value string) *Envelope {
	if e.Meta == nil {
		e.Meta = make(map[string]string)
	}
	e.Meta[key] = value
	return e
}

// GenerateID 生成唯一ID
func GenerateID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Heartbeat 心跳消息
type Heartbeat struct {
	Timestamp int64 `json:"timestamp"`
}

// AuthRequest 认证请求 (连接后5秒内必须发送)
type AuthRequest struct {
	ClientID  string `json:"client_id"`            // 客户端唯一标识
	Token     string `json:"token"`                // 认证令牌
	Version   string `json:"version"`              // 客户端版本
	NodeType  string `json:"node_type,omitempty"`  // 节点类型 (node/panel)
	Timestamp int64  `json:"timestamp"`            // 请求时间戳
	Signature string `json:"signature,omitempty"`  // 签名 (可选)
}

// AuthResponse 认证响应
type AuthResponse struct {
	Success   bool   `json:"success"`            // 是否成功
	SessionID string `json:"session_id"`         // 会话ID
	Message   string `json:"message,omitempty"`  // 提示消息
	ExpiresAt int64  `json:"expires_at"`         // 认证过期时间
}

// String 消息类型字符串
func (t MessageType) String() string {
	switch t {
	case MsgTypeHeartbeat:
		return "heartbeat"
	case MsgTypeAuth:
		return "auth"
	case MsgTypeData:
		return "data"
	case MsgTypeRequest:
		return "request"
	case MsgTypeResponse:
		return "response"
	case MsgTypeEvent:
		return "event"
	case MsgTypeCommand:
		return "command"
	case MsgTypeBroadcast:
		return "broadcast"
	case MsgTypeError:
		return "error"
	default:
		return "unknown"
	}
}
