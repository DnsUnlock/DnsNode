package protocol

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DnsUnlock/DnsNode/protocol/channel"
	"github.com/DnsUnlock/DnsNode/protocol/message"
	"github.com/gorilla/websocket"
)

// AuthTimeout 认证超时时间
const AuthTimeout = 5 * time.Second

// Session 客户端会话
type Session struct {
	ID            string
	ClientID      string
	Conn          *websocket.Conn
	SendChan      chan *message.Envelope
	server        *Server
	done          chan struct{}
	mu            sync.Mutex
	authenticated atomic.Bool
	authTimer     *time.Timer
}

// readLoop 读取循环
func (sess *Session) readLoop() {
	defer func() {
		sess.Close()
		sess.server.removeSession(sess.ID)
	}()

	// 启动认证超时定时器
	sess.authTimer = time.AfterFunc(AuthTimeout, func() {
		if !sess.authenticated.Load() {
			sess.Close()
		}
	})

	for {
		select {
		case <-sess.done:
			return
		default:
			_, data, err := sess.Conn.ReadMessage()
			if err != nil {
				return
			}

			envelope, compressed, err := sess.server.codec.Decode(data)
			if err != nil {
				continue
			}

			// 传输层解压
			if compressed {
				if decompressed, err := sess.server.compressor.Decompress(envelope.Payload); err == nil {
					envelope.Payload = decompressed
				}
			}

			// 未认证时只处理认证消息
			if !sess.authenticated.Load() {
				if envelope.Type == message.MsgTypeAuth {
					sess.handleAuth(envelope)
				}
				continue
			}

			sess.server.dispatch(sess, envelope)
		}
	}
}

// writeLoop 写入循环
func (sess *Session) writeLoop() {
	ticker := time.NewTicker(sess.server.config.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case envelope := <-sess.SendChan:
			data, err := sess.server.codec.Encode(envelope, false)
			if err != nil {
				continue
			}
			sess.mu.Lock()
			err = sess.Conn.WriteMessage(websocket.BinaryMessage, data)
			sess.mu.Unlock()
			if err != nil {
				return
			}
		case <-ticker.C:
			if sess.authenticated.Load() {
				sess.sendHeartbeat()
			}
		case <-sess.done:
			return
		}
	}
}

// sendHeartbeat 发送心跳
func (sess *Session) sendHeartbeat() {
	heartbeat := &message.Heartbeat{Timestamp: time.Now().UnixNano()}
	payload, _ := json.Marshal(heartbeat)
	envelope := message.NewEnvelope(message.MsgTypeHeartbeat, payload)
	envelope.From = "server"
	envelope.To = sess.ClientID
	sess.Send(envelope)
}

// handleAuth 处理认证
func (sess *Session) handleAuth(envelope *message.Envelope) {
	var req message.AuthRequest
	if err := json.Unmarshal(envelope.Payload, &req); err != nil {
		sess.sendAuthResponse(envelope.ID, false, "", "invalid auth request")
		return
	}

	// TODO: 实际的认证逻辑，验证 token
	// 这里暂时只检查 ClientID 和 Token 是否非空
	if req.ClientID == "" || req.Token == "" {
		sess.sendAuthResponse(envelope.ID, false, "", "missing client_id or token")
		return
	}

	// 认证成功
	sess.ClientID = req.ClientID
	sess.authenticated.Store(true)
	sess.authTimer.Stop()

	sess.sendAuthResponse(envelope.ID, true, sess.ID, "")
}

// sendAuthResponse 发送认证响应
func (sess *Session) sendAuthResponse(correlationID string, success bool, sessionID, errMsg string) {
	resp := &message.AuthResponse{
		Success:   success,
		SessionID: sessionID,
		Message:   errMsg,
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	}

	payload, _ := json.Marshal(resp)
	envelope := message.NewEnvelope(message.MsgTypeResponse, payload)
	envelope.CorrelationID = correlationID
	envelope.From = "server"
	envelope.To = sess.ClientID
	envelope.Target = message.TargetSingle

	sess.Send(envelope)
}

// Send 发送消息
func (sess *Session) Send(envelope *message.Envelope) error {
	select {
	case sess.SendChan <- envelope:
		return nil
	default:
		return channel.ErrChannelFull
	}
}

// Close 关闭会话
func (sess *Session) Close() {
	sess.mu.Lock()
	defer sess.mu.Unlock()

	select {
	case <-sess.done:
		return
	default:
		close(sess.done)
		if sess.authTimer != nil {
			sess.authTimer.Stop()
		}
		sess.Conn.Close()
	}
}

// IsAuthenticated 是否已认证
func (sess *Session) IsAuthenticated() bool {
	return sess.authenticated.Load()
}
