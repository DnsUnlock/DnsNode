package protocol

import (
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/DnsUnlock/DnsNode/protocol/channel"
	"github.com/DnsUnlock/DnsNode/protocol/compress"
	"github.com/DnsUnlock/DnsNode/protocol/message"
	"github.com/gorilla/websocket"
)

// ServerConfig 服务端配置
type ServerConfig struct {
	Address            string
	Path               string
	HeartbeatInterval  time.Duration
	ReadBufferSize     int
	WriteBufferSize    int
	CompressionEnabled bool
}

// DefaultServerConfig 默认服务端配置
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Address:            ":8080",
		Path:               "/ws",
		HeartbeatInterval:  30 * time.Second,
		ReadBufferSize:     4096,
		WriteBufferSize:    4096,
		CompressionEnabled: true,
	}
}

// Server 协议服务端
type Server struct {
	config     *ServerConfig
	upgrader   websocket.Upgrader
	sessions   map[string]*Session
	groups     map[string]map[string]*Session // 分组 -> 会话集合
	sessionsMu sync.RWMutex
	codec      *message.Codec
	compressor *compress.GzipCompressor
	handlers   map[message.MessageType][]channel.Handler
	handlersMu sync.RWMutex
	done       chan struct{}
}

// NewServer 创建服务端
func NewServer(config *ServerConfig) *Server {
	if config == nil {
		config = DefaultServerConfig()
	}

	return &Server{
		config: config,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  config.ReadBufferSize,
			WriteBufferSize: config.WriteBufferSize,
			CheckOrigin:     func(r *http.Request) bool { return true },
		},
		sessions:   make(map[string]*Session),
		groups:     make(map[string]map[string]*Session),
		codec:      message.NewCodec(),
		compressor: compress.NewGzipCompressor(1024, -1),
		handlers:   make(map[message.MessageType][]channel.Handler),
		done:       make(chan struct{}),
	}
}

// Start 启动服务端
func (s *Server) Start() error {
	http.HandleFunc(s.config.Path, s.handleWebSocket)
	http.HandleFunc("/health", s.handleHealth)
	http.HandleFunc("/send", s.handleHTTPSend)
	http.HandleFunc("/poll", s.handleHTTPPoll)

	log.Printf("Server starting on %s", s.config.Address)
	return http.ListenAndServe(s.config.Address, nil)
}

// Stop 停止服务端
func (s *Server) Stop() {
	close(s.done)

	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	for _, session := range s.sessions {
		session.Close()
	}
}

// handleWebSocket 处理 WebSocket 连接
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Upgrade error: %v", err)
		return
	}

	session := &Session{
		ID:       message.GenerateID(),
		Conn:     conn,
		SendChan: make(chan *message.Envelope, 100),
		server:   s,
		done:     make(chan struct{}),
	}

	s.sessionsMu.Lock()
	s.sessions[session.ID] = session
	s.sessionsMu.Unlock()

	go session.readLoop()
	go session.writeLoop()
}

// handleHealth 健康检查
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// handleHTTPSend 处理 HTTP 发送
func (s *Server) handleHTTPSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" {
		http.Error(w, "Missing session ID", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

// handleHTTPPoll 处理 HTTP 轮询
func (s *Server) handleHTTPPoll(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" {
		http.Error(w, "Missing session ID", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// OnMessage 注册消息处理器
func (s *Server) OnMessage(msgType message.MessageType, h channel.Handler) {
	s.handlersMu.Lock()
	defer s.handlersMu.Unlock()
	s.handlers[msgType] = append(s.handlers[msgType], h)
}

// Broadcast 广播消息给所有客户端
func (s *Server) Broadcast(envelope *message.Envelope) {
	envelope.Target = message.TargetBroadcast
	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()

	for _, session := range s.sessions {
		session.Send(envelope)
	}
}

// BroadcastToGroup 广播消息给指定分组
func (s *Server) BroadcastToGroup(group string, envelope *message.Envelope) {
	envelope.Target = message.TargetGroup
	envelope.To = group
	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()

	if groupSessions, ok := s.groups[group]; ok {
		for _, session := range groupSessions {
			session.Send(envelope)
		}
	}
}

// SendTo 发送给指定会话
func (s *Server) SendTo(sessionID string, envelope *message.Envelope) error {
	envelope.Target = message.TargetSingle
	envelope.To = sessionID
	s.sessionsMu.RLock()
	session, ok := s.sessions[sessionID]
	s.sessionsMu.RUnlock()

	if !ok {
		return ErrSessionNotFound
	}

	return session.Send(envelope)
}

// SendToClient 发送给指定客户端ID
func (s *Server) SendToClient(clientID string, envelope *message.Envelope) error {
	envelope.Target = message.TargetSingle
	envelope.To = clientID
	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()

	for _, session := range s.sessions {
		if session.ClientID == clientID {
			return session.Send(envelope)
		}
	}
	return ErrSessionNotFound
}

// JoinGroup 将会话加入分组
func (s *Server) JoinGroup(sessionID, group string) {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()

	session, ok := s.sessions[sessionID]
	if !ok {
		return
	}

	if s.groups[group] == nil {
		s.groups[group] = make(map[string]*Session)
	}
	s.groups[group][sessionID] = session
}

// LeaveGroup 将会话移出分组
func (s *Server) LeaveGroup(sessionID, group string) {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()

	if groupSessions, ok := s.groups[group]; ok {
		delete(groupSessions, sessionID)
		if len(groupSessions) == 0 {
			delete(s.groups, group)
		}
	}
}

// GetSession 获取会话
func (s *Server) GetSession(sessionID string) (*Session, bool) {
	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()
	session, ok := s.sessions[sessionID]
	return session, ok
}

// removeSession 移除会话
func (s *Server) removeSession(sessionID string) {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	delete(s.sessions, sessionID)

	// 从所有分组中移除
	for group, groupSessions := range s.groups {
		delete(groupSessions, sessionID)
		if len(groupSessions) == 0 {
			delete(s.groups, group)
		}
	}
}

// dispatch 分发消息
func (s *Server) dispatch(session *Session, envelope *message.Envelope) {
	s.handlersMu.RLock()
	handlers := s.handlers[envelope.Type]
	s.handlersMu.RUnlock()

	for _, h := range handlers {
		if err := h(envelope); err != nil {
			log.Printf("Handler error: %v", err)
		}
	}
}

// route 路由消息到目标
func (s *Server) route(envelope *message.Envelope) {
	switch envelope.Target {
	case message.TargetBroadcast:
		s.Broadcast(envelope)
	case message.TargetGroup:
		s.BroadcastToGroup(envelope.To, envelope)
	case message.TargetSingle:
		s.SendTo(envelope.To, envelope)
	}
}

// 错误定义
var ErrSessionNotFound = channel.ErrChannelNotFound
