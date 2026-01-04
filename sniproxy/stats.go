package sniproxy

import (
	"sync"
	"sync/atomic"
	"time"
)

// Stats 连接统计信息
type Stats struct {
	SourceIP      string    `json:"source_ip"`
	SNI           string    `json:"sni"`
	TargetAddress string    `json:"target_address"`
	Transport     string    `json:"transport"`
	BytesRead     int64     `json:"bytes_read"`
	BytesWritten  int64     `json:"bytes_written"`
	StartTime     time.Time `json:"start_time"`
	EndTime       time.Time `json:"end_time,omitempty"`
	Duration      int64     `json:"duration_ms"`
	Status        string    `json:"status"` // active, completed, error
	Error         string    `json:"error,omitempty"`
}

// StatsCollector 流量统计收集器
type StatsCollector struct {
	mu              sync.RWMutex
	activeConns     map[string]*Stats
	totalBytesRead  int64
	totalBytesWritten int64
	totalConnections  int64
	activeConnCount   int64
	reporter        StatsReporter
}

// StatsReporter 统计上报接口
type StatsReporter interface {
	// Report 上报统计信息
	Report(stats *Stats) error
	// ReportBatch 批量上报
	ReportBatch(stats []*Stats) error
}

// NewStatsCollector 创建统计收集器
func NewStatsCollector(reporter StatsReporter) *StatsCollector {
	return &StatsCollector{
		activeConns: make(map[string]*Stats),
		reporter:    reporter,
	}
}

// StartConnection 记录连接开始
func (sc *StatsCollector) StartConnection(connID, sourceIP, sni, target, transport string) *Stats {
	stats := &Stats{
		SourceIP:      sourceIP,
		SNI:           sni,
		TargetAddress: target,
		Transport:     transport,
		StartTime:     time.Now(),
		Status:        "active",
	}

	sc.mu.Lock()
	sc.activeConns[connID] = stats
	sc.mu.Unlock()

	atomic.AddInt64(&sc.totalConnections, 1)
	atomic.AddInt64(&sc.activeConnCount, 1)

	return stats
}

// UpdateBytes 更新字节统计
func (sc *StatsCollector) UpdateBytes(connID string, bytesRead, bytesWritten int64) {
	sc.mu.RLock()
	stats, ok := sc.activeConns[connID]
	sc.mu.RUnlock()

	if ok {
		atomic.AddInt64(&stats.BytesRead, bytesRead)
		atomic.AddInt64(&stats.BytesWritten, bytesWritten)
	}

	atomic.AddInt64(&sc.totalBytesRead, bytesRead)
	atomic.AddInt64(&sc.totalBytesWritten, bytesWritten)
}

// EndConnection 记录连接结束
func (sc *StatsCollector) EndConnection(connID string, err error) {
	sc.mu.Lock()
	stats, ok := sc.activeConns[connID]
	if ok {
		delete(sc.activeConns, connID)
	}
	sc.mu.Unlock()

	if !ok {
		return
	}

	atomic.AddInt64(&sc.activeConnCount, -1)

	stats.EndTime = time.Now()
	stats.Duration = stats.EndTime.Sub(stats.StartTime).Milliseconds()

	if err != nil {
		stats.Status = "error"
		stats.Error = err.Error()
	} else {
		stats.Status = "completed"
	}

	// 上报统计
	if sc.reporter != nil {
		go sc.reporter.Report(stats)
	}
}

// GetActiveConnections 获取活跃连接
func (sc *StatsCollector) GetActiveConnections() []*Stats {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	result := make([]*Stats, 0, len(sc.activeConns))
	for _, stats := range sc.activeConns {
		statsCopy := *stats
		statsCopy.Duration = time.Since(stats.StartTime).Milliseconds()
		result = append(result, &statsCopy)
	}
	return result
}

// GetSummary 获取统计摘要
func (sc *StatsCollector) GetSummary() map[string]int64 {
	return map[string]int64{
		"total_bytes_read":    atomic.LoadInt64(&sc.totalBytesRead),
		"total_bytes_written": atomic.LoadInt64(&sc.totalBytesWritten),
		"total_connections":   atomic.LoadInt64(&sc.totalConnections),
		"active_connections":  atomic.LoadInt64(&sc.activeConnCount),
	}
}

// NoopReporter 空实现的上报器
type NoopReporter struct{}

func (n *NoopReporter) Report(stats *Stats) error      { return nil }
func (n *NoopReporter) ReportBatch(stats []*Stats) error { return nil }

// HTTPReporter HTTP上报器（预留实现）
type HTTPReporter struct {
	endpoint string
	client   interface{} // *http.Client
	batch    []*Stats
	mu       sync.Mutex
}

// NewHTTPReporter 创建HTTP上报器
func NewHTTPReporter(endpoint string) *HTTPReporter {
	return &HTTPReporter{
		endpoint: endpoint,
		batch:    make([]*Stats, 0),
	}
}

// Report 单条上报
func (r *HTTPReporter) Report(stats *Stats) error {
	// TODO: 实现HTTP上报逻辑
	r.mu.Lock()
	r.batch = append(r.batch, stats)
	r.mu.Unlock()
	return nil
}

// ReportBatch 批量上报
func (r *HTTPReporter) ReportBatch(stats []*Stats) error {
	// TODO: 实现批量HTTP上报逻辑
	return nil
}

// Flush 刷新缓冲区
func (r *HTTPReporter) Flush() error {
	r.mu.Lock()
	batch := r.batch
	r.batch = make([]*Stats, 0)
	r.mu.Unlock()

	if len(batch) == 0 {
		return nil
	}

	return r.ReportBatch(batch)
}
