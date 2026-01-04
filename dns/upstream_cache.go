package dns

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// UpstreamCache 上游DNS查询缓存（独立于记录表）
type UpstreamCache struct {
	mu       sync.RWMutex
	entries  map[string]*cacheEntry
	maxSize  int
	stopChan chan struct{}
}

// cacheEntry 缓存条目
type cacheEntry struct {
	IPs       []net.IP
	ExpiresAt time.Time
}

// NewUpstreamCache 创建上游缓存
func NewUpstreamCache(maxSize int, defaultTTL time.Duration) *UpstreamCache {
	c := &UpstreamCache{
		entries:  make(map[string]*cacheEntry),
		maxSize:  maxSize,
		stopChan: make(chan struct{}),
	}

	// 启动清理协程
	go c.cleanupLoop()

	return c
}

// cacheKey 生成缓存键
func cacheKey(domain string, qtype uint16) string {
	return fmt.Sprintf("%s:%d", domain, qtype)
}

// Get 获取缓存
func (c *UpstreamCache) Get(domain string, qtype uint16) ([]net.IP, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := cacheKey(domain, qtype)
	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}

	// 检查是否过期
	if time.Now().After(entry.ExpiresAt) {
		return nil, false
	}

	return entry.IPs, true
}

// Set 设置缓存
func (c *UpstreamCache) Set(domain string, qtype uint16, ips []net.IP, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 检查容量
	if len(c.entries) >= c.maxSize {
		c.evictOldest()
	}

	key := cacheKey(domain, qtype)
	c.entries[key] = &cacheEntry{
		IPs:       ips,
		ExpiresAt: time.Now().Add(ttl),
	}
}

// Delete 删除缓存
func (c *UpstreamCache) Delete(domain string, qtype uint16) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := cacheKey(domain, qtype)
	delete(c.entries, key)
}

// Clear 清空缓存
func (c *UpstreamCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]*cacheEntry)
}

// Stop 停止缓存
func (c *UpstreamCache) Stop() {
	close(c.stopChan)
}

// Count 返回缓存数量
func (c *UpstreamCache) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// cleanupLoop 清理过期条目
func (c *UpstreamCache) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.cleanup()
		case <-c.stopChan:
			return
		}
	}
}

// cleanup 清理过期条目
func (c *UpstreamCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.entries {
		if now.After(entry.ExpiresAt) {
			delete(c.entries, key)
		}
	}
}

// evictOldest 驱逐最旧的条目
func (c *UpstreamCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range c.entries {
		if oldestKey == "" || entry.ExpiresAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.ExpiresAt
		}
	}

	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}
