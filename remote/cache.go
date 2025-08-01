package remote

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/gophertool/tool/db/cache/config"
	"github.com/gophertool/tool/db/cache/interface"
	_ "github.com/gophertool/tool/db/cache/buntdb" // 导入BuntDB驱动
	"github.com/miekg/dns"
)

// Cache 表示使用BuntDB的DNS查询缓存
type Cache struct {
	db              _interface.Cache
	defaultTTL      time.Duration
	cleanupInterval time.Duration
}

// cacheKey 为域名和查询类型生成缓存键
func cacheKey(domain string, qtype uint16) string {
	return fmt.Sprintf("dns:%s:%s", domain, dns.TypeToString[qtype])
}

// ipCacheData 表示缓存的IP数据
type ipCacheData struct {
	IPs []string `json:"ips"`
}

// NewCache 使用BuntDB创建一个新的缓存实例
func NewCache(maxSize int, defaultTTL, cleanupInterval time.Duration) *Cache {
	return NewCacheWithPath(":memory:", maxSize, defaultTTL, cleanupInterval)
}

// NewCacheWithPath 使用自定义路径创建一个新的缓存实例
func NewCacheWithPath(path string, maxSize int, defaultTTL, cleanupInterval time.Duration) *Cache {
	return NewCacheWithOptions(path, "", maxSize, defaultTTL, cleanupInterval)
}

// NewCacheWithOptions 使用完整选项创建一个新的缓存实例
func NewCacheWithOptions(path, syncPolicy string, maxSize int, defaultTTL, cleanupInterval time.Duration) *Cache {
	// 配置BuntDB
	// 注意：gophertool缓存不支持同步策略配置
	cfg := config.Cache{
		Driver: config.CacheDriverBuntdb,
		Path:   path,
	}
	
	// 创建缓存实例
	db, err := _interface.New(cfg)
	if err != nil {
		// 如果缓存创建失败，返回将绕过缓存的nil缓存
		return &Cache{
			db:              nil,
			defaultTTL:      defaultTTL,
			cleanupInterval: cleanupInterval,
		}
	}
	
	return &Cache{
		db:              db,
		defaultTTL:      defaultTTL,
		cleanupInterval: cleanupInterval,
	}
}

// Get 从缓存中检索IP地址
func (c *Cache) Get(domain string, qtype uint16) ([]net.IP, bool) {
	if c.db == nil {
		return nil, false
	}
	
	key := cacheKey(domain, qtype)
	
	// 从BuntDB获取
	data, err := c.db.Get(key)
	if err != nil {
		return nil, false
	}
	
	// 反序列化IP数据
	var cacheData ipCacheData
	if err := json.Unmarshal([]byte(data), &cacheData); err != nil {
		return nil, false
	}
	
	// 将字符串转换回 net.IP
	var ips []net.IP
	for _, ipStr := range cacheData.IPs {
		if ip := net.ParseIP(ipStr); ip != nil {
			ips = append(ips, ip)
		}
	}
	
	return ips, len(ips) > 0
}

// Set 使用默认TTL在缓存中存储IP地址
func (c *Cache) Set(domain string, qtype uint16, ips []net.IP) {
	c.SetWithTTL(domain, qtype, ips, c.defaultTTL)
}

// SetWithTTL 使用自定义TTL在缓存中存储IP地址
func (c *Cache) SetWithTTL(domain string, qtype uint16, ips []net.IP, ttl time.Duration) {
	if c.db == nil {
		return
	}
	
	key := cacheKey(domain, qtype)
	
	// 将IP地址转换为字符串以便序列化
	ipStrs := make([]string, len(ips))
	for i, ip := range ips {
		ipStrs[i] = ip.String()
	}
	
	// 序列化IP数据
	cacheData := ipCacheData{IPs: ipStrs}
	data, err := json.Marshal(cacheData)
	if err != nil {
		return
	}
	
	// 在BuntDB中存储并设置TTL
	c.db.Set(key, string(data), ttl)
}

// Delete 从缓存中删除一个条目
func (c *Cache) Delete(domain string, qtype uint16) {
	if c.db == nil {
		return
	}
	
	key := cacheKey(domain, qtype)
	c.db.Delete(key)
}

// Clear 清除所有缓存条目
func (c *Cache) Clear() {
	if c.db == nil {
		return
	}
	
	// BuntDB接口不暴露清除所有条目的方法
	// 我们需要遍历所有带有我们前缀的键并删除它们
	// 目前，这是一个空操作
}

// Stop 停止缓存清理
func (c *Cache) Stop() {
	if c.db != nil {
		c.db.Close()
	}
}