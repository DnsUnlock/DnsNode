package remote

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/tidwall/buntdb"
)

// sourceIPRule 源IP规则 (用于索引)
type sourceIPRule struct {
	Rule     string      // 规则字符串 (IP 或 CIDR)
	IsCIDR   bool        // 是否为CIDR
	MaskSize int         // CIDR掩码长度 (用于优先级排序，更精确的优先)
	IPNet    *net.IPNet  // 预解析的CIDR (仅IsCIDR=true时有效)
	IP       net.IP      // 预解析的IP (仅IsCIDR=false时有效)
}

// RecordStore 基于buntdb的DNS记录存储
// 键结构: sourceIP:domain:type (sourceIP为空时使用 "*")
type RecordStore struct {
	db *buntdb.DB

	// CIDR缓存: rule string -> *net.IPNet
	cidrCache sync.Map
	// 源IP规则索引: domain:type -> []sourceIPRule (用于快速查找需要检查的CIDR规则)
	ruleIndex sync.Map
}

// NewRecordStore 创建记录存储 (内存模式)
func NewRecordStore() (*RecordStore, error) {
	return NewRecordStoreWithPath(":memory:")
}

// NewRecordStoreWithPath 使用指定路径创建记录存储
func NewRecordStoreWithPath(path string) (*RecordStore, error) {
	db, err := buntdb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open buntdb: %w", err)
	}

	rs := &RecordStore{db: db}

	// 创建索引
	db.CreateIndex("domain", "*", buntdb.IndexJSON("domain"))
	db.CreateIndex("type", "*", buntdb.IndexJSON("type"))

	// 重建规则索引 (从持久化数据恢复)
	rs.rebuildRuleIndex()

	return rs, nil
}

// Close 关闭数据库
func (rs *RecordStore) Close() error {
	return rs.db.Close()
}

// makeKey 生成记录键: sourceIP:domain:type
func makeKey(sourceIP, domain string, rtype RecordType) string {
	domain = strings.ToLower(domain)
	if sourceIP == "" {
		sourceIP = "*"
	}
	return fmt.Sprintf("%s:%s:%s", sourceIP, domain, rtype)
}

// parseKey 解析键
func parseKey(key string) (sourceIP, domain string, rtype RecordType) {
	parts := strings.SplitN(key, ":", 3)
	if len(parts) == 3 {
		sourceIP = parts[0]
		if sourceIP == "*" {
			sourceIP = ""
		}
		domain = parts[1]
		rtype = RecordType(parts[2])
	}
	return
}

// Set 设置记录
func (rs *RecordStore) Set(record *DNSRecord) error {
	record.Domain = strings.ToLower(record.Domain)
	if record.TTL == 0 {
		record.TTL = 300
	}

	key := makeKey(record.SourceIP, record.Domain, record.Type)
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}

	err = rs.db.Update(func(tx *buntdb.Tx) error {
		_, _, err := tx.Set(key, string(data), nil)
		return err
	})
	if err != nil {
		return err
	}

	// 更新索引
	rs.updateRuleIndex(record.SourceIP, record.Domain, record.Type)
	return nil
}

// SetBatch 批量设置记录
func (rs *RecordStore) SetBatch(records []*DNSRecord) error {
	err := rs.db.Update(func(tx *buntdb.Tx) error {
		for _, record := range records {
			record.Domain = strings.ToLower(record.Domain)
			if record.TTL == 0 {
				record.TTL = 300
			}
			key := makeKey(record.SourceIP, record.Domain, record.Type)
			data, err := json.Marshal(record)
			if err != nil {
				return err
			}
			if _, _, err := tx.Set(key, string(data), nil); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	// 批量更新索引
	for _, record := range records {
		rs.updateRuleIndex(record.SourceIP, record.Domain, record.Type)
	}
	return nil
}

// Get 获取记录
func (rs *RecordStore) Get(sourceIP, domain string, rtype RecordType) (*DNSRecord, error) {
	key := makeKey(sourceIP, domain, rtype)
	var record DNSRecord

	err := rs.db.View(func(tx *buntdb.Tx) error {
		val, err := tx.Get(key)
		if err != nil {
			return err
		}
		return json.Unmarshal([]byte(val), &record)
	})

	if err == buntdb.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &record, nil
}

// Query 查询记录 (根据源IP匹配)
func (rs *RecordStore) Query(domain string, rtype RecordType, sourceIP net.IP) *DNSRecord {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	// 1. 尝试精确源IP匹配
	if sourceIP != nil {
		if record := rs.findBySourceIP(domain, rtype, sourceIP); record != nil {
			return record
		}
	}

	// 2. 尝试默认记录 (sourceIP = "*")
	if record := rs.getDefault(domain, rtype); record != nil {
		return record
	}

	// 3. 尝试通配符域名
	return rs.queryWildcard(domain, rtype, sourceIP)
}

// findBySourceIP 查找匹配源IP的记录 (使用索引优化)
func (rs *RecordStore) findBySourceIP(domain string, rtype RecordType, sourceIP net.IP) *DNSRecord {
	indexKey := fmt.Sprintf("%s:%s", domain, rtype)
	rulesRaw, ok := rs.ruleIndex.Load(indexKey)
	if !ok {
		return nil
	}

	rules := rulesRaw.([]sourceIPRule)

	// 规则按精确度排序: 精确IP > 大掩码CIDR > 小掩码CIDR
	// 遍历找第一个匹配的
	for _, rule := range rules {
		if rule.IsCIDR {
			if rule.IPNet.Contains(sourceIP) {
				return rs.getBySourceIP(rule.Rule, domain, rtype)
			}
		} else {
			if rule.IP.Equal(sourceIP) {
				return rs.getBySourceIP(rule.Rule, domain, rtype)
			}
		}
	}

	return nil
}

// getBySourceIP 根据源IP规则获取记录
func (rs *RecordStore) getBySourceIP(sourceIP, domain string, rtype RecordType) *DNSRecord {
	key := makeKey(sourceIP, domain, rtype)
	var record DNSRecord

	err := rs.db.View(func(tx *buntdb.Tx) error {
		val, err := tx.Get(key)
		if err != nil {
			return err
		}
		return json.Unmarshal([]byte(val), &record)
	})

	if err != nil || !record.Enabled {
		return nil
	}
	return &record
}

// getDefault 获取默认记录
func (rs *RecordStore) getDefault(domain string, rtype RecordType) *DNSRecord {
	key := makeKey("", domain, rtype) // sourceIP = "*"
	var record DNSRecord

	err := rs.db.View(func(tx *buntdb.Tx) error {
		val, err := tx.Get(key)
		if err != nil {
			return err
		}
		return json.Unmarshal([]byte(val), &record)
	})

	if err != nil || !record.Enabled {
		return nil
	}
	return &record
}

// queryWildcard 通配符域名查询
func (rs *RecordStore) queryWildcard(domain string, rtype RecordType, sourceIP net.IP) *DNSRecord {
	parts := strings.SplitN(domain, ".", 2)
	if len(parts) < 2 {
		return nil
	}

	wildcard := "*." + parts[1]

	// 先尝试源IP匹配
	if sourceIP != nil {
		if record := rs.findBySourceIP(wildcard, rtype, sourceIP); record != nil {
			return record
		}
	}

	// 再尝试默认记录
	if record := rs.getDefault(wildcard, rtype); record != nil {
		return record
	}

	// 递归查找上层
	if strings.Contains(parts[1], ".") {
		return rs.queryWildcard(parts[1], rtype, sourceIP)
	}

	return nil
}

// Delete 删除记录
func (rs *RecordStore) Delete(sourceIP, domain string, rtype RecordType) error {
	key := makeKey(sourceIP, domain, rtype)
	return rs.db.Update(func(tx *buntdb.Tx) error {
		_, err := tx.Delete(key)
		if err == buntdb.ErrNotFound {
			return nil
		}
		return err
	})
}

// DeleteByDomain 删除域名下所有记录
func (rs *RecordStore) DeleteByDomain(domain string) error {
	domain = strings.ToLower(domain)
	return rs.db.Update(func(tx *buntdb.Tx) error {
		var keys []string
		tx.AscendKeys("*:"+domain+":*", func(key, _ string) bool {
			keys = append(keys, key)
			return true
		})
		for _, key := range keys {
			tx.Delete(key)
		}
		return nil
	})
}

// Clear 清空所有记录
func (rs *RecordStore) Clear() error {
	return rs.db.Update(func(tx *buntdb.Tx) error {
		var keys []string
		tx.AscendKeys("*", func(key, _ string) bool {
			keys = append(keys, key)
			return true
		})
		for _, key := range keys {
			tx.Delete(key)
		}
		return nil
	})
}

// List 列出所有域名
func (rs *RecordStore) List() []string {
	domainSet := make(map[string]struct{})
	rs.db.View(func(tx *buntdb.Tx) error {
		tx.AscendKeys("*", func(key, _ string) bool {
			_, domain, _ := parseKey(key)
			if domain != "" {
				domainSet[domain] = struct{}{}
			}
			return true
		})
		return nil
	})

	domains := make([]string, 0, len(domainSet))
	for d := range domainSet {
		domains = append(domains, d)
	}
	return domains
}

// Count 记录数量
func (rs *RecordStore) Count() int {
	count := 0
	rs.db.View(func(tx *buntdb.Tx) error {
		tx.AscendKeys("*", func(_, _ string) bool {
			count++
			return true
		})
		return nil
	})
	return count
}

// updateRuleIndex 更新源IP规则索引
func (rs *RecordStore) updateRuleIndex(sourceIP, domain string, rtype RecordType) {
	if sourceIP == "" || sourceIP == "*" {
		return // 默认规则不需要索引
	}

	indexKey := fmt.Sprintf("%s:%s", strings.ToLower(domain), rtype)

	// 解析规则
	var rule sourceIPRule
	rule.Rule = sourceIP

	if strings.Contains(sourceIP, "/") {
		_, ipNet, err := net.ParseCIDR(sourceIP)
		if err != nil {
			return
		}
		rule.IsCIDR = true
		rule.IPNet = ipNet
		ones, _ := ipNet.Mask.Size()
		rule.MaskSize = ones
	} else {
		ip := net.ParseIP(sourceIP)
		if ip == nil {
			return
		}
		rule.IsCIDR = false
		rule.IP = ip
		rule.MaskSize = 128 // 精确IP优先级最高
	}

	// 更新索引
	for {
		rulesRaw, loaded := rs.ruleIndex.Load(indexKey)
		var rules []sourceIPRule
		if loaded {
			rules = rulesRaw.([]sourceIPRule)
			// 检查是否已存在
			exists := false
			for _, r := range rules {
				if r.Rule == sourceIP {
					exists = true
					break
				}
			}
			if exists {
				return
			}
		}

		// 添加新规则
		newRules := append(rules, rule)

		// 按精确度排序: 精确IP (MaskSize=128) > 大掩码 > 小掩码
		sort.Slice(newRules, func(i, j int) bool {
			return newRules[i].MaskSize > newRules[j].MaskSize
		})

		if loaded {
			if rs.ruleIndex.CompareAndSwap(indexKey, rulesRaw, newRules) {
				return
			}
		} else {
			if _, swapped := rs.ruleIndex.LoadOrStore(indexKey, newRules); !swapped {
				return
			}
		}
	}
}

// rebuildRuleIndex 重建源IP规则索引 (启动时调用)
func (rs *RecordStore) rebuildRuleIndex() {
	rs.ruleIndex = sync.Map{}

	rs.db.View(func(tx *buntdb.Tx) error {
		tx.AscendKeys("*", func(key, _ string) bool {
			srcIP, domain, rtype := parseKey(key)
			if srcIP != "" && srcIP != "*" {
				rs.updateRuleIndex(srcIP, domain, rtype)
			}
			return true
		})
		return nil
	})
}

// Export 导出所有记录
func (rs *RecordStore) Export() []*DNSRecord {
	var records []*DNSRecord
	rs.db.View(func(tx *buntdb.Tx) error {
		tx.AscendKeys("*", func(_, value string) bool {
			var record DNSRecord
			if json.Unmarshal([]byte(value), &record) == nil {
				records = append(records, &record)
			}
			return true
		})
		return nil
	})
	return records
}

// Import 导入记录
func (rs *RecordStore) Import(records []*DNSRecord) error {
	return rs.SetBatch(records)
}

// Shrink 压缩数据库
func (rs *RecordStore) Shrink() error {
	return rs.db.Shrink()
}
