package remote

// RecordType DNS记录类型
type RecordType string

const (
	TypeA     RecordType = "A"
	TypeAAAA  RecordType = "AAAA"
	TypeCNAME RecordType = "CNAME"
	TypeMX    RecordType = "MX"
	TypeTXT   RecordType = "TXT"
	TypeNS    RecordType = "NS"
	TypeHTTPS RecordType = "HTTPS"
)

// DNSRecord DNS记录 (源IP + 域名 + 类型 -> 值)
// 键结构: sourceIP:domain:type (sourceIP为空时使用 "*")
type DNSRecord struct {
	SourceIP string     `json:"source_ip,omitempty"` // 源IP规则 (空表示默认)
	Domain   string     `json:"domain"`              // 域名
	Type     RecordType `json:"type"`                // 记录类型
	TTL      int        `json:"ttl"`                 // TTL (秒)
	Enabled  bool       `json:"enabled"`             // 是否启用

	// 记录值 (根据类型使用不同字段)
	Values []string     `json:"values,omitempty"` // A/AAAA/TXT/NS: 多个值
	CNAME  string       `json:"cname,omitempty"`  // CNAME: 单个目标
	MX     []MXValue    `json:"mx,omitempty"`     // MX: 多个邮件服务器
	HTTPS  []HTTPSValue `json:"https,omitempty"`  // HTTPS: 多个SVCB记录
}

// MXValue MX记录值
type MXValue struct {
	Host     string `json:"host"`
	Priority int    `json:"priority"`
}

// HTTPSValue HTTPS/SVCB记录值 (RFC 9460)
type HTTPSValue struct {
	Priority  int      `json:"priority"`
	Target    string   `json:"target"`
	ALPN      []string `json:"alpn,omitempty"`
	Port      int      `json:"port,omitempty"`
	IPv4Hint  []string `json:"ipv4hint,omitempty"`
	IPv6Hint  []string `json:"ipv6hint,omitempty"`
	ECH       string   `json:"ech,omitempty"`
	NoDefALPN bool     `json:"no_def_alpn,omitempty"`
}
