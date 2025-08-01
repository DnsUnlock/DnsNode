# DnsNode

A high-performance DNS node server written in Go that supports remote IP resolution with system DNS fallback.

## Features

- **Remote IP Resolution**: Fetch domain-to-IP mappings from a remote HTTP/HTTPS API
- **System DNS Fallback**: Automatically fall back to system DNS when domains are not found in remote source
- **Encrypted DNS Support**:
  - DNS-over-TLS (DoT) server on port 853
  - DNS-over-HTTPS (DoH) server with RFC 8484 compliance
  - Support for DoT/DoH upstream queries
- **High Performance**: 
  - Concurrent request handling with goroutines
  - Connection pooling for HTTP requests
  - BuntDB caching with TTL support (in-memory or persistent)
  - Rate limiting to prevent overload
- **TLS Certificate Management**:
  - Auto-generation of self-signed certificates
  - Support for custom certificates
- **Flexible Configuration**: YAML/JSON configuration file support
- **Protocol Support**: UDP, TCP, DoT, and DoH DNS queries
- **Record Types**: A, AAAA record support

## Installation

```bash
cd DnsNode
go build -o DnsNode
```

## Usage

### Basic Usage

Run with default configuration:
```bash
sudo ./DnsNode
```

### With Custom Configuration

```bash
sudo ./DnsNode -config=config.yaml
```

### Command Line Options

- `-config`: Path to configuration file (default: config.yaml)
- `-port`: DNS server port (default: 53)
- `-debug`: Enable debug mode

## Configuration

The server can be configured using a YAML file. See `config.yaml` for an example.

### Enabling Encrypted DNS

To enable DoT and/or DoH:

1. Obtain TLS certificates from a Certificate Authority (CA)
2. Place the certificate and key files at the specified paths
3. Set `dot.enabled: true` and/or `doh.enabled: true` in the configuration

### Using Encrypted Upstream DNS

To use DoT or DoH for upstream queries:

1. For DoT: Set `system_dns.use_dot: true` and use servers like `1.1.1.1:853`
2. For DoH: Set `system_dns.use_doh: true` and use URLs like `https://cloudflare-dns.com/dns-query`

Example configuration:

```yaml
# Server port
port: 53

# Enable debug mode
debug: false

# Maximum concurrent queries
max_concurrent_queries: 1000

# Remote API configuration
remote_api:
  enabled: true
  url: "https://example.com/api/dns-mappings"
  timeout: 5s
  refresh_interval: 5m
  headers:
    X-API-Key: "your-api-key"

# Cache configuration
cache:
  enabled: true
  max_size: 10000
  default_ttl: 5m
  cleanup_interval: 10m
  path: ":memory:"        # BuntDB path - use ":memory:" for in-memory cache or file path for persistent cache
  sync_policy: "everysecond"  # Sync policy: "always", "everysecond", or "never"

# System DNS configuration (fallback)
system_dns:
  enabled: true
  servers:
    - "8.8.8.8:53"
    - "8.8.4.4:53"
    - "1.1.1.1:53"
  timeout: 3s
  use_tcp: false
  use_dot: false  # Use DNS-over-TLS for upstream
  use_doh: false  # Use DNS-over-HTTPS for upstream

# DNS-over-TLS configuration
dot:
  enabled: false
  port: 853
  cert_file: "cert.pem"
  key_file: "key.pem"

# DNS-over-HTTPS configuration
doh:
  enabled: false
  port: 443
  path: "/dns-query"
  cert_file: "cert.pem"
  key_file: "key.pem"

# TLS certificate configuration
tls:
  auto_generate: true
  domains:
    - "localhost"
    - "dns.example.com"
```

## Remote API Format

The remote API should return JSON in the following format:

```json
{
  "mappings": [
    {
      "domain": "example.com",
      "ips": ["192.168.1.1", "192.168.1.2"],
      "ttl": 300
    },
    {
      "domain": "test.com",
      "ips": ["10.0.0.1"],
      "ttl": 600
    }
  ],
  "updated": "2024-01-01T00:00:00Z"
}
```

## Architecture

```
DnsNode/
├── main.go              # Entry point
├── config/
│   └── config.go        # Configuration management
├── dns/
│   ├── server.go        # DNS server core
│   ├── handler.go       # Request handler with rate limiting
│   ├── dot_server.go    # DNS-over-TLS server
│   └── doh_server.go    # DNS-over-HTTPS server
├── remote/
│   ├── resolver.go      # Remote IP resolution
│   ├── client.go        # HTTP client with connection pooling
│   └── cache.go         # BuntDB cache implementation
├── system/
│   ├── resolver.go      # System DNS fallback
│   ├── dot_client.go    # DNS-over-TLS client
│   └── doh_client.go    # DNS-over-HTTPS client
├── tls/
│   └── certificate.go   # TLS certificate management
└── examples/
    ├── buntdb-cache-example.go  # BuntDB cache usage examples
    ├── dns-cache-test.go        # DNS-specific cache testing
    ├── cache-monitor.go         # Cache monitoring and debugging
    ├── cache-configs.yaml       # Example cache configurations
    └── README.md                # Examples documentation
```

## Performance Optimizations

1. **Concurrent Processing**: Each DNS query is handled in its own goroutine
2. **Connection Pooling**: HTTP connections are reused for remote API calls
3. **Caching**: Frequently accessed domains are cached in memory
4. **Rate Limiting**: Prevents server overload with configurable concurrent query limits
5. **Efficient Memory Usage**: Minimal allocations during request processing

## Testing

Test the DNS server using various tools:

### Standard DNS (UDP/TCP)
```bash
# Test A record
dig @localhost example.com

# Test AAAA record
dig @localhost example.com AAAA

# Test with TCP
dig @localhost +tcp example.com
```

### DNS-over-TLS (DoT)
```bash
# Using kdig (from knot-dnsutils)
kdig -d @localhost +tls example.com

# Using stubby
stubby -C "upstream_recursive_servers:
  - address_data: 127.0.0.1
    tls_port: 853"
```

### DNS-over-HTTPS (DoH)
```bash
# Using curl
curl -H "accept: application/dns-message" \
     "https://localhost/dns-query?dns=$(dig +short example.com A | base64 -w0)"

# Using dog (DNS client with DoH support)
dog example.com --https @https://localhost/dns-query
```

## Requirements

- Go 1.19 or higher
- Root/Administrator privileges (to bind to port 53)

## Dependencies

- `github.com/miekg/dns`: DNS library
- `github.com/gophertool/tool`: BuntDB-based cache implementation
- `gopkg.in/yaml.v3`: YAML configuration support

## BuntDB Cache Examples

See the `examples/` directory for comprehensive BuntDB cache usage examples:

- **Basic Usage**: `buntdb-cache-example.go` - Basic cache operations, TTL, persistence
- **DNS Integration**: `dns-cache-test.go` - DNS-specific cache testing
- **Monitoring**: `cache-monitor.go` - Cache performance monitoring and debugging
- **Configurations**: `cache-configs.yaml` - Various cache configuration examples

Run examples:
```bash
cd examples
go run buntdb-cache-example.go
```

## License

This project is part of the DnsUnlock project.