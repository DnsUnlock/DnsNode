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
- `-debug`: Enable debug mode (default: false)

## Configuration

The server uses a YAML configuration file. See `config.yaml` for an example configuration.

### Configuration Options

#### Server Settings
- `server_name`: DNS server identifier
- `port`: DNS server port (default: 53)
- `debug`: Enable debug logging
- `max_concurrent_queries`: Maximum concurrent DNS queries

#### Remote API
- `enabled`: Enable/disable remote resolution
- `url`: Remote API endpoint for fetching mappings
- `timeout`: Request timeout
- `refresh_interval`: How often to refresh mappings
- `headers`: Custom headers for API authentication

#### Cache Settings
- `enabled`: Enable/disable caching
- `max_size`: Maximum cache entries
- `default_ttl`: Default time-to-live for cached entries
- `cleanup_interval`: Cache cleanup frequency
- `path`: BuntDB storage path (":memory:" for in-memory, file path for persistent)
- `sync_policy`: Disk sync policy for persistent cache

#### System DNS
- `enabled`: Enable/disable system DNS fallback
- `servers`: List of upstream DNS servers
- `timeout`: Query timeout
- `use_tcp`: Use TCP instead of UDP
- `use_dot`: Use DNS-over-TLS for upstream
- `use_doh`: Use DNS-over-HTTPS for upstream

#### DNS-over-TLS (DoT)
- `enabled`: Enable DoT server
- `port`: DoT server port (default: 853)
- `cert_file`: TLS certificate file path
- `key_file`: TLS key file path

#### DNS-over-HTTPS (DoH)
- `enabled`: Enable DoH server
- `port`: DoH server port (default: 443)
- `path`: HTTP path for DNS queries (default: /dns-query)
- `cert_file`: TLS certificate file path
- `key_file`: TLS key file path

## Remote API Format

The remote API should return JSON in the following format:

```json
{
  "domains": [
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

### Using dig
```bash
# Standard DNS query
dig @localhost example.com

# DNS-over-TLS query
dig @localhost +tls example.com

# Specify port
dig @localhost -p 53 example.com
```

### Using nslookup
```bash
nslookup example.com localhost
```

### Using curl (for DoH)
```bash
# GET method
curl -H "accept: application/dns-message" \
  "https://localhost:443/dns-query?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"

# POST method
curl -H "accept: application/dns-message" \
  -H "content-type: application/dns-message" \
  --data-binary @query.bin \
  https://localhost:443/dns-query
```

## Examples

The `examples/` directory contains various usage examples:
- **buntdb-cache-example.go**: Basic cache operations
- **dns-cache-test.go**: DNS-specific caching scenarios
- **cache-monitor.go**: Real-time cache monitoring
- **cache-configs.yaml**: Sample configuration files

Run examples:
```bash
cd examples
go run buntdb-cache-example.go
```

## License

This project is part of the DnsUnlock project.