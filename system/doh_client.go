package system

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

// DoHClient 表示DNS-over-HTTPS客户端
type DoHClient struct {
	url        string
	httpClient *http.Client
	useGET     bool
}

// NewDoHClient 创建一个新的DNS-over-HTTPS客户端
func NewDoHClient(url string, timeout time.Duration, useGET bool) *DoHClient {
	return &DoHClient{
		url:    url,
		useGET: useGET,
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 2,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

// Query 通过HTTPS执行DNS查询
func (c *DoHClient) Query(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	// 打包DNS消息
	data, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %w", err)
	}

	var req *http.Request
	if c.useGET {
		req, err = c.buildGETRequest(ctx, data)
	} else {
		req, err = c.buildPOSTRequest(ctx, data)
	}
	if err != nil {
		return nil, err
	}

	// 执行请求
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// 解包DNS响应
	dnsResp := new(dns.Msg)
	if err := dnsResp.Unpack(body); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS response: %w", err)
	}

	return dnsResp, nil
}

// buildGETRequest 构建带有base64url编码DNS消息的GET请求
func (c *DoHClient) buildGETRequest(ctx context.Context, data []byte) (*http.Request, error) {
	// 使base64url编码DNS消息
	encoded := base64.RawURLEncoding.EncodeToString(data)
	
	// 构建带查询参数的URL
	url := fmt.Sprintf("%s?dns=%s", c.url, encoded)
	
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create GET request: %w", err)
	}

	req.Header.Set("Accept", "application/dns-message")
	return req, nil
}

// buildPOSTRequest 构建在请求体中包含DNS消息的POST请求
func (c *DoHClient) buildPOSTRequest(ctx context.Context, data []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create POST request: %w", err)
	}

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	return req, nil
}