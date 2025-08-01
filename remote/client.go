package remote

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// Client 处理向远程API发送的HTTP请求
type Client struct {
	httpClient *http.Client
	baseURL    string
	headers    map[string]string
}

// NewClient 创建一个新的远程API客户端
func NewClient(baseURL string, timeout time.Duration, headers map[string]string) *Client {
	return &Client{
		baseURL: baseURL,
		headers: headers,
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
			},
		},
	}
}

// DoRequest 在上下文中执行HTTP请求
func (c *Client) DoRequest(ctx context.Context, method, path string) (*http.Response, error) {
	url := c.baseURL + path
	
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// 添加请求头
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return resp, nil
}