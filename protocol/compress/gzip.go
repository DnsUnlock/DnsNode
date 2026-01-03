// Package compress 提供数据压缩和解压缩功能
package compress

import (
	"bytes"
	"compress/gzip"
	"io"
	"sync"
)

// 压缩阈值：超过此大小的数据才进行压缩
const DefaultThreshold = 1024 // 1KB

// Compressor 压缩器接口
type Compressor interface {
	Compress(data []byte) ([]byte, error)
	Decompress(data []byte) ([]byte, error)
	Type() uint8
}

// GzipCompressor gzip 压缩器
type GzipCompressor struct {
	threshold int
	level     int
	pool      sync.Pool
}

// NewGzipCompressor 创建 gzip 压缩器
func NewGzipCompressor(threshold, level int) *GzipCompressor {
	if threshold <= 0 {
		threshold = DefaultThreshold
	}
	if level < gzip.BestSpeed || level > gzip.BestCompression {
		level = gzip.DefaultCompression
	}

	return &GzipCompressor{
		threshold: threshold,
		level:     level,
		pool: sync.Pool{
			New: func() interface{} {
				w, _ := gzip.NewWriterLevel(nil, level)
				return w
			},
		},
	}
}

// Compress 压缩数据
func (c *GzipCompressor) Compress(data []byte) ([]byte, error) {
	if len(data) < c.threshold {
		return data, nil
	}

	var buf bytes.Buffer
	w := c.pool.Get().(*gzip.Writer)
	defer c.pool.Put(w)

	w.Reset(&buf)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}

	// 压缩后更大则返回原数据
	if buf.Len() >= len(data) {
		return data, nil
	}

	return buf.Bytes(), nil
}

// Decompress 解压数据
func (c *GzipCompressor) Decompress(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return data, nil
	}

	// 检查 gzip magic number
	if data[0] != 0x1f || data[1] != 0x8b {
		return data, nil
	}

	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()

	return io.ReadAll(r)
}

// Type 返回压缩类型
func (c *GzipCompressor) Type() uint8 {
	return 1 // CompressionGzip
}

// ShouldCompress 判断是否需要压缩
func (c *GzipCompressor) ShouldCompress(size int) bool {
	return size >= c.threshold
}
