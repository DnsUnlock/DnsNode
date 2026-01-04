package sniproxy

import (
	"errors"
	"io"
)

// SNI 解析相关错误
var (
	ErrNoSNI           = errors.New("no SNI extension found")
	ErrInvalidTLS      = errors.New("invalid TLS record")
	ErrTruncatedData   = errors.New("truncated TLS data")
	ErrUnsupportedType = errors.New("unsupported TLS record type")
)

// ParseSNI 从 TLS ClientHello 中解析 SNI
func ParseSNI(data []byte) (string, error) {
	if len(data) < 5 {
		return "", ErrTruncatedData
	}

	// TLS Record Header
	// byte 0: content type (0x16 = Handshake)
	// bytes 1-2: version
	// bytes 3-4: length
	if data[0] != 0x16 {
		return "", ErrInvalidTLS
	}

	recordLen := int(data[3])<<8 | int(data[4])
	if len(data) < 5+recordLen {
		return "", ErrTruncatedData
	}

	return parseClientHello(data[5 : 5+recordLen])
}

// parseClientHello 解析 ClientHello 消息
func parseClientHello(data []byte) (string, error) {
	if len(data) < 38 {
		return "", ErrTruncatedData
	}

	// Handshake Header
	// byte 0: handshake type (0x01 = ClientHello)
	// bytes 1-3: length
	if data[0] != 0x01 {
		return "", ErrUnsupportedType
	}

	pos := 4 // 跳过 handshake header

	// 跳过 client version (2 bytes)
	pos += 2

	// 跳过 random (32 bytes)
	pos += 32

	if pos >= len(data) {
		return "", ErrTruncatedData
	}

	// 跳过 session ID
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	if pos+2 > len(data) {
		return "", ErrTruncatedData
	}

	// 跳过 cipher suites
	cipherSuitesLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2 + cipherSuitesLen

	if pos >= len(data) {
		return "", ErrTruncatedData
	}

	// 跳过 compression methods
	compressionLen := int(data[pos])
	pos += 1 + compressionLen

	if pos+2 > len(data) {
		return "", ErrNoSNI
	}

	// Extensions
	extensionsLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2

	if pos+extensionsLen > len(data) {
		return "", ErrTruncatedData
	}

	return parseExtensions(data[pos : pos+extensionsLen])
}

// parseExtensions 解析扩展并提取 SNI
func parseExtensions(data []byte) (string, error) {
	pos := 0

	for pos+4 <= len(data) {
		extType := int(data[pos])<<8 | int(data[pos+1])
		extLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4

		if pos+extLen > len(data) {
			return "", ErrTruncatedData
		}

		// SNI extension type = 0
		if extType == 0 {
			return parseSNIExtension(data[pos : pos+extLen])
		}

		pos += extLen
	}

	return "", ErrNoSNI
}

// parseSNIExtension 解析 SNI 扩展
func parseSNIExtension(data []byte) (string, error) {
	if len(data) < 2 {
		return "", ErrTruncatedData
	}

	// SNI list length
	listLen := int(data[0])<<8 | int(data[1])
	if len(data) < 2+listLen {
		return "", ErrTruncatedData
	}

	pos := 2
	for pos+3 <= 2+listLen {
		nameType := data[pos]
		nameLen := int(data[pos+1])<<8 | int(data[pos+2])
		pos += 3

		if pos+nameLen > len(data) {
			return "", ErrTruncatedData
		}

		// Name type 0 = hostname
		if nameType == 0 {
			return string(data[pos : pos+nameLen]), nil
		}

		pos += nameLen
	}

	return "", ErrNoSNI
}

// PeekClientHello 从连接中预读 TLS ClientHello 并解析 SNI
// 返回 SNI 和完整的读取数据（需要重放给后端）
func PeekClientHello(reader io.Reader) (sni string, data []byte, err error) {
	// 读取 TLS record header (5 bytes)
	header := make([]byte, 5)
	if _, err := io.ReadFull(reader, header); err != nil {
		return "", nil, err
	}

	// 验证是否为 TLS handshake
	if header[0] != 0x16 {
		return "", header, ErrInvalidTLS
	}

	// 获取 record 长度
	recordLen := int(header[3])<<8 | int(header[4])
	if recordLen > 16384 { // TLS最大记录长度
		return "", header, ErrInvalidTLS
	}

	// 读取完整的 handshake 消息
	record := make([]byte, recordLen)
	if _, err := io.ReadFull(reader, record); err != nil {
		return "", append(header, record...), err
	}

	data = append(header, record...)
	sni, err = parseClientHello(record)
	return sni, data, err
}
