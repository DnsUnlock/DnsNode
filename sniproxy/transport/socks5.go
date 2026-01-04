package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// SOCKS5Dialer SOCKS5代理传输层
type SOCKS5Dialer struct {
	config   DialerConfig
	address  string
	username string
	password string
	dialer   *net.Dialer
}

// NewSOCKS5Dialer 创建SOCKS5代理传输层
func NewSOCKS5Dialer(config DialerConfig, address, username, password string) *SOCKS5Dialer {
	return &SOCKS5Dialer{
		config:   config,
		address:  address,
		username: username,
		password: password,
		dialer: &net.Dialer{
			Timeout:   config.ConnectTimeout,
			KeepAlive: config.KeepAlive,
		},
	}
}

// Dial 通过SOCKS5代理建立连接
func (d *SOCKS5Dialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	// 连接到SOCKS5服务器
	conn, err := d.dialer.DialContext(ctx, "tcp", d.address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SOCKS5 server: %w", err)
	}

	// 执行SOCKS5握手
	if err := d.handshake(conn, address); err != nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 handshake failed: %w", err)
	}

	return conn, nil
}

// handshake 执行SOCKS5握手
func (d *SOCKS5Dialer) handshake(conn net.Conn, targetAddr string) error {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return fmt.Errorf("invalid target address: %w", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid port: %w", err)
	}

	// 发送认证方法协商
	if err := d.sendAuthRequest(conn); err != nil {
		return err
	}

	// 接收认证方法响应
	method, err := d.recvAuthResponse(conn)
	if err != nil {
		return err
	}

	// 根据方法进行认证
	if method == 0x02 { // 用户名/密码认证
		if err := d.authenticate(conn); err != nil {
			return err
		}
	} else if method != 0x00 { // 不需要认证
		return fmt.Errorf("unsupported auth method: %d", method)
	}

	// 发送连接请求
	if err := d.sendConnectRequest(conn, host, port); err != nil {
		return err
	}

	// 接收连接响应
	return d.recvConnectResponse(conn)
}

// sendAuthRequest 发送认证方法协商请求
func (d *SOCKS5Dialer) sendAuthRequest(conn net.Conn) error {
	var methods []byte
	if d.username != "" {
		methods = []byte{0x00, 0x02} // 无认证 + 用户名/密码
	} else {
		methods = []byte{0x00} // 无认证
	}

	req := make([]byte, 2+len(methods))
	req[0] = 0x05 // SOCKS5版本
	req[1] = byte(len(methods))
	copy(req[2:], methods)

	_, err := conn.Write(req)
	return err
}

// recvAuthResponse 接收认证方法响应
func (d *SOCKS5Dialer) recvAuthResponse(conn net.Conn) (byte, error) {
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return 0, err
	}

	if resp[0] != 0x05 {
		return 0, errors.New("invalid SOCKS5 version")
	}

	if resp[1] == 0xFF {
		return 0, errors.New("no acceptable auth method")
	}

	return resp[1], nil
}

// authenticate 执行用户名/密码认证
func (d *SOCKS5Dialer) authenticate(conn net.Conn) error {
	req := make([]byte, 3+len(d.username)+len(d.password))
	req[0] = 0x01 // 认证版本
	req[1] = byte(len(d.username))
	copy(req[2:], d.username)
	req[2+len(d.username)] = byte(len(d.password))
	copy(req[3+len(d.username):], d.password)

	if _, err := conn.Write(req); err != nil {
		return err
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}

	if resp[1] != 0x00 {
		return errors.New("authentication failed")
	}

	return nil
}

// sendConnectRequest 发送连接请求
func (d *SOCKS5Dialer) sendConnectRequest(conn net.Conn, host string, port int) error {
	req := make([]byte, 4)
	req[0] = 0x05 // SOCKS5版本
	req[1] = 0x01 // CONNECT命令
	req[2] = 0x00 // 保留

	// 判断地址类型
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req[3] = 0x01 // IPv4
			req = append(req, ip4...)
		} else {
			req[3] = 0x04 // IPv6
			req = append(req, ip...)
		}
	} else {
		req[3] = 0x03 // 域名
		req = append(req, byte(len(host)))
		req = append(req, []byte(host)...)
	}

	// 添加端口
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	req = append(req, portBytes...)

	_, err := conn.Write(req)
	return err
}

// recvConnectResponse 接收连接响应
func (d *SOCKS5Dialer) recvConnectResponse(conn net.Conn) error {
	resp := make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}

	if resp[0] != 0x05 {
		return errors.New("invalid SOCKS5 version in response")
	}

	if resp[1] != 0x00 {
		return fmt.Errorf("SOCKS5 connect failed with code: %d", resp[1])
	}

	// 读取绑定地址 (我们不需要使用它)
	addrType := resp[3]
	switch addrType {
	case 0x01: // IPv4
		addr := make([]byte, 4+2)
		_, err := io.ReadFull(conn, addr)
		return err
	case 0x03: // 域名
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			return err
		}
		addr := make([]byte, int(lenByte[0])+2)
		_, err := io.ReadFull(conn, addr)
		return err
	case 0x04: // IPv6
		addr := make([]byte, 16+2)
		_, err := io.ReadFull(conn, addr)
		return err
	default:
		return fmt.Errorf("unknown address type: %d", addrType)
	}
}

// Name 返回传输层名称
func (d *SOCKS5Dialer) Name() string {
	return "socks5"
}

// Close 关闭传输层资源
func (d *SOCKS5Dialer) Close() error {
	return nil
}
