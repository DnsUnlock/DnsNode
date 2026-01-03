package message

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

// 二进制协议格式:
// [Magic(2)] [Version(1)] [Flags(1)] [PayloadLen(4)] [Envelope(var)]

const (
	MagicBytes   = 0xD50E           // "DN" for DnsNode
	VersionV1    = 0x01
	MaxFrameSize = 10 * 1024 * 1024 // 10MB
)

// Flags 标志位 (传输层使用)
type Flags uint8

const (
	FlagCompressed Flags = 1 << 0 // 数据已压缩
)

// Codec 编解码器
type Codec struct{}

// NewCodec 创建编解码器
func NewCodec() *Codec {
	return &Codec{}
}

// Encode 编码消息
func (c *Codec) Encode(e *Envelope, compressed bool) ([]byte, error) {
	// 编码 envelope 主体
	body := c.encodeEnvelope(e)
	bodyLen := uint32(len(body))

	// 构建帧: Magic(2) + Version(1) + Flags(1) + BodyLen(4) + Body
	buf := bytes.NewBuffer(make([]byte, 0, 8+len(body)))

	binary.Write(buf, binary.BigEndian, uint16(MagicBytes))
	buf.WriteByte(VersionV1)

	var flags Flags
	if compressed {
		flags |= FlagCompressed
	}
	buf.WriteByte(byte(flags))

	binary.Write(buf, binary.BigEndian, bodyLen)
	buf.Write(body)

	return buf.Bytes(), nil
}

// Decode 解码消息，返回 envelope 和是否压缩标志
func (c *Codec) Decode(data []byte) (*Envelope, bool, error) {
	if len(data) < 8 {
		return nil, false, errors.New("frame too small")
	}

	r := bytes.NewReader(data)

	var magic uint16
	binary.Read(r, binary.BigEndian, &magic)
	if magic != MagicBytes {
		return nil, false, errors.New("invalid magic")
	}

	version, _ := r.ReadByte()
	if version != VersionV1 {
		return nil, false, errors.New("unsupported version")
	}

	flagsByte, _ := r.ReadByte()
	compressed := Flags(flagsByte)&FlagCompressed != 0

	var bodyLen uint32
	binary.Read(r, binary.BigEndian, &bodyLen)

	if bodyLen > MaxFrameSize {
		return nil, false, errors.New("payload too large")
	}

	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, false, err
	}

	e, err := c.decodeEnvelope(body)
	if err != nil {
		return nil, false, err
	}

	return e, compressed, nil
}

// encodeEnvelope 编码 envelope 主体
func (c *Codec) encodeEnvelope(e *Envelope) []byte {
	buf := bytes.NewBuffer(nil)

	// ID
	writeString(buf, e.ID)
	// Type (1字节)
	buf.WriteByte(byte(e.Type))
	// From
	writeString(buf, e.From)
	// To
	writeString(buf, e.To)
	// Target (1字节)
	buf.WriteByte(byte(e.Target))
	// CorrelationID
	writeString(buf, e.CorrelationID)
	// Timestamp (8字节)
	binary.Write(buf, binary.BigEndian, e.Timestamp)
	// Payload
	binary.Write(buf, binary.BigEndian, uint32(len(e.Payload)))
	buf.Write(e.Payload)
	// Meta
	buf.WriteByte(byte(len(e.Meta)))
	for k, v := range e.Meta {
		writeString(buf, k)
		writeString(buf, v)
	}

	return buf.Bytes()
}

// decodeEnvelope 解码 envelope 主体
func (c *Codec) decodeEnvelope(data []byte) (*Envelope, error) {
	r := bytes.NewReader(data)
	e := &Envelope{Meta: make(map[string]string)}

	e.ID = readString(r)
	typeByte, _ := r.ReadByte()
	e.Type = MessageType(typeByte)
	e.From = readString(r)
	e.To = readString(r)
	targetByte, _ := r.ReadByte()
	e.Target = TargetType(targetByte)
	e.CorrelationID = readString(r)
	binary.Read(r, binary.BigEndian, &e.Timestamp)

	var payloadLen uint32
	binary.Read(r, binary.BigEndian, &payloadLen)
	e.Payload = make([]byte, payloadLen)
	r.Read(e.Payload)

	metaCount, _ := r.ReadByte()
	for i := byte(0); i < metaCount; i++ {
		k := readString(r)
		v := readString(r)
		e.Meta[k] = v
	}

	return e, nil
}

func writeString(buf *bytes.Buffer, s string) {
	b := []byte(s)
	buf.WriteByte(byte(len(b)))
	buf.Write(b)
}

func readString(r *bytes.Reader) string {
	length, _ := r.ReadByte()
	b := make([]byte, length)
	r.Read(b)
	return string(b)
}
