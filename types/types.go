package types

import (
	"net"
	"time"
)

type Session struct {
	ID        string
	Key       *SecureBytes 
	IV        *SecureBytes 
	CreatedAt time.Time
	Conn      net.Conn
}

type SecureBytes struct {
	data []byte 
}

func NewBytes(data []byte) *SecureBytes {
	return &SecureBytes{data: data}
}

func (sb *SecureBytes) Get() []byte {
	return sb.data
}

type MessageHeader struct {
	Version    byte
	Type       byte
	PayloadLen uint32
}

const (
	PROTOCOL_VERSION  = 1
	MSG_HANDSHAKE     = 1
	MSG_COMMAND       = 2
	MSG_RESPONSE      = 3
	MSG_FILE_UPLOAD   = 4
	MSG_FILE_DOWNLOAD = 5
	MSG_ERROR         = 255
	HANDSHAKE_OK      = 0
	HANDSHAKE_FAILED  = 1
)
