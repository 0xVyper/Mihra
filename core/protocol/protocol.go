package protocol

import (
	"net"

	"github.com/0xvyper/mihra/types"
)

type ProtocolHandler interface {
	Connect(host string, port int) (net.Conn, error)
	Listen(host string, port int) (net.Listener, error)
	Accept(listener net.Listener) (net.Conn, error)
	SendMessage(conn net.Conn, msgType byte, payload []byte, session *types.Session) error
	ReceiveMessage(conn net.Conn, session *types.Session) (byte, []byte, error)
	PerformHandshake(conn net.Conn, session *types.Session) error
	Close() error
	IsStateless() bool
}
