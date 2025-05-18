package protocol

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/0xvyper/mihra/core/crypto"
	"github.com/0xvyper/mihra/keys"
	"github.com/0xvyper/mihra/types"
)

type ICMPHandler struct {
	conn       *icmp.PacketConn
	serverAddr net.Addr
	sequence   int
	sessionKey []byte
}

func NewICMPHandler() *ICMPHandler {
	return &ICMPHandler{
		sequence: 1,
	}
}

func (h *ICMPHandler) Connect(host string, port int) (net.Conn, error) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %v", err)
	}
	serverAddr, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to resolve address: %v", err)
	}
	h.conn = conn
	h.serverAddr = serverAddr
	return nil, nil
}

func (h *ICMPHandler) Listen(host string, port int) (net.Listener, error) {
	conn, err := icmp.ListenPacket("ip4:icmp", host)
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %v", err)
	}
	h.conn = conn
	return nil, nil
}

func (h *ICMPHandler) Accept(listener net.Listener) (net.Conn, error) {
	return nil, fmt.Errorf("ICMP does not support Accept")
}

func (h *ICMPHandler) SendMessage(conn net.Conn, msgType byte, payload []byte, session *types.Session) error {
	encrypted, err := crypto.AESEncrypt(payload, session.Key.Get())
	if err != nil {
		return fmt.Errorf("encryption failed: %v", err)
	}
	data := append([]byte{msgType}, encrypted...)
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  h.sequence,
			Data: data,
		},
	}
	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %v", err)
	}
	if _, err := h.conn.WriteTo(msgBytes, h.serverAddr); err != nil {
		return fmt.Errorf("failed to send message: %v", err)
	}
	h.sequence++
	return nil
}

func (h *ICMPHandler) ReceiveMessage(conn net.Conn, session *types.Session) (byte, []byte, error) {
	reply := make([]byte, 1500)
	h.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	n, _, err := h.conn.ReadFrom(reply)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to receive message: %v", err)
	}
	h.conn.SetReadDeadline(time.Time{})
	parsedMsg, err := icmp.ParseMessage(1, reply[:n])
	if err != nil {
		return 0, nil, fmt.Errorf("failed to parse message: %v", err)
	}
	if parsedMsg.Type != ipv4.ICMPTypeEchoReply {
		return 0, nil, fmt.Errorf("unexpected ICMP type: %v", parsedMsg.Type)
	}
	echo, ok := parsedMsg.Body.(*icmp.Echo)
	if !ok {
		return 0, nil, fmt.Errorf("invalid ICMP echo reply")
	}
	if len(echo.Data) < 1 {
		return 0, nil, fmt.Errorf("empty ICMP payload")
	}
	msgType := echo.Data[0]
	decrypted, err := crypto.AESDecrypt(echo.Data[1:], session.Key.Get())
	if err != nil {
		return 0, nil, fmt.Errorf("decryption failed: %v", err)
	}
	return msgType, decrypted, nil
}

func (h *ICMPHandler) PerformHandshake(conn net.Conn, session *types.Session) error {
	publicKey, err := keys.GetPublicKeyPEM()
	if err != nil {
		return fmt.Errorf("failed to retrieve public key: %v", err)
	}
	sessionKey, err := crypto.GenerateRandomBytes(32)
	if err != nil {
		return fmt.Errorf("failed to generate session key: %v", err)
	}
	encryptedKey, err := crypto.RsaEnconding(publicKey, sessionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt session key: %v", err)
	}
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  h.sequence,
			Data: append([]byte(session.ID), encryptedKey...)},
	}
	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %v", err)
	}
	if _, err := h.conn.WriteTo(msgBytes, h.serverAddr); err != nil {
		return fmt.Errorf("failed to send message: %v", err)
	}
	reply := make([]byte, 1500)
	h.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, _, err := h.conn.ReadFrom(reply)
	if err != nil {
		return fmt.Errorf("failed to receive response: %v", err)
	}
	h.conn.SetReadDeadline(time.Time{})
	parsedMsg, err := icmp.ParseMessage(1, reply[:n])
	if err != nil {
		return fmt.Errorf("failed to parse response: %v", err)
	}
	if parsedMsg.Type != ipv4.ICMPTypeEchoReply {
		return fmt.Errorf("unexpected ICMP type: %v", parsedMsg.Type)
	}
	echo, ok := parsedMsg.Body.(*icmp.Echo)
	if !ok {
		return fmt.Errorf("invalid ICMP echo reply")
	}
	if len(echo.Data) < 1 || echo.Data[0] != types.HANDSHAKE_OK {
		return fmt.Errorf("handshake failed")
	}
	h.sessionKey = sessionKey
	session.Key = types.NewBytes(sessionKey)
	session.IV = types.NewBytes(make([]byte, 16))
	h.sequence++
	return nil
}

func (h *ICMPHandler) Close() error {
	if h.conn != nil {
		return h.conn.Close()
	}
	return nil
}

func (h *ICMPHandler) IsStateless() bool {
	return true
}
