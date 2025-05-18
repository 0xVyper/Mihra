package protocol

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/gob"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"time"

	"github.com/0xvyper/mihra/core/crypto"
	"github.com/0xvyper/mihra/keys"
	"github.com/0xvyper/mihra/types"
)

type TCPHandler struct {
	conn      net.Conn
	listener  net.Listener
	useTLS    bool
	tlsConfig *tls.Config
}

func NewTCPHandler(useTLS bool) ProtocolHandler {
	var tlsConfig *tls.Config
	if useTLS {
		
		cert, err := generateSelfSignedCert()
		if err != nil {
			fmt.Printf("Failed to generate self-signed certificate, falling back to TCP: %v\n", err)
			useTLS = false
		} else {
			tlsConfig = &tls.Config{
				Certificates:       []tls.Certificate{cert},
				InsecureSkipVerify: true, 
				MinVersion:         tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				},
			}
		}
	}
	return &TCPHandler{
		useTLS:    useTLS,
		tlsConfig: tlsConfig,
	}
}

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Mihra Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost"},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func (h *TCPHandler) Connect(host string, port int) (net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	if h.useTLS {
		conn, err := tls.Dial("tcp", addr, h.tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("TLS connection failed: %v", err)
		}
		h.conn = conn
		return conn, nil
	}
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("TCP connection failed: %v", err)
	}
	h.conn = conn
	return conn, nil
}

func (h *TCPHandler) Listen(host string, port int) (net.Listener, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	var listener net.Listener
	var err error
	if h.useTLS {
		listener, err = tls.Listen("tcp", addr, h.tlsConfig)
	} else {
		listener, err = net.Listen("tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %v", addr, err)
	}
	h.listener = listener
	return listener, nil
}

func (h *TCPHandler) Accept(listener net.Listener) (net.Conn, error) {
	conn, err := listener.Accept()
	if err != nil {
		return nil, fmt.Errorf("failed to accept connection: %v", err)
	}
	return conn, nil
}

func (h *TCPHandler) SendMessage(conn net.Conn, msgType byte, payload []byte, session *types.Session) error {
	encryptedPayload, err := crypto.AESEncrypt(payload, session.Key.Get())
	if err != nil {
		return fmt.Errorf("encryption failed: %v", err)
	}
	header := types.MessageHeader{
		Version:    types.PROTOCOL_VERSION,
		Type:       msgType,
		PayloadLen: uint32(len(encryptedPayload)),
	}
	if err := binary.Write(conn, binary.BigEndian, header.Version); err != nil {
		return err
	}
	if err := binary.Write(conn, binary.BigEndian, header.Type); err != nil {
		return err
	}
	if err := binary.Write(conn, binary.BigEndian, header.PayloadLen); err != nil {
		return err
	}
	_, err = conn.Write(encryptedPayload)
	return err
}

func (h *TCPHandler) ReceiveMessage(conn net.Conn, session *types.Session) (byte, []byte, error) {
	var header types.MessageHeader
	if err := binary.Read(conn, binary.BigEndian, &header.Version); err != nil {
		return 0, nil, err
	}
	if err := binary.Read(conn, binary.BigEndian, &header.Type); err != nil {
		return 0, nil, err
	}
	if err := binary.Read(conn, binary.BigEndian, &header.PayloadLen); err != nil {
		return 0, nil, err
	}
	if header.Version != types.PROTOCOL_VERSION {
		return 0, nil, fmt.Errorf("unsupported protocol version: %d", header.Version)
	}
	encryptedPayload := make([]byte, header.PayloadLen)
	if _, err := io.ReadFull(conn, encryptedPayload); err != nil {
		return 0, nil, err
	}
	payload, err := crypto.AESDecrypt(encryptedPayload, session.Key.Get())
	if err != nil {
		return 0, nil, fmt.Errorf("decryption failed: %v", err)
	}
	return header.Type, payload, nil
}

func (h *TCPHandler) PerformHandshake(conn net.Conn, session *types.Session) error {
	encoder := gob.NewEncoder(conn)
	decoder := gob.NewDecoder(conn)
	publicKey, err := keys.GetPublicKeyPEM()
	if err != nil {
		return fmt.Errorf("failed to retrieve public key: %v", err)
	}
	keyEnc, err := crypto.RsaEnconding(publicKey, session.Key.Get())
	if err != nil {
		return fmt.Errorf("failed to encrypt key: %v", err)
	}
	ivEnc, err := crypto.RsaEnconding(publicKey, session.IV.Get())
	if err != nil {
		return fmt.Errorf("failed to encrypt IV: %v", err)
	}
	if err := encoder.Encode(session.ID); err != nil {
		return fmt.Errorf("failed to send session ID: %v", err)
	}
	if err := encoder.Encode(keyEnc); err != nil {
		return fmt.Errorf("failed to send encrypted key: %v", err)
	}
	if err := encoder.Encode(ivEnc); err != nil {
		return fmt.Errorf("failed to send encrypted IV: %v", err)
	}
	var response []byte
	if err := decoder.Decode(&response); err != nil {
		return fmt.Errorf("failed to receive handshake response: %v", err)
	}
	if len(response) < 1 || response[0] != types.HANDSHAKE_OK {
		return fmt.Errorf("invalid handshake response")
	}
	return nil
}

func (h *TCPHandler) Close() error {
	var err error
	if h.conn != nil {
		err = h.conn.Close()
		h.conn = nil
	}
	if h.listener != nil {
		if err == nil {
			err = h.listener.Close()
		}
		h.listener = nil
	}
	return err
}

func (h *TCPHandler) IsStateless() bool {
	return false
}
