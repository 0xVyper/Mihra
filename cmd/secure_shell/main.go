package main

import (
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/simplified_c2/core/crypto"
	"github.com/simplified_c2/shell"
)

const (
	// Protocol version
	PROTOCOL_VERSION = 1

	// Message types
	MSG_HANDSHAKE     = 1
	MSG_COMMAND       = 2
	MSG_RESPONSE      = 3
	MSG_FILE_UPLOAD   = 4
	MSG_FILE_DOWNLOAD = 5
	MSG_ERROR         = 255

	// Handshake status
	HANDSHAKE_OK     = 0
	HANDSHAKE_FAILED = 1
)

// Message header structure
type MessageHeader struct {
	Version    byte
	Type       byte
	PayloadLen uint32
}

// Secure shell client
type SecureShell struct {
	conn        net.Conn
	passphrase  []byte
	interactive bool
	shell       *shell.Shell
}

// Create a new secure shell
func NewSecureShell(passphrase string, interactive bool) *SecureShell {
	return &SecureShell{
		passphrase:  []byte(passphrase),
		interactive: interactive,
		shell:       shell.NewShell(),
	}
}

// Connect to a server
func (s *SecureShell) Connect(host string, port int, useTLS bool) error {
	var err error
	addr := fmt.Sprintf("%s:%d", host, port)

	if useTLS {
		// Configure TLS with secure settings
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true, // Note: In production, this should be false and proper certificates should be used
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

	// Perform handshake
	if err := s.performHandshake(); err != nil {
		s.conn.Close()
		return fmt.Errorf("handshake failed: %v", err)
	}

	fmt.Println("Secure connection established")
	return nil
}

// Perform the handshake protocol
func (s *SecureShell) performHandshake() error {
	// Generate a random challenge
	challenge, err := crypto.GenerateRandomBytes(32)
	if err != nil {
		return err
	}

	// Send handshake message with challenge
	if err := s.sendMessage(MSG_HANDSHAKE, challenge); err != nil {
		return err
	}

	// Receive handshake response
	msgType, payload, err := s.receiveMessage()
	if err != nil {
		return err
	}

	if msgType != MSG_HANDSHAKE {
		return fmt.Errorf("unexpected message type: %d", msgType)
	}

	if len(payload) < 1 {
		return fmt.Errorf("invalid handshake response")
	}

	status := payload[0]
	if status != HANDSHAKE_OK {
		return fmt.Errorf("handshake rejected by server")
	}

	// Verify the response (in a real implementation, this would involve cryptographic verification)
	if len(payload) < 33 {
		return fmt.Errorf("invalid handshake response length")
	}

	// The server should have encrypted our challenge with the shared passphrase
	// and sent it back. Here we would decrypt and verify it.
	// This is a simplified implementation.

	return nil
}

// Send a message
func (s *SecureShell) sendMessage(msgType byte, payload []byte) error {
	// Encrypt the payload
	encryptedPayload, err := crypto.AESEncrypt(payload, s.passphrase)
	if err != nil {
		return err
	}

	// Create header
	header := MessageHeader{
		Version:    PROTOCOL_VERSION,
		Type:       msgType,
		PayloadLen: uint32(len(encryptedPayload)),
	}

	// Write header
	if err := binary.Write(s.conn, binary.BigEndian, header.Version); err != nil {
		return err
	}
	if err := binary.Write(s.conn, binary.BigEndian, header.Type); err != nil {
		return err
	}
	if err := binary.Write(s.conn, binary.BigEndian, header.PayloadLen); err != nil {
		return err
	}

	// Write payload
	_, err = s.conn.Write(encryptedPayload)
	return err
}

// Receive a message
func (s *SecureShell) receiveMessage() (byte, []byte, error) {
	// Read header
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

	// Read payload
	encryptedPayload := make([]byte, header.PayloadLen)
	if _, err := io.ReadFull(s.conn, encryptedPayload); err != nil {
		return 0, nil, err
	}

	// Decrypt payload
	payload, err := crypto.AESDecrypt(encryptedPayload, s.passphrase)
	if err != nil {
		return 0, nil, err
	}

	return header.Type, payload, nil
}

// Run the interactive shell
func (s *SecureShell) RunInteractive() error {
	// Set up signal handling for clean exit
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
		var command string
		fmt.Scanln(&command)

		if command == "exit" {
			break
		}

		if command == "" {
			continue
		}

		// Handle special commands
		if len(command) > 7 && command[:7] == "upload " {
			// Parse upload command
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
			// Parse download command
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

		// Send command to server
		if err := s.sendMessage(MSG_COMMAND, []byte(command)); err != nil {
			fmt.Printf("Error sending command: %v\n", err)
			break
		}

		// Receive response
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

// Upload a file
func (s *SecureShell) uploadFile(localPath, remotePath string) error {
	// Read the local file
	data, err := os.ReadFile(localPath)
	if err != nil {
		return err
	}

	// Prepare upload message
	uploadMsg := append([]byte(remotePath), 0) // Null-terminated path
	uploadMsg = append(uploadMsg, data...)

	// Send upload message
	if err := s.sendMessage(MSG_FILE_UPLOAD, uploadMsg); err != nil {
		return err
	}

	// Receive response
	msgType, payload, err := s.receiveMessage()
	if err != nil {
		return err
	}

	if msgType == MSG_ERROR {
		return fmt.Errorf("server error: %s", string(payload))
	}

	return nil
}

// Download a file
func (s *SecureShell) downloadFile(remotePath, localPath string) error {
	// Send download message
	if err := s.sendMessage(MSG_FILE_DOWNLOAD, []byte(remotePath)); err != nil {
		return err
	}

	// Receive response
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

	// Write the file
	return os.WriteFile(localPath, payload, 0644)
}

// Execute a single command and return the result
func (s *SecureShell) ExecuteCommand(command string) (string, error) {
	// Send command to server
	if err := s.sendMessage(MSG_COMMAND, []byte(command)); err != nil {
		return "", err
	}

	// Receive response
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

// Close the connection
func (s *SecureShell) Close() {
	if s.conn != nil {
		s.conn.Close()
	}
}

func main() {
	// Parse command line arguments
	host := flag.String("host", "127.0.0.1", "Host to connect to")
	port := flag.Int("port", 8443, "Port to connect to")
	passphrase := flag.String("passphrase", "default-passphrase", "Passphrase for encryption")
	useTLS := flag.Bool("tls", true, "Use TLS encryption")
	interactive := flag.Bool("interactive", true, "Run in interactive mode")
	command := flag.String("command", "", "Single command to execute (non-interactive mode)")

	flag.Parse()

	// Create secure shell
	secureShell := NewSecureShell(*passphrase, *interactive)

	// Connect to server
	err := secureShell.Connect(*host, *port, *useTLS)
	if err != nil {
		fmt.Printf("Connection failed: %v\n", err)
		os.Exit(1)
	}
	defer secureShell.Close()

	// Run in interactive or command mode
	if *interactive {
		if err := secureShell.RunInteractive(); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	} else if *command != "" {
		// Execute a single command
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
