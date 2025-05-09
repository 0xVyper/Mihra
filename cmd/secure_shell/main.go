package main

import (
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

	"github.com/peterh/liner"

	"github.com/simplified_c2/core/crypto"
	"github.com/simplified_c2/module"
	"github.com/simplified_c2/modules/sessions"
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
	conn         net.Conn
	passphrase   []byte // Fallback passphrase (not used with session key)
	sessionID    string
	sessionKey   []byte // Session-specific AES key
	sessionIV    []byte // Session-specific AES IV
	interactive  bool
	shell        *shell.Shell
	moduleSystem *module.ModuleSystem // Reutilizar moduleSystem
}

//go:embed private_key.pem
var privateKeyPEM []byte // RSA private key for decrypting session key/IV

func NewSecureShell(passphrase string, interactive bool) *SecureShell {
	// Inicializar moduleSystem
	moduleSystem := module.NewModuleSystem()
	registerBuiltinModules(moduleSystem)
	return &SecureShell{
		passphrase:   []byte(passphrase),
		interactive:  interactive,
		shell:        shell.NewShell(),
		moduleSystem: moduleSystem,
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

	sessionModule, err := s.moduleSystem.Manager.LoadModule("sessions")
	if err != nil {
		s.conn.Close()
		return fmt.Errorf("failed to load sessions module: %v", err)
	}

	if err := s.performHandshake(host, port, string(s.passphrase), useTLS, sessionModule); err != nil {
		s.conn.Close()
		return fmt.Errorf("handshake failed: %v", err)
	}

	fmt.Println("Secure connection established")
	return nil
}

func (s *SecureShell) performHandshake(host string, port int, passphrase string, useTLS bool, sessionModule module.ModuleInterface) error {
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

	// Register session in the sessions module
	_, err = sessionModule.ExecuteCommand("register", []string{host, fmt.Sprintf("%d", port), passphrase, sessionID, fmt.Sprintf("%t", useTLS)})
	if err != nil {
		return fmt.Errorf("failed to register session: %v", err)
	}
	fmt.Printf("Session %s registered successfully\n", sessionID)

	// Connect session to mark as active
	_, err = sessionModule.ExecuteCommand("connect", []string{"new", host, fmt.Sprintf("%d", port), passphrase, fmt.Sprintf("%t", useTLS)})
	if err != nil {
		return fmt.Errorf("failed to connect session: %v", err)
	}
	fmt.Printf("Session %s connected successfully\n", sessionID)

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
		if s.conn != nil {
			s.conn.Close()
		}
		os.Exit(0)
	}()

	// Initialize liner for interactive TTY
	line := liner.NewLiner()
	defer line.Close()

	// Enable history
	line.SetCtrlCAborts(true)
	historyFile := os.Getenv("HOME") + "/.c2_history"
	if f, err := os.Open(historyFile); err == nil {
		line.ReadHistory(f)
		f.Close()
	}

	// Set completer for commands
	line.SetCompleter(func(line string) (c []string) {
		commands := []string{
			"upload ", "download ", "cd ", "pwd", "/sessions ",
			"/sessions connect ", "/sessions disconnect", "/sessions listsessions",
			"/sessions changesession ", "/sessions execute ", "/sessions status",
			"exit",
		}
		for _, cmd := range commands {
			if strings.HasPrefix(cmd, strings.ToLower(line)) {
				c = append(c, cmd)
			}
		}
		return
	})

	fmt.Println("Secure shell ready. Type 'exit' to quit.")
	fmt.Println("Special commands:")
	fmt.Println("  upload <local_file> <remote_file> - Upload a file")
	fmt.Println("  download <remote_file> <local_file> - Download a file")
	fmt.Println("  cd <directory> - Change directory")
	fmt.Println("  pwd - Print working directory")
	fmt.Println("  /sessions [subcommand] - Manage sessions (e.g., connect, disconnect, listsessions)")

	for {
		command, err := line.Prompt("> ")
		if err == liner.ErrPromptAborted || err == io.EOF {
			break
		}
		if err != nil {
			fmt.Printf("Error reading input: %v\n", err)
			break
		}

		command = strings.TrimSpace(command)
		if command == "" {
			continue
		}

		// Append to history
		line.AppendHistory(command)

		// Handle special commands
		if len(command) > 7 && command[:7] == "upload " {
			var localFile, remoteFile string
			fmt.Sscanf(command[7:], "%s %s", &localFile, &remoteFile)
			if localFile == "" || remoteFile == "" {
				fmt.Println("Usage: upload <local_file> <remote_file>")
				continue
			}
			if s.conn == nil {
				fmt.Println("Error: no active connection")
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
			if s.conn == nil {
				fmt.Println("Error: no active connection")
				continue
			}
			if err := s.downloadFile(remoteFile, localFile); err != nil {
				fmt.Printf("Download failed: %v\n", err)
			} else {
				fmt.Println("Download complete")
			}
			continue
		}
		if len(command) >= 9 && command[:9] == "/sessions" {
			sessionModule, err := s.moduleSystem.Manager.LoadModule("sessions")
			if err != nil {
				fmt.Printf("Error loading sessions module: %v\n", err)
				continue
			}

			// Parse subcomando e argumentos
			parts := strings.Fields(command)
			if len(parts) == 1 {
				// /sessions sem subcomando = listsessions
				result, err := sessionModule.ExecuteCommand("listsessions", []string{})
				if err != nil {
					fmt.Printf("Error executing listsessions: %v\n", err)
					continue
				}
				for _, line := range result.([]string) {
					fmt.Println("session:", line)
				}
			} else {
				// /sessions <subcomando> <args>
				subcommand := parts[1]
				args := parts[2:]
				result, err := sessionModule.ExecuteCommand(subcommand, args)
				if err != nil {
					fmt.Printf("Error executing %s: %v\n", subcommand, err)
					continue
				}
				switch subcommand {
				case "listsessions":
					for _, line := range result.([]string) {
						fmt.Println("session:", line)
					}
				case "connect", "changesession", "execute", "register":
					fmt.Println(result.(string))
				case "disconnect":
					fmt.Println(result.(string))
					// Atualizar conexão do SecureShell
					if len(args) > 0 {
						s.sessionID = args[0]
						s.conn = nil // Conexão foi fechada
					}
				case "status":
					for key, value := range result.(map[string]interface{}) {
						fmt.Printf("%s: %v\n", key, value)
					}
				default:
					fmt.Printf("Unknown subcommand: %s\n", subcommand)
				}
			}
			continue
		}

		// Send command to server
		if s.conn == nil {
			fmt.Println("Error: no active connection. Use '/sessions connect' to establish a connection")
			continue
		}
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

	// Save history
	if f, err := os.Create(historyFile); err == nil {
		line.WriteHistory(f)
		f.Close()
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
	if s.conn == nil {
		return "", fmt.Errorf("no active connection")
	}
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
	host := flag.String("host", "", "Host to connect to")
	port := flag.Int("port", 8443, "Port to connect to")
	passphrase := flag.String("passphrase", "default-passphrase", "Passphrase for encryption (fallback)")
	useTLS := flag.Bool("tls", true, "Use TLS encryption")
	interactive := flag.Bool("interactive", true, "Run in interactive mode")
	command := flag.String("command", "", "Single command to execute (non-interactive mode)")
	flag.Parse()

	secureShell := NewSecureShell(*passphrase, *interactive)

	// Só conectar se host for fornecido
	if *host != "" && *interactive {
		err := secureShell.Connect(*host, *port, *useTLS)
		if err != nil {
			fmt.Printf("Connection failed: %v\n", err)
			os.Exit(1)
		}
		defer secureShell.Close()
	}

	if *interactive {
		if err := secureShell.RunInteractive(); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	} else if *command != "" {
		if *host == "" {
			fmt.Println("Error: host must be specified in non-interactive mode")
			os.Exit(1)
		}
		err := secureShell.Connect(*host, *port, *useTLS)
		if err != nil {
			fmt.Printf("Connection failed: %v\n", err)
			os.Exit(1)
		}
		defer secureShell.Close()
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

func registerBuiltinModules(moduleSystem *module.ModuleSystem) {
	sessionModule := sessions.NewModule()
	moduleSystem.Registry.RegisterModule("sessions", func() module.ModuleInterface {
		return sessionModule
	})
}
