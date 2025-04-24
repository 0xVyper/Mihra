package shell_anon

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// ShellAnonymizer provides functionality for shell anonymization
type ShellAnonymizer struct {
	originalEnv map[string]string
	safeEnv     map[string]string
}

// NewShellAnonymizer creates a new shell anonymizer
func NewShellAnonymizer() *ShellAnonymizer {
	return &ShellAnonymizer{
		originalEnv: make(map[string]string),
		safeEnv:     make(map[string]string),
	}
}

// DisableHistory disables command history
func (s *ShellAnonymizer) DisableHistory() error {
	// Save original history settings
	s.originalEnv["HISTFILE"] = os.Getenv("HISTFILE")
	s.originalEnv["HISTFILESIZE"] = os.Getenv("HISTFILESIZE")
	s.originalEnv["HISTSIZE"] = os.Getenv("HISTSIZE")
	s.originalEnv["HISTCONTROL"] = os.Getenv("HISTCONTROL")

	// Disable history
	os.Setenv("HISTFILE", "/dev/null")
	os.Setenv("HISTFILESIZE", "0")
	os.Setenv("HISTSIZE", "0")
	os.Setenv("HISTCONTROL", "ignoreboth")

	return nil
}

// RestoreHistory restores the original history settings
func (s *ShellAnonymizer) RestoreHistory() error {
	// Restore original history settings
	for k, v := range s.originalEnv {
		if strings.HasPrefix(k, "HIST") {
			os.Setenv(k, v)
		}
	}

	return nil
}

// SetSecurePrompt sets a secure prompt that doesn't reveal sensitive information
func (s *ShellAnonymizer) SetSecurePrompt(prompt string) {
	// Save original prompt
	s.originalEnv["PS1"] = os.Getenv("PS1")

	// Set secure prompt
	if prompt == "" {
		prompt = "\\[\\033[36m\\]\\u\\[\\033[m\\]@\\[\\033[32m\\]\\h:\\[\\033[33;1m\\]\\w\\[\\033[m\\]\\$ "
	}

	os.Setenv("PS1", prompt)
}

// SetSecureTempDir sets a secure temporary directory
func (s *ShellAnonymizer) SetSecureTempDir() error {
	// Save original temporary directory
	s.originalEnv["TMPDIR"] = os.Getenv("TMPDIR")

	// Set secure temporary directory
	// Prefer memory-based temporary directories
	if _, err := os.Stat("/dev/shm"); err == nil {
		os.Setenv("TMPDIR", "/dev/shm")
	} else if _, err := os.Stat("/tmp"); err == nil {
		os.Setenv("TMPDIR", "/tmp")
	}

	return nil
}

// ExecuteHiddenCommand executes a command with hidden output
func (s *ShellAnonymizer) ExecuteHiddenCommand(command string) (string, error) {
	// This is a simplified implementation
	// In a real implementation, you would use more sophisticated techniques

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

// HideProcessName hides the process name in ps output
func (s *ShellAnonymizer) HideProcessName(pid int, newName string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("process name hiding is only supported on Linux")
	}

	// This is a simplified implementation
	// In a real implementation, you would use prctl(PR_SET_NAME) syscall
	// or modify /proc/[pid]/comm

	// For demonstration purposes, we'll just check if the command exists
	_, err := exec.LookPath("prctl")
	if err != nil {
		return fmt.Errorf("prctl command not found")
	}

	return nil
}

// SetupHackShell sets up a complete "hack shell" environment
func (s *ShellAnonymizer) SetupHackShell() error {
	// Disable command history
	if err := s.DisableHistory(); err != nil {
		return err
	}

	// Set secure prompt
	s.SetSecurePrompt("")

	// Set secure temporary directory
	if err := s.SetSecureTempDir(); err != nil {
		return err
	}

	// Set additional security-focused environment variables
	s.safeEnv["PATH"] = ".:" + os.Getenv("PATH") // Add current directory to PATH
	s.safeEnv["TERM"] = "xterm"                  // Set standard terminal type

	// Set locale to avoid weird characters
	s.safeEnv["LANG"] = "en_US.UTF-8"
	s.safeEnv["LC_ALL"] = "en_US.UTF-8"

	// Apply all environment variables
	for k, v := range s.safeEnv {
		s.originalEnv[k] = os.Getenv(k)
		os.Setenv(k, v)
	}

	return nil
}

// GenerateHackShellScript generates a script to set up a hack shell
func (s *ShellAnonymizer) GenerateHackShellScript() string {
	var script strings.Builder

	script.WriteString("#!/bin/bash\n\n")
	script.WriteString("# Shell anonymization setup script\n\n")

	// Disable history
	script.WriteString("# Disable command history\n")
	script.WriteString("unset HISTFILE\n")
	script.WriteString("export HISTFILE=/dev/null\n")
	script.WriteString("export HISTFILESIZE=0\n")
	script.WriteString("export HISTSIZE=0\n")
	script.WriteString("export HISTCONTROL=ignoreboth\n")
	script.WriteString("export HISTIGNORE=\"*\"\n\n")

	// Disable application-specific history
	script.WriteString("# Disable application-specific history\n")
	script.WriteString("export LESSHISTFILE=-\n")
	script.WriteString("export MYSQL_HISTFILE=/dev/null\n")
	script.WriteString("export REDISCLI_HISTFILE=/dev/null\n\n")

	// Set secure temporary directory
	script.WriteString("# Set secure temporary directory\n")
	script.WriteString("TMPDIR=\"/tmp\"\n")
	script.WriteString("[ -d \"/var/tmp\" ] && TMPDIR=\"/var/tmp\"\n")
	script.WriteString("[ -d \"/dev/shm\" ] && TMPDIR=\"/dev/shm\"\n")
	script.WriteString("export TMPDIR\n\n")

	// Set secure PATH
	script.WriteString("# Set secure PATH\n")
	script.WriteString("export PATH=\".:${PATH}\"\n\n")

	// Set custom prompt
	script.WriteString("# Set custom prompt\n")
	script.WriteString("PS1='\\[\\033[36m\\]\\u\\[\\033[m\\]@\\[\\033[32m\\]\\h:\\[\\033[33;1m\\]\\w\\[\\033[m\\]\\$ '\n\n")

	// Set locale
	script.WriteString("# Set locale\n")
	script.WriteString("export LANG=en_US.UTF-8\n")
	script.WriteString("locale -a 2>/dev/null|grep -Fqim1 en_US.UTF || export LANG=en_US\n\n")

	// Set aliases for common tools
	script.WriteString("# Set secure aliases\n")
	script.WriteString("alias wget='wget --no-hsts'\n")
	script.WriteString("alias vi='vi -i NONE'\n")
	script.WriteString("alias vim='vim -i NONE'\n")
	script.WriteString("alias screen='screen -ln'\n\n")

	// Terminal setup
	script.WriteString("# Terminal setup\n")
	script.WriteString("TERM=xterm reset -I\n")
	script.WriteString("stty cols 400\n")
	script.WriteString("resize &>/dev/null || { stty -echo;printf \"\\e[18t\"; read -t5 -rdt R;IFS=';' read -r -a a <<< \"${R:-8;25;80}\";[ \"${a[1]}\" -ge \"${a[2]}\" ] && { R=\"${a[1]}\";a[1]=\"${a[2]}\";a[2]=\"${R}\";}; stty sane rows \"${a[1]}\" cols \"${a[2]}\";};\n\n")

	// Add reminder about space prefix
	script.WriteString("# Remember: any command starting with a space will not be logged to history\n")
	script.WriteString("echo \"Hack shell initialized. Commands prefixed with a space will not be logged to history.\"\n")

	return script.String()
}

// GetHiddenCommandTips returns tips for hiding commands
func (s *ShellAnonymizer) GetHiddenCommandTips() []string {
	return []string{
		"Prefix commands with a space to avoid bash history",
		"Use 'exec' to replace the current process",
		"Use process name hiding techniques",
		"Use environment variables to hide command line options",
		"Use aliases to hide actual commands",
		"Use encoded commands: echo 'Y21kIGhlcmU=' | base64 -d | bash",
	}
}

// GetNetworkHidingTips returns tips for hiding network connections
func (s *ShellAnonymizer) GetNetworkHidingTips() []string {
	return []string{
		"Use encrypted protocols (SSH, TLS)",
		"Use common ports (80, 443) to blend with normal traffic",
		"Use DNS tunneling for covert communication",
		"Use ICMP tunneling to evade firewall restrictions",
		"Use HTTP/HTTPS proxies to hide the origin",
		"Use Tor or other anonymization networks",
	}
}
