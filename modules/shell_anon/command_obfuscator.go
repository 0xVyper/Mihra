package shell_anon

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// CommandObfuscator provides functionality for obfuscating commands
type CommandObfuscator struct {
}

// NewCommandObfuscator creates a new command obfuscator
func NewCommandObfuscator() *CommandObfuscator {
	return &CommandObfuscator{}
}

// ObfuscateCommand obfuscates a command to avoid detection
func (c *CommandObfuscator) ObfuscateCommand(command string) string {
	// This is a simplified implementation
	// In a real implementation, you would use more sophisticated techniques
	
	// Replace spaces with ${IFS}
	command = strings.ReplaceAll(command, " ", "${IFS}")
	
	// Replace common commands with their path equivalents
	command = strings.ReplaceAll(command, "cat ", "/bin/cat ")
	command = strings.ReplaceAll(command, "ls ", "/bin/ls ")
	command = strings.ReplaceAll(command, "ps ", "/bin/ps ")
	command = strings.ReplaceAll(command, "netstat ", "/bin/netstat ")
	
	return command
}

// EncodeCommand encodes a command using base64
func (c *CommandObfuscator) EncodeCommand(command string) string {
	// Encode the command using base64
	encoded := base64.StdEncoding.EncodeToString([]byte(command))
	
	// Create a command that will decode and execute the encoded command
	return fmt.Sprintf("echo %s | base64 -d | bash", encoded)
}

// HideCommandOptions hides command line options using environment variables
func (c *CommandObfuscator) HideCommandOptions(command string, options map[string]string) string {
	// Split the command into parts
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return command
	}
	
	// Extract the base command
	baseCommand := parts[0]
	
	// Create environment variable exports
	var exports []string
	for k, v := range options {
		exports = append(exports, fmt.Sprintf("export %s=%s", k, v))
	}
	
	// Combine the exports and the base command
	return fmt.Sprintf("%s && %s", strings.Join(exports, "; "), baseCommand)
}

// GetCommandObfuscationTips returns tips for obfuscating commands
func (c *CommandObfuscator) GetCommandObfuscationTips() []string {
	return []string{
		"Use ${IFS} instead of spaces",
		"Use base64 encoding to hide command content",
		"Use environment variables to hide command options",
		"Use command substitution to hide command names",
		"Use aliases to hide actual commands",
		"Use hex or octal encoding for strings",
	}
}
