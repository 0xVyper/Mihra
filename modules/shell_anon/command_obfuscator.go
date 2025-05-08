package shell_anon
import (
	"encoding/base64"
	"fmt"
	"strings"
)
type CommandObfuscator struct {
}
func NewCommandObfuscator() *CommandObfuscator {
	return &CommandObfuscator{}
}
func (c *CommandObfuscator) ObfuscateCommand(command string) string {
	
	
	
	
	command = strings.ReplaceAll(command, " ", "${IFS}")
	
	
	command = strings.ReplaceAll(command, "cat ", "/bin/cat ")
	command = strings.ReplaceAll(command, "ls ", "/bin/ls ")
	command = strings.ReplaceAll(command, "ps ", "/bin/ps ")
	command = strings.ReplaceAll(command, "netstat ", "/bin/netstat ")
	
	return command
}
func (c *CommandObfuscator) EncodeCommand(command string) string {
	
	encoded := base64.StdEncoding.EncodeToString([]byte(command))
	
	
	return fmt.Sprintf("echo %s | base64 -d | bash", encoded)
}
func (c *CommandObfuscator) HideCommandOptions(command string, options map[string]string) string {
	
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return command
	}
	
	
	baseCommand := parts[0]
	
	
	var exports []string
	for k, v := range options {
		exports = append(exports, fmt.Sprintf("export %s=%s", k, v))
	}
	
	
	return fmt.Sprintf("%s && %s", strings.Join(exports, "; "), baseCommand)
}
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
