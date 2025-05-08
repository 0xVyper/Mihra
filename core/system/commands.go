package system

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"unicode"
)

type CommandExecutor struct {
	terminal string
	argument string
	commands map[string]func(string) ([]byte, error)
}

func NewCommandExecutor() *CommandExecutor {
	var terminal, argument string
	if runtime.GOOS == "windows" {
		terminal = "cmd.exe"
		argument = "/C"
	} else {
		terminal = "bash"
		argument = "-c"
	}
	ce := &CommandExecutor{
		terminal: terminal,
		argument: argument,
		commands: make(map[string]func(string) ([]byte, error)),
	}

	ce.commands["whoami"] = func(_ string) ([]byte, error) {
		return []byte(os.Getenv("USER")), nil
	}
	ce.commands["sysinfo"] = func(_ string) ([]byte, error) {
		return []byte(fmt.Sprintf("OS: %s, Arch: %s", runtime.GOOS, runtime.GOARCH)), nil
	}
	ce.commands["pwd"] = func(_ string) ([]byte, error) {
		path, _ := os.Getwd()
		return []byte("current directory: " + path), nil
	}
	return ce
}
func CleanCommand(command string) string {
	var cleaned []rune
	for _, r := range command {
		if unicode.IsPrint(r) {
			cleaned = append(cleaned, r)
		}
	}
	return string(cleaned)
}
func (ce *CommandExecutor) Execute(command string) ([]byte, error) {
	cleanedData := CleanCommand(strings.TrimSpace(command))
	cmdParts := strings.Fields(cleanedData)
	if len(cmdParts) == 0 {
		return []byte("Empty command"), nil
	}

	if handler, ok := ce.commands[cmdParts[0]]; ok {
		return handler(strings.Join(cmdParts[1:], " "))
	}

	var output []byte
	var err error
	if strings.HasPrefix(cleanedData, "cd ") {
		newDir := strings.TrimPrefix(cleanedData, "cd ")
		err = os.Chdir(newDir)
		if err != nil {
			return nil, fmt.Errorf("error changing directory: %v", err)
		}
		path, _ := os.Getwd()
		output = []byte("current directory: " + path)
	} else {
		cmd := exec.Command(ce.terminal, ce.argument, cleanedData)
		cmd.Stdin = os.Stdin
		var outBuffer, errBuffer bytes.Buffer
		cmd.Stdout = &outBuffer
		cmd.Stderr = &errBuffer
		err = cmd.Run()
		if err != nil {
			return errBuffer.Bytes(), nil
		}
		output = outBuffer.Bytes()
	}
	return output, nil
}
func (ce *CommandExecutor) RegisterCommand(name string, handler func(string) ([]byte, error)) {
	ce.commands[name] = handler
}
