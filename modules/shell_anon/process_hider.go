package shell_anon

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// ProcessHider provides functionality for hiding processes
type ProcessHider struct {
}

// NewProcessHider creates a new process hider
func NewProcessHider() *ProcessHider {
	return &ProcessHider{}
}

// HideProcess hides a process from monitoring tools
func (p *ProcessHider) HideProcess(pid int, newName string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("process hiding is only supported on Linux")
	}

	// This is a simplified implementation
	// In a real implementation, you would use prctl(PR_SET_NAME) syscall
	// or modify /proc/[pid]/comm

	// For demonstration purposes, we'll just check if the command exists
	_, err := exec.LookPath("prctl")
	if err != nil {
		return fmt.Errorf("prctl command not found")
	}

	// In a real implementation, you would execute something like:
	// cmd := exec.Command("prctl", "-n", "pr_setname", "-v", newName, fmt.Sprintf("%d", pid))
	// return cmd.Run()

	return nil
}

// HideCurrentProcess hides the current process
func (p *ProcessHider) HideCurrentProcess(newName string) error {
	return p.HideProcess(os.Getpid(), newName)
}

// HideFromPS hides a process from ps command output
func (p *ProcessHider) HideFromPS() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("process hiding from ps is only supported on Linux")
	}

	// This is a simplified implementation
	// In a real implementation, you would use LD_PRELOAD to hook the readdir function
	// or modify the process name to start with a space

	// For demonstration purposes, we'll just check if we're on Linux
	return nil
}

// GetProcessHidingTips returns tips for hiding processes
func (p *ProcessHider) GetProcessHidingTips() []string {
	return []string{
		"Use prctl to change process name",
		"Prefix process name with a space to hide from casual ps",
		"Use LD_PRELOAD to hook readdir and filter out processes",
		"Use cgroups to hide processes (advanced)",
		"Use kernel modules to hide processes (advanced)",
	}
}
