package shell_anon
import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)
type ProcessHider struct {
}
func NewProcessHider() *ProcessHider {
	return &ProcessHider{}
}
func (p *ProcessHider) HideProcess(pid int, newName string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("process hiding is only supported on Linux")
	}
	
	
	
	
	_, err := exec.LookPath("prctl")
	if err != nil {
		return fmt.Errorf("prctl command not found")
	}
	
	
	
	return nil
}
func (p *ProcessHider) HideCurrentProcess(newName string) error {
	return p.HideProcess(os.Getpid(), newName)
}
func (p *ProcessHider) HideFromPS() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("process hiding from ps is only supported on Linux")
	}
	
	
	
	
	return nil
}
func (p *ProcessHider) GetProcessHidingTips() []string {
	return []string{
		"Use prctl to change process name",
		"Prefix process name with a space to hide from casual ps",
		"Use LD_PRELOAD to hook readdir and filter out processes",
		"Use cgroups to hide processes (advanced)",
		"Use kernel modules to hide processes (advanced)",
	}
}
