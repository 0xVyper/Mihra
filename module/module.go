package module

import (
	"errors"
	"fmt"
	"plugin"
	"sync"
)

// ModuleInterface defines the interface that all modules must implement
type ModuleInterface interface {
	// GetInfo returns information about the module
	GetInfo() *ModuleInfo
	// Initialize initializes the module
	Initialize() error
	// ExecuteCommand executes a command
	ExecuteCommand(command string, args []string) (interface{}, error)
}

// ModuleInfo contains information about a module
type ModuleInfo struct {
	Name        string
	Version     string
	Description string
	Author      string
	Commands    []CommandInfo
	Options     map[string]string
}

// CommandInfo contains information about a command
type CommandInfo struct {
	Name        string
	Description string
	Usage       string
	Options     map[string]string
}

// ModuleRegistry manages module registration
type ModuleRegistry struct {
	modules map[string]func() ModuleInterface
	mutex   sync.RWMutex
}

// NewModuleRegistry creates a new module registry
func NewModuleRegistry() *ModuleRegistry {
	return &ModuleRegistry{
		modules: make(map[string]func() ModuleInterface),
	}
}

// RegisterModule registers a module
func (r *ModuleRegistry) RegisterModule(name string, factory func() ModuleInterface) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.modules[name] = factory
}

// GetModule gets a module factory
func (r *ModuleRegistry) GetModule(name string) (func() ModuleInterface, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	factory, ok := r.modules[name]
	if !ok {
		return nil, fmt.Errorf("module not found: %s", name)
	}
	return factory, nil
}

// ListModules lists all registered modules
func (r *ModuleRegistry) ListModules() []string {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	var modules []string
	for name := range r.modules {
		modules = append(modules, name)
	}
	return modules
}

// ModuleManager manages module instances
type ModuleManager struct {
	Registry *ModuleRegistry
	modules  map[string]ModuleInterface
	mutex    sync.RWMutex
}

// NewModuleManager creates a new module manager
func NewModuleManager(registry *ModuleRegistry) *ModuleManager {
	return &ModuleManager{
		Registry: registry,
		modules:  make(map[string]ModuleInterface),
	}
}

// LoadModule loads a module
func (m *ModuleManager) LoadModule(name string) (ModuleInterface, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check if the module is already loaded
	if mod, ok := m.modules[name]; ok {
		return mod, nil
	}

	// Get the module factory
	factory, err := m.Registry.GetModule(name)
	if err != nil {
		return nil, err
	}

	// Create the module
	mod := factory()

	// Initialize the module
	if err := mod.Initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize module: %v", err)
	}

	// Store the module
	m.modules[name] = mod

	return mod, nil
}

// GetModule gets a loaded module
func (m *ModuleManager) GetModule(name string) (ModuleInterface, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	mod, ok := m.modules[name]
	if !ok {
		return nil, fmt.Errorf("module not loaded: %s", name)
	}

	return mod, nil
}

// GetModuleInfo gets information about a module
func (m *ModuleManager) GetModuleInfo(name string) (*ModuleInfo, error) {
	mod, err := m.GetModule(name)
	if err != nil {
		return nil, err
	}

	return mod.GetInfo(), nil
}

// ExecuteCommand executes a command in a module
func (m *ModuleManager) ExecuteCommand(moduleName, commandName string, args []string) (interface{}, error) {
	mod, err := m.GetModule(moduleName)
	if err != nil {
		return nil, err
	}

	return mod.ExecuteCommand(commandName, args)
}

// ListModules lists all loaded modules
func (m *ModuleManager) ListModules() []string {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var modules []string
	for name := range m.modules {
		modules = append(modules, name)
	}

	return modules
}

// ModuleLoader loads modules from shared libraries
type ModuleLoader struct {
	Manager *ModuleManager
}

// NewModuleLoader creates a new module loader
func NewModuleLoader(manager *ModuleManager) *ModuleLoader {
	return &ModuleLoader{
		Manager: manager,
	}
}

// LoadModuleFromFile loads a module from a shared library file
func (l *ModuleLoader) LoadModuleFromFile(path string) (string, error) {
	// Load the plugin
	p, err := plugin.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open plugin: %v", err)
	}

	// Look up the module symbol
	sym, err := p.Lookup("Module")
	if err != nil {
		return "", fmt.Errorf("failed to find Module symbol: %v", err)
	}

	// Check if the symbol is a ModuleInterface
	mod, ok := sym.(ModuleInterface)
	if !ok {
		return "", errors.New("Module symbol is not a ModuleInterface")
	}

	// Get the module info
	info := mod.GetInfo()
	if info == nil {
		return "", errors.New("module info is nil")
	}

	// Register the module
	l.Manager.Registry.RegisterModule(info.Name, func() ModuleInterface {
		return mod
	})

	// Load the module
	_, err = l.Manager.LoadModule(info.Name)
	if err != nil {
		return "", fmt.Errorf("failed to load module: %v", err)
	}

	return info.Name, nil
}

// ModuleSystem represents the module system
type ModuleSystem struct {
	Registry *ModuleRegistry
	Manager  *ModuleManager
	Loader   *ModuleLoader
}

// NewModuleSystem creates a new module system
func NewModuleSystem() *ModuleSystem {
	registry := NewModuleRegistry()
	manager := NewModuleManager(registry)
	loader := NewModuleLoader(manager)

	return &ModuleSystem{
		Registry: registry,
		Manager:  manager,
		Loader:   loader,
	}
}
