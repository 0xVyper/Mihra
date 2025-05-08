package module
import (
	"errors"
	"fmt"
	"plugin"
	"sync"
)
type ModuleInterface interface {
	
	GetInfo() *ModuleInfo
	
	Initialize() error
	
	ExecuteCommand(command string, args []string) (interface{}, error)
}
type ModuleInfo struct {
	Name        string
	Version     string
	Description string
	Author      string
	Commands    []CommandInfo
	Options     map[string]string
}
type CommandInfo struct {
	Name        string
	Description string
	Usage       string
	Options     map[string]string
}
type ModuleRegistry struct {
	modules map[string]func() ModuleInterface
	mutex   sync.RWMutex
}
func NewModuleRegistry() *ModuleRegistry {
	return &ModuleRegistry{
		modules: make(map[string]func() ModuleInterface),
	}
}
func (r *ModuleRegistry) RegisterModule(name string, factory func() ModuleInterface) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.modules[name] = factory
}
func (r *ModuleRegistry) GetModule(name string) (func() ModuleInterface, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	factory, ok := r.modules[name]
	if !ok {
		return nil, fmt.Errorf("module not found: %s", name)
	}
	return factory, nil
}
func (r *ModuleRegistry) ListModules() []string {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	var modules []string
	for name := range r.modules {
		modules = append(modules, name)
	}
	return modules
}
type ModuleManager struct {
	Registry *ModuleRegistry
	modules  map[string]ModuleInterface
	mutex    sync.RWMutex
}
func NewModuleManager(registry *ModuleRegistry) *ModuleManager {
	return &ModuleManager{
		Registry: registry,
		modules:  make(map[string]ModuleInterface),
	}
}
func (m *ModuleManager) LoadModule(name string) (ModuleInterface, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	if mod, ok := m.modules[name]; ok {
		return mod, nil
	}
	
	factory, err := m.Registry.GetModule(name)
	if err != nil {
		return nil, err
	}
	
	mod := factory()
	
	if err := mod.Initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize module: %v", err)
	}
	
	m.modules[name] = mod
	return mod, nil
}
func (m *ModuleManager) GetModule(name string) (ModuleInterface, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	mod, ok := m.modules[name]
	if !ok {
		return nil, fmt.Errorf("module not loaded: %s", name)
	}
	return mod, nil
}
func (m *ModuleManager) GetModuleInfo(name string) (*ModuleInfo, error) {
	mod, err := m.GetModule(name)
	if err != nil {
		return nil, err
	}
	return mod.GetInfo(), nil
}
func (m *ModuleManager) ExecuteCommand(moduleName, commandName string, args []string) (interface{}, error) {
	mod, err := m.GetModule(moduleName)
	if err != nil {
		return nil, err
	}
	return mod.ExecuteCommand(commandName, args)
}
func (m *ModuleManager) ListModules() []string {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	var modules []string
	for name := range m.modules {
		modules = append(modules, name)
	}
	return modules
}
type ModuleLoader struct {
	Manager *ModuleManager
}
func NewModuleLoader(manager *ModuleManager) *ModuleLoader {
	return &ModuleLoader{
		Manager: manager,
	}
}
func (l *ModuleLoader) LoadModuleFromFile(path string) (string, error) {
	
	p, err := plugin.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open plugin: %v", err)
	}
	
	sym, err := p.Lookup("Module")
	if err != nil {
		return "", fmt.Errorf("failed to find Module symbol: %v", err)
	}
	
	mod, ok := sym.(ModuleInterface)
	if !ok {
		return "", errors.New("Module symbol is not a ModuleInterface")
	}
	
	info := mod.GetInfo()
	if info == nil {
		return "", errors.New("module info is nil")
	}
	
	l.Manager.Registry.RegisterModule(info.Name, func() ModuleInterface {
		return mod
	})
	
	_, err = l.Manager.LoadModule(info.Name)
	if err != nil {
		return "", fmt.Errorf("failed to load module: %v", err)
	}
	return info.Name, nil
}
type ModuleSystem struct {
	Registry *ModuleRegistry
	Manager  *ModuleManager
	Loader   *ModuleLoader
}
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
