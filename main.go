package main

import (
	"fmt"
	"github.com/JamesHovious/w32"
	"golang.org/x/sys/windows"
	"os"
	"syscall"
	"unsafe"
)

var modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
var getModuleHandleA = modkernel32.NewProc("GetModuleHandleA")
var loadLibraryA = modkernel32.NewProc("LoadLibraryA")

func input(q string) string {
	var s string
	fmt.Println(q)
	fmt.Scanln(&s)
	return s
}

func GetModuleHandleA(moduleName string) w32.HANDLE {
	s16, err := syscall.UTF16PtrFromString(moduleName)
	if err != nil {
		panic("err")
	}
	r1, r2, e1 := syscall.Syscall(getModuleHandleA.Addr(), 1, uintptr(unsafe.Pointer(s16)), 0, 0)
	fmt.Println(r1, r2, e1)
	if r1 == 0 {
		if e1 != 0 {
			fmt.Println(syscall.Errno(e1))

		} else {
			err = syscall.EINVAL
		}
	}
	return w32.HANDLE(r1)
}

// GetProcessName ---
func GetProcessName(id uint32) string {
	snapshot := w32.CreateToolhelp32Snapshot(w32.TH32CS_SNAPMODULE, id)
	if snapshot == w32.ERROR_INVALID_HANDLE {
		return "<UNKNOWN>"
	}
	defer w32.CloseHandle(snapshot)

	var me w32.MODULEENTRY32
	me.Size = uint32(unsafe.Sizeof(me))
	if w32.Module32First(snapshot, &me) {
		return w32.UTF16PtrToString(&me.SzModule[0])
	}

	return "<UNKNOWN>"
}

// ListProcesses ---
func ListProcesses() []uint32 {
	sz := uint32(1000)
	procs := make([]uint32, sz)
	var bytesReturned uint32
	if w32.EnumProcesses(procs, sz, &bytesReturned) {
		return procs[:int(bytesReturned)/4]
	}
	return []uint32{}
}

// TODO: SWITCH TO MEMORYGO
// FindProcessByName ---
func FindProcessByName(name string) (uint32, error) {
	for _, pid := range ListProcesses() {
		if GetProcessName(pid) == name {
			return pid, nil
		}
	}
	return 0, fmt.Errorf("unknown process")
}

func main() {

	pid, err := FindProcessByName("notepad.exe")
	if err != nil {
		panic(err)
	}

	// dllName := input("DLL:")
	dir, err := os.Getwd()
	if err != nil {
		fmt.Println("OpenProcess failed")
		panic(err)
	}

	dll := dir + "\\" + "inject.dll"

	h, err := w32.OpenProcess(w32.PROCESS_ALL_ACCESS, false, pid)
	if err != nil {
		fmt.Println("OpenProcess failed")
		panic(err)
	}

	argAddress, err := w32.VirtualAllocEx(h, 0, len(dll), 0x1000|0x2000, w32.PAGE_READWRITE)
	if err != nil {
		fmt.Println("VirtualAllocEx failed")
		panic(err)
	}

	w32.WriteProcessMemory(h, uint32(argAddress), []byte(dll), uint(len(dll)))
	fmt.Println(uint32(loadLibraryA.Addr()), argAddress, dll, pid)
	w32.CreateRemoteThread(h, nil, 0, uint32(loadLibraryA.Addr()), argAddress, 0)
}
