package main

import (
	"fmt"
	"os"
	"syscall"

	"github.com/JamesHovious/w32"
	memory "github.com/eidyz/memorygo"
	"golang.org/x/sys/windows"
)

var modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
var hKernel32 = modkernel32.Handle()
var getModuleHandleA = modkernel32.NewProc("GetModuleHandleA")
var loadLibraryA = modkernel32.NewProc("LoadLibraryA")

func input(q string) string {
	var s string
	fmt.Println(q)
	fmt.Scanln(&s)
	return s
}

func main() {
	processName := input("Process name: ")
	pid, err := memory.FindProcessByName(processName)
	if err != nil {
		panic(err)
	}

	dir, err := os.Getwd()
	if err != nil {
		fmt.Println("Resolving current directory failed")
		panic(err)
	}

	dll := dir + "\\" + "inject.dll"

	h, err := w32.OpenProcess(w32.PROCESS_QUERY_INFORMATION|w32.PROCESS_CREATE_THREAD|w32.PROCESS_VM_OPERATION|w32.PROCESS_VM_WRITE, false, pid)
	if err != nil {
		fmt.Println("OpenProcess failed")
		panic(err)
	}

	argAddress, err := w32.VirtualAllocEx(h, 0, len(dll), w32.MEM_COMMIT, w32.PAGE_READWRITE)
	if err != nil {
		fmt.Println("VirtualAllocEx failed")
		panic(err)
	}
	fmt.Println("Arg adress:", argAddress)
	bytesW := w32.WriteProcessMemory(h, uint32(argAddress), []byte(dll), uint(len(dll)))
	fmt.Println("Bytes written:", bytesW)

	loadLib, err := syscall.GetProcAddress(syscall.Handle(hKernel32), "LoadLibraryA")
	if err != nil {
		fmt.Println("GetProcAddress failed")
		panic(err)
	}

	_, threadId, err := w32.CreateRemoteThread(h, nil, 0, uint32(loadLib), argAddress, 0)
	if err != nil {
		fmt.Println("CreateRemoteThread failed")
		panic(err)
	}
	fmt.Println("Thread ID:", threadId)
	w32.CloseHandle(h)
}
