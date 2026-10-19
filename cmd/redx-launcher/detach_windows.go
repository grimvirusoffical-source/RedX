//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

const createNoWindow = 0x08000000
const detachedProcess = 0x00000008

func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow | detachedProcess}
}

// showMessage shows a native message box (the launcher is a GUI-subsystem program: no console).
func showMessage(title, msg string) {
	u32 := syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW")
	t, _ := syscall.UTF16PtrFromString(title)
	m, _ := syscall.UTF16PtrFromString(msg)
	u32.Call(0, uintptr(unsafePtr(m)), uintptr(unsafePtr(t)), 0x10)
}
