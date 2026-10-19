//go:build !windows

package main

import (
	"os/exec"
	"runtime"
	"syscall"
)

func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

func showMessage(title, msg string) {
	if runtime.GOOS == "darwin" {
		_ = exec.Command("osascript", "-e", `display alert "`+title+`" message "`+msg+`"`).Run()
	}
}
