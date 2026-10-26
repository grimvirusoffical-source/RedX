//go:build linux

package rsx

import (
	"syscall"
	"unsafe"
)

// getrandom(2) syscall numbers.
var sysGetrandom = map[string]uintptr{"amd64": 318, "arm64": 278, "386": 355, "arm": 384, "riscv64": 278, "ppc64le": 359, "s390x": 349, "loong64": 278, "mips64le": 5313}

func osRandom(b []byte) error {
	nr, ok := sysGetrandom[goarch]
	if !ok {
		return urandom(b)
	}
	for len(b) > 0 {
		n, _, e := syscall.Syscall(nr, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0)
		if e == syscall.EINTR {
			continue
		}
		if e == syscall.ENOSYS {
			return urandom(b)
		}
		if e != 0 {
			return e
		}
		b = b[n:]
	}
	return nil
}
