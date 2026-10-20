//go:build windows

package rsx

import (
	"syscall"
	"unsafe"
)

var (
	advapi32  = syscall.NewLazyDLL("advapi32.dll")
	rtlGenRnd = advapi32.NewProc("SystemFunction036") // RtlGenRandom
)

func osRandom(b []byte) error {
	for len(b) > 0 {
		n := len(b)
		if n > 1<<30 {
			n = 1 << 30
		}
		r, _, e := rtlGenRnd.Call(uintptr(unsafe.Pointer(&b[0])), uintptr(n))
		if r == 0 {
			return e
		}
		b = b[n:]
	}
	return nil
}
