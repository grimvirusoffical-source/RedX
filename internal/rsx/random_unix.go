//go:build !windows

package rsx

import (
	"io"
	"os"
	"runtime"
)

var goarch = runtime.GOARCH

func urandom(b []byte) error {
	f, err := os.Open("/dev/urandom")
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.ReadFull(f, b)
	return err
}
