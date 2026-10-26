//go:build !linux

package rsx

func memAvailableKiB() uint64 { return 0 }
