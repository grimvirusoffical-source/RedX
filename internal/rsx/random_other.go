//go:build !linux && !windows

package rsx

func osRandom(b []byte) error { return urandom(b) }
