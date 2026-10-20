//go:build linux

package rsx

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// memAvailableKiB reads MemAvailable from /proc/meminfo (0 if unknown).
func memAvailableKiB() uint64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := sc.Text()
		if strings.HasPrefix(l, "MemAvailable:") {
			fs := strings.Fields(l)
			if len(fs) >= 2 {
				v, _ := strconv.ParseUint(fs[1], 10, 64)
				return v
			}
		}
	}
	return 0
}
