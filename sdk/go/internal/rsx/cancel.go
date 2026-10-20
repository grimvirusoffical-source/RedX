package rsx

import "sync/atomic"

func loadCancel(p *int32) bool { return atomic.LoadInt32(p) != 0 }
