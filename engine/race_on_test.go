//go:build race

package engine

// raceEnabled: the race detector slows every memory access several times over, so latency budgets widen.
const raceEnabled = true
