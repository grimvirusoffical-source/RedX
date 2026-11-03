package engine

import (
	"errors"
	"fmt"
	"strings"

	"redx/box"
)

// ErrCASDurability means an acknowledged CAS cannot promise durable storage.
var ErrCASDurability = errors.New("engine: record CAS requires sync or group durability")

func recordCASPath(path string) (box.Path, error) {
	p, err := box.ParsePath(path)
	if err != nil || p.String() != path || !strings.HasSuffix(p.File, ".red-xai.db") || len(p.Segs) != 1 || p.HasWild() {
		return p, fmt.Errorf("%w: CAS requires a canonical full persistent record path", ErrBadPath)
	}
	return p, nil
}

// ReadCASRecord reads exactly the named durable file and whole record. Unlike
// normal convenience reads, a missing full filename never resolves to another
// file with that prefix. A failed WAL table cannot supply authoritative state.
func (db *Database) ReadCASRecord(path string) (box.Value, error) {
	if db.closed.Load() {
		return box.Value{}, ErrClosed
	}
	p, err := recordCASPath(path)
	if err != nil {
		return box.Value{}, err
	}
	db.mu.RLock()
	t := db.tables[p.File]
	db.mu.RUnlock()
	if t == nil {
		return box.Value{}, ErrNotFound
	}
	t.mu.RLock()
	if t.closed {
		t.mu.RUnlock()
		return box.Value{}, ErrClosed
	}
	if t.failed != nil {
		err := t.failed
		t.mu.RUnlock()
		return box.Value{}, err
	}
	if t.typ != ftCold || t.p == nil || t.p.dur == durAsync {
		t.mu.RUnlock()
		return box.Value{}, ErrCASDurability
	}
	e, ok := t.resolveExact(p.Segs)
	var value box.Value
	if ok {
		value = e.Value.Clone()
	}
	// The in-memory commit becomes visible before group fsync completes. Tie
	// every snapshot, including an absence caused by Delete, to its WAL ticket
	// and wait without holding the table lock. Failed deletes are not empty state.
	t.p.mu.Lock()
	ticket, walErr := t.p.seq, t.p.err
	t.p.mu.Unlock()
	t.mu.RUnlock()
	if walErr != nil {
		return box.Value{}, fmt.Errorf("%w: %v", ErrFailed, walErr)
	}
	if err := t.p.wait(ticket); err != nil {
		return box.Value{}, fmt.Errorf("%w: %v", ErrFailed, err)
	}
	if !ok {
		return box.Value{}, ErrNotFound
	}
	t.nGet.Add(1)
	return value, nil
}

// CompareAndSwap replaces one complete persistent record iff its value still
// equals expected. A nil expected means the record must not exist; NELL is a
// stored value, not an absence marker. Comparison and replacement share the
// native table commit lock and one WAL frame, including against REST/BoxQL
// writers. Successful returns have passed the sync/group WAL durability wait.
// No wildcard, file alias, subfield, TTL file or async durability is accepted.
func (db *Database) CompareAndSwap(path string, expected *box.Value, replacement box.Value) error {
	if db.closed.Load() {
		return ErrClosed
	}
	if db.isFollower() {
		return ErrFollower
	}
	p, err := recordCASPath(path)
	if err != nil {
		return err
	}
	if db.dur == durAsync {
		return ErrCASDurability
	}
	db.mu.RLock()
	t := db.tables[p.File]
	db.mu.RUnlock()
	if t == nil {
		if expected != nil {
			return ErrConflict
		}
		t, err = db.createTable(p.File)
		if err != nil {
			return err
		}
	}
	if t.typ != ftCold || t.p == nil || t.p.dur == durAsync {
		return ErrCASDurability
	}
	op, err := t.prepareOp(p.Segs, replacement, SetOpts{}, t.now())
	if err != nil {
		return err
	}
	var want *box.Value
	if expected != nil {
		v := expected.Clone()
		want = &v
	}
	pre := func() error {
		if db.isFollower() {
			return ErrFollower
		}
		current, exists := t.resolveExact(p.Segs)
		if (want == nil && exists) || (want != nil && (!exists || !current.Value.Equal(*want))) {
			t.nConflict.Add(1)
			return ErrConflict
		}
		return nil
	}
	t.nTxn.Add(1)
	return t.commit([]Op{op}, commitMode{pre: pre})
}
