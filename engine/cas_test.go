package engine

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"redx/box"
)

const casPath = "ledger.red-xai.db:Record[ID=1]"

func TestRecordCASConcurrentCreateAndReplace(t *testing.T) {
	db := open(t, t.TempDir(), Config{Durability: "group"})
	defer db.Close()
	race := func(expected *box.Value, next box.Value) {
		t.Helper()
		var wins atomic.Int64
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < 32; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				err := db.CompareAndSwap(casPath, expected, next)
				if err == nil {
					wins.Add(1)
				} else if !errors.Is(err, ErrConflict) {
					t.Errorf("CAS: %v", err)
				}
			}()
		}
		close(start)
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatalf("successful writers = %d", wins.Load())
		}
	}
	one := box.String("revision1")
	race(nil, one)
	race(&one, box.String("revision2"))
	if v, err := db.Get(casPath); err != nil || v.Str != "revision2" {
		t.Fatalf("record: %v %v", v, err)
	}
}

func TestRecordCASDetectsOrdinarySubfieldWrites(t *testing.T) {
	db := open(t, t.TempDir(), Config{})
	defer db.Close()
	one, _ := box.ParseValue(`[ {revision[]} = 1, {payload[]} = "before" ]`)
	if err := db.CompareAndSwap(casPath, nil, one); err != nil {
		t.Fatal(err)
	}
	mustSet(t, db, casPath+".payload", box.String("ordinary-write"), SetOpts{})
	two, _ := box.ParseValue(`[ {revision[]} = 2, {payload[]} = "stale-cas" ]`)
	if err := db.CompareAndSwap(casPath, &one, two); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale whole record: %v", err)
	}
	v, err := db.Get(casPath + ".payload")
	if err != nil || v.Str != "ordinary-write" {
		t.Fatalf("ordinary write lost: %v %v", v, err)
	}
}

func TestRecordCASAcknowledgedValuesSurviveCrash(t *testing.T) {
	for _, durability := range []string{"sync", "group"} {
		t.Run(durability, func(t *testing.T) {
			dir := t.TempDir()
			db := open(t, dir, Config{Durability: durability})
			one := box.String("one")
			two := box.String("two: \"quoted\"\n雪")
			if err := db.CompareAndSwap(casPath, nil, one); err != nil {
				t.Fatal(err)
			}
			if err := db.CompareAndSwap(casPath, &one, two); err != nil {
				t.Fatal(err)
			}
			db.crash() // no Close/Checkpoint flush can manufacture durability
			db = open(t, dir, Config{Durability: durability})
			defer db.Close()
			v, err := db.Get(casPath)
			if err != nil || !v.Equal(two) {
				t.Fatalf("acknowledged value lost: %v %v", v, err)
			}
		})
	}
}

func TestRecordCASTornLastFrameKeepsWholePreviousRecord(t *testing.T) {
	dir := t.TempDir()
	db := open(t, dir, Config{Durability: "sync"})
	one, _ := box.ParseValue(`[ {revision[]} = 1, {payload[]} = "old" ]`)
	two, _ := box.ParseValue(`[ {revision[]} = 2, {payload[]} = "new" ]`)
	if err := db.CompareAndSwap(casPath, nil, one); err != nil {
		t.Fatal(err)
	}
	wal := walFile(t, dir, "ledger.red-xai.db")
	first, err := os.Stat(wal)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CompareAndSwap(casPath, &one, two); err != nil {
		t.Fatal(err)
	}
	last, err := os.Stat(wal)
	if err != nil {
		t.Fatal(err)
	}
	db.crash()
	for _, cut := range []int64{first.Size() + 1, (first.Size() + last.Size()) / 2, last.Size() - 1} {
		copy := filepath.Join(t.TempDir(), "db")
		copyDir(t, dir, copy)
		if err := os.Truncate(filepath.Join(copy, filepath.Base(wal)), cut); err != nil {
			t.Fatal(err)
		}
		recovered := open(t, copy, Config{})
		v, err := recovered.Get(casPath)
		if err != nil || !v.Equal(one) {
			t.Fatalf("cut %d: partial replacement %v %v", cut, v, err)
		}
		recovered.Close()
	}
}

func TestRecordCASRejectsUnsafePathsDurabilityAndFollower(t *testing.T) {
	db := open(t, t.TempDir(), Config{})
	defer db.Close()
	for _, p := range []string{"Record[ID=1]", "ledger:Record[ID=1]", "ledger.red-xai.db:Record[ID=1].payload", "ledger.red-xai.db:Record[ID=*]", "ledger.red-xai.db:Record[ID=01]", `"ledger.red-xai.db":Record[ID=1]`, "ledger.red-xai-db-qs:Record[ID=1]"} {
		if err := db.CompareAndSwap(p, nil, box.String("bad")); !errors.Is(err, ErrBadPath) {
			t.Errorf("path %q: %v", p, err)
		}
	}
	async := open(t, t.TempDir(), Config{Durability: "async"})
	defer async.Close()
	if err := async.CompareAndSwap(casPath, nil, box.String("bad")); !errors.Is(err, ErrCASDurability) {
		t.Fatalf("async: %v", err)
	}
	if _, err := async.Get(casPath); !errors.Is(err, ErrNotFound) {
		t.Fatalf("async wrote: %v", err)
	}
	follower := open(t, t.TempDir(), Config{Follower: true})
	defer follower.Close()
	if err := follower.CompareAndSwap(casPath, nil, box.String("bad")); !errors.Is(err, ErrFollower) {
		t.Fatalf("follower: %v", err)
	}
}

func TestRecordCASDoesNotAcknowledgeSyncFailure(t *testing.T) {
	db := open(t, t.TempDir(), Config{Durability: "sync"})
	defer db.Close()
	first := box.String("one")
	if err := db.CompareAndSwap(casPath, nil, first); err != nil {
		t.Fatal(err)
	}
	table := db.tableList()[0]
	table.p.ioHook = func(op string, _ *os.File, _ []byte) error {
		if op == "sync" {
			return errors.New("fixture fsync failure")
		}
		return nil
	}
	if err := db.CompareAndSwap(casPath, &first, box.String("two")); err == nil {
		t.Fatal("failed sync acknowledged")
	}
	if _, err := db.ReadCASRecord(casPath); !errors.Is(err, ErrFailed) {
		t.Fatalf("uncertain WAL state was readable: %v", err)
	}
	if err := db.CompareAndSwap(casPath, nil, box.String("three")); !errors.Is(err, ErrFailed) {
		t.Fatalf("failed table accepted another write: %v", err)
	}
}

func TestRecordCASDoesNotResolveAnExtendedFilename(t *testing.T) {
	db := open(t, t.TempDir(), Config{Durability: "sync"})
	defer db.Close()
	extended := "ledger.red-xai.db.other.red-xai.db:Record[ID=1]"
	mustSet(t, db, extended, box.String("other-file"), SetOpts{})
	if _, err := db.ReadCASRecord(casPath); !errors.Is(err, ErrNotFound) {
		t.Fatalf("read escaped exact filename: %v", err)
	}
	other := box.String("other-file")
	if err := db.CompareAndSwap(casPath, &other, box.String("wrong")); !errors.Is(err, ErrConflict) {
		t.Fatalf("update resolved alias: %v", err)
	}
	if err := db.CompareAndSwap(casPath, nil, box.String("exact-file")); err != nil {
		t.Fatal(err)
	}
	if v, err := db.ReadCASRecord(casPath); err != nil || v.Str != "exact-file" {
		t.Fatalf("exact record: %v %v", v, err)
	}
	if v, err := db.Get(extended); err != nil || v.Str != "other-file" {
		t.Fatalf("other namespace overwritten: %v %v", v, err)
	}
}

func TestRecordCASReadWaitsForGroupDurability(t *testing.T) {
	db := open(t, t.TempDir(), Config{Durability: "group"})
	defer db.Close()
	one := box.String("one")
	if err := db.CompareAndSwap(casPath, nil, one); err != nil {
		t.Fatal(err)
	}
	table := db.tableList()[0]
	syncing, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	table.p.ioHook = func(op string, _ *os.File, _ []byte) error {
		if op == "sync" {
			close(syncing)
			<-release
		}
		return nil
	}
	written := make(chan error, 1)
	go func() { written <- db.CompareAndSwap(casPath, &one, box.String("two")) }()
	select {
	case <-syncing:
	case <-time.After(time.Second):
		t.Fatal("group sync did not begin")
	}
	type readResult struct {
		v   box.Value
		err error
	}
	read := make(chan readResult, 1)
	go func() { v, err := db.ReadCASRecord(casPath); read <- readResult{v, err} }()
	select {
	case r := <-read:
		t.Fatalf("unflushed state escaped: %v %v", r.v, r.err)
	case <-time.After(30 * time.Millisecond):
	}
	unblock()
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	r := <-read
	if r.err != nil || r.v.Str != "two" {
		t.Fatalf("durable snapshot: %v %v", r.v, r.err)
	}
}

func TestRecordCASAbsentReadWaitsForDeleteDurability(t *testing.T) {
	db := open(t, t.TempDir(), Config{Durability: "group"})
	defer db.Close()
	if err := db.CompareAndSwap(casPath, nil, box.String("retained-ledger")); err != nil {
		t.Fatal(err)
	}
	table := db.tableList()[0]
	syncing, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	table.p.ioHook = func(op string, _ *os.File, _ []byte) error {
		if op == "sync" {
			close(syncing)
			<-release
			return errors.New("fixture delete fsync failure")
		}
		return nil
	}
	deleted := make(chan error, 1)
	go func() { deleted <- db.Delete(casPath) }()
	select {
	case <-syncing:
	case <-time.After(time.Second):
		t.Fatal("delete sync did not begin")
	}
	read := make(chan error, 1)
	go func() { _, err := db.ReadCASRecord(casPath); read <- err }()
	select {
	case err := <-read:
		t.Fatalf("unflushed deletion looked like authoritative absence: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	unblock()
	if err := <-deleted; err == nil {
		t.Fatal("failed delete sync acknowledged")
	}
	if err := <-read; !errors.Is(err, ErrFailed) {
		t.Fatalf("failed deletion became empty ledger: %v", err)
	}
}
