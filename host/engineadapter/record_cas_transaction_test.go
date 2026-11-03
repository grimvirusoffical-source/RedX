package engineadapter

import (
	"errors"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"
	"unsafe"

	"redx/box"
	"redx/engine"
	"redx/host"
)

const txnRecordPath = "rxa-bridge-platform.red-xai.db:Record[ID=42]"
const txnRecordFile = "rxa-bridge-platform.red-xai.db"

func transactionFixture(t *testing.T, mode string) *store {
	t.Helper()
	b, err := Opener(Config{Durability: mode})(t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	s := b.(*store)
	t.Cleanup(func() { _ = s.Close() })
	if err := s.db.Set(txnRecordFile+":Record[ID=0]", box.String("isolated fixture bootstrap"), engine.SetOpts{}); err != nil {
		t.Fatal(err)
	}
	return s
}

// The engine already contains an internal test I/O seam. Access that seam only
// in this fixture test so engine files, production APIs and formats stay intact.
// Each pointer belongs exclusively to the native database opened in t.TempDir.
func fixtureWalHook(t *testing.T, s *store, hook func(string, *os.File, []byte) error) {
	t.Helper()
	tables := reflect.ValueOf(s.db).Elem().FieldByName("tables")
	table := tables.MapIndex(reflect.ValueOf(txnRecordFile))
	if !table.IsValid() {
		t.Fatal("fixture table missing")
	}
	field := table.Elem().FieldByName("p").Elem().FieldByName("ioHook")
	if !field.IsValid() || !field.CanAddr() {
		t.Fatal("fixture I/O seam unavailable")
	}
	reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Set(reflect.ValueOf(hook))
}

func TestRecordCASTransactionDurableValueAndAbsenceBarrier(t *testing.T) {
	for _, missing := range []bool{false, true} {
		for _, fail := range []bool{false, true} {
			name := "value"
			if missing {
				name = "absence"
			}
			if fail {
				name += "-wal-failure"
			}
			t.Run(name, func(t *testing.T) {
				s := transactionFixture(t, "group")
				v, _ := recordValue(host.CASRecord{Key: "bridge-platform-v1", Revision: 1, Payload: "durable-before"})
				if missing {
					if err := s.db.Set(txnRecordPath, v, engine.SetOpts{}); err != nil {
						t.Fatal(err)
					}
				}
				entered, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				var releaseOnce sync.Once
				t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
				fixtureWalHook(t, s, func(op string, _ *os.File, _ []byte) error {
					first := false
					if op == "sync" {
						once.Do(func() { first = true; close(entered); <-release })
					}
					if first && fail {
						return errors.New("fixture fsync failure")
					}
					return nil
				})
				writeDone := make(chan error, 1)
				go func() {
					if missing {
						writeDone <- s.db.Delete(txnRecordPath)
					} else {
						writeDone <- s.db.Set(txnRecordPath, v, engine.SetOpts{})
					}
				}()
				select {
				case <-entered:
				case <-time.After(3 * time.Second):
					t.Fatal("writer never reached fsync")
				}
				readDone := make(chan error, 1)
				go func() {
					r, err := s.ReadCASRecord(host.SecPrincipal{}, txnRecordPath)
					if !missing && err == nil && r.Payload != "durable-before" {
						err = errors.New("unexpected value")
					}
					readDone <- err
				}()
				select {
				case err := <-readDone:
					t.Fatalf("read escaped pending fsync: %v", err)
				case <-time.After(30 * time.Millisecond):
				}
				releaseOnce.Do(func() { close(release) })
				select {
				case err := <-writeDone:
					if (err != nil) != fail {
						t.Fatalf("write error=%v fail=%v", err, fail)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("writer hung")
				}
				select {
				case err := <-readDone:
					if fail && !errors.Is(err, host.ErrUnavailable) {
						t.Fatalf("failed WAL must refuse value/absence: %v", err)
					}
					if !fail && missing && !errors.Is(err, host.ErrNotFound) {
						t.Fatalf("durable absence: %v", err)
					}
					if !fail && !missing && err != nil {
						t.Fatal(err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("read barrier hung")
				}
			})
		}
	}
}

func TestRecordCASTransactionNativeConcurrencyAndIsolation(t *testing.T) {
	s := transactionFixture(t, "group")
	var wg sync.WaitGroup
	out := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out <- s.CompareAndSwapRecord(host.SecPrincipal{}, txnRecordPath, 0, host.CASRecord{Key: "bridge-platform-v1", Revision: 1, Payload: "winner"})
		}()
	}
	wg.Wait()
	close(out)
	wins, conflicts := 0, 0
	for err := range out {
		if err == nil {
			wins++
		} else if errors.Is(err, host.ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if wins != 1 || conflicts != 15 {
		t.Fatalf("winners=%d conflicts=%d", wins, conflicts)
	}
	if err := s.db.Set("unrelated.red-xai.db:Other[ID=1]", box.Int(1), engine.SetOpts{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadCASRecord(host.SecPrincipal{}, txnRecordPath); !errors.Is(err, host.ErrUnavailable) {
		t.Fatalf("mixed database accepted: %v", err)
	}
}

func TestRecordCASTransactionRequiresExactProvisionedFile(t *testing.T) {
	b, err := Opener(Config{Durability: "sync"})(t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	s := b.(*store)
	defer s.Close()
	if _, err := s.ReadCASRecord(host.SecPrincipal{}, txnRecordPath); !errors.Is(err, host.ErrUnavailable) {
		t.Fatalf("unprovisioned file accepted: %v", err)
	}
	alias := txnRecordFile + ".red-xai.db:Record[ID=42]"
	if err := s.db.Set(alias, box.String("must not alias"), engine.SetOpts{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadCASRecord(host.SecPrincipal{}, txnRecordPath); !errors.Is(err, host.ErrUnavailable) {
		t.Fatalf("missing full name aliased: %v", err)
	}
	if len(s.db.Files()) != 1 {
		t.Fatal("read created a table")
	}
}
