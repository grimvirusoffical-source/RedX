package host

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

type failingAuditSink struct {
	short    bool
	writeErr error
	syncErr  error
}

func (f failingAuditSink) Write(b []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	if f.short {
		return len(b) - 1, nil
	}
	return len(b), nil
}
func (f failingAuditSink) Sync() error  { return f.syncErr }
func (f failingAuditSink) Close() error { return nil }

func TestOwnerAuthenticationRejectsShortWriteAndWriteSyncErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		sink failingAuditSink
	}{
		{"short-write", failingAuditSink{short: true}},
		{"write-error", failingAuditSink{writeErr: errors.New("synthetic write failure")}},
		{"sync-error", failingAuditSink{syncErr: errors.New("synthetic sync failure")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			au := &Auditor{f: tc.sink, maxSize: 1 << 20}
			auth := NewAuthenticator(nil, au, 100, 100, false)
			pr := &Principal{Key: KeyRecord{ID: "acct:fixture-owner"}, Account: &AccountIdentity{Sub: "fixture-owner", Email: "owner@example.invalid", Owner: true}}
			r := httptest.NewRequest(http.MethodGet, "/v1/owner/dbs", nil)
			result, _, err := auth.accountResult(r, "127.0.0.1", pr)
			if !errors.Is(err, ErrAuditUnavailable) || result != nil || !pr.Account.Owner {
				t.Fatal("audit failure permitted access or silently demoted owner")
			}
			// A subsequent successful writer cannot hide a previous incomplete
			// append or uncertain sync in this auditor instance.
			au.f = failingAuditSink{}
			if result, _, err := auth.accountResult(r, "127.0.0.1", pr); !errors.Is(err, ErrAuditUnavailable) || result != nil {
				t.Fatal("failed audit sink silently resumed privileged access")
			}
		})
	}
}

func TestRequiredAuditPreservesAndRefusesIncompleteTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	fragment := []byte(`{"event":"interrupted`)
	if err := os.WriteFile(path, fragment, 0o600); err != nil {
		t.Fatal(err)
	}
	au, err := NewAuditor(path)
	if err != nil {
		t.Fatal(err)
	}
	defer au.Close()
	if au.LogRequired(AuditEvent{Event: "owner.read"}) == nil {
		t.Fatal("unterminated audit fragment accepted privileged access")
	}
	au.Log(AuditEvent{Event: "fixture.best-effort"})
	data, err := os.ReadFile(path)
	if err != nil || string(data) != string(fragment) {
		t.Fatal("incomplete evidence was changed or joined to a new event")
	}
}

func TestRequiredAuditSuccessfulRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	au, err := NewAuditor(path)
	if err != nil {
		t.Fatal(err)
	}
	defer au.Close()
	if err := au.LogRequired(AuditEvent{Event: "owner.read", Target: "db:first"}); err != nil {
		t.Fatal(err)
	}
	au.maxSize = au.size
	if err := au.LogRequired(AuditEvent{Event: "owner.read", Target: "db:second"}); err != nil {
		t.Fatal(err)
	}
	previous, err := os.ReadFile(path + ".1")
	if err != nil || !strings.Contains(string(previous), "db:first") {
		t.Fatal("rotation lost the previous event")
	}
	current, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(current), "db:second") {
		t.Fatal("rotation omitted the required new event")
	}
	if err := au.LogRequired(AuditEvent{Event: "owner.read", Target: "db:third"}); err != nil {
		t.Fatal(err)
	}
	previous, err = os.ReadFile(path + ".1")
	if err != nil || !strings.Contains(string(previous), "db:second") {
		t.Fatal("replacement rotation lost the previous event")
	}
}

func TestUnreadableAuditTailDisablesPrivilegeWithoutFailingAuditorStartup(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("requires non-root Unix permission enforcement")
	}
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, []byte("{}\n"), 0o200); err != nil {
		t.Fatal(err)
	}
	au, err := NewAuditor(path)
	if err != nil {
		t.Fatal("new tail guard prevented ordinary service startup")
	}
	defer au.Close()
	if err := au.LogRequired(AuditEvent{Event: "owner.read"}); err == nil {
		t.Fatal("unreadable audit tail accepted owner access")
	}
}

func TestRequiredAuditRejectsDisabledClosedAndFailedRotation(t *testing.T) {
	ev := AuditEvent{Event: "owner.read", KeyID: "acct:fixture-owner", Target: "db:fixture"}
	var absent *Auditor
	if absent.LogRequired(ev) == nil {
		t.Fatal("nil sink accepted privileged audit")
	}
	disabled, err := NewAuditor("")
	if err != nil || disabled.LogRequired(ev) == nil {
		t.Fatal("disabled sink accepted privileged audit")
	}
	path := filepath.Join(t.TempDir(), "audit.log")
	au, err := NewAuditor(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := au.Close(); err != nil || au.LogRequired(ev) == nil {
		t.Fatal("closed sink accepted privileged audit")
	}
	au, err = NewAuditor(path)
	if err != nil {
		t.Fatal(err)
	}
	defer au.Close()
	if err := os.Mkdir(path+".1", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path+".1", "fixture"), []byte("synthetic"), 0o600); err != nil {
		t.Fatal(err)
	}
	au.maxSize = 1
	if err := au.LogRequired(ev); err == nil {
		t.Fatal("failed rotation accepted privileged audit")
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) != 0 {
		t.Fatal("failed rotation reported an unrecorded event")
	}
}

func TestRequiredAuditConcurrentCloseAndAppend(t *testing.T) {
	au, err := NewAuditor(filepath.Join(t.TempDir(), "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = au.LogRequired(AuditEvent{Event: "owner.read", Target: "db:fixture"})
			au.Log(AuditEvent{Event: "fixture.best-effort"})
		}()
	}
	if err := au.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if err := au.LogRequired(AuditEvent{Event: "owner.read"}); err == nil {
		t.Fatal("closed sink accepted later privileged event")
	}
}

func TestRequiredAuditWritesCompleteAttributedEvent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	au, err := NewAuditor(path)
	if err != nil {
		t.Fatal(err)
	}
	defer au.Close()
	if err := au.LogRequired(AuditEvent{Event: "owner.write", KeyID: "acct:fixture-owner", Actor: "owner@example.invalid", Target: "db:fixture", Method: "POST"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var ev AuditEvent
	if !strings.HasSuffix(string(data), "\n") || json.Unmarshal(data, &ev) != nil || ev.Time.IsZero() || ev.KeyID != "acct:fixture-owner" || ev.Target != "db:fixture" || ev.Actor != "owner@example.invalid" {
		t.Fatal("required event attribution missing")
	}
}
