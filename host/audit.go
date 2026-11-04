package host

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditEvent is one line of the JSON-lines audit log. It never contains key
// material; KeyID is the public 8-char lookup id.
type AuditEvent struct {
	Time   time.Time `json:"time"`
	Event  string    `json:"event"`
	KeyID  string    `json:"key_id,omitempty"`
	Actor  string    `json:"actor,omitempty"`  // acting owner (Red-XAI Account email) for owner.* events
	Target string    `json:"target,omitempty"` // what an owner request touched (database, account id, route)
	DB     string    `json:"db,omitempty"`
	Remote string    `json:"remote,omitempty"`
	Method string    `json:"method,omitempty"`
	Route  string    `json:"route,omitempty"`
	Reason string    `json:"reason,omitempty"`
	Detail string    `json:"detail,omitempty"`
}

// Auditor appends events to a file (size-rotated).
type Auditor struct {
	mu      sync.Mutex
	path    string
	f       auditSink
	size    int64
	maxSize int64
	failed  error
}

type auditSink interface {
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

// NewAuditor opens (appending) the log. path=="" discards events.
func NewAuditor(path string) (*Auditor, error) {
	a := &Auditor{path: path, maxSize: 50 << 20}
	if path == "" {
		return a, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := a.open(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *Auditor) open() error {
	f, err := os.OpenFile(a.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	if st != nil {
		a.size = st.Size()
		if st.Size() > 0 {
			// Preserve an interrupted append as evidence; do not join a new
			// privileged event onto an unterminated fragment after restart.
			reader, err := os.Open(a.path)
			if err != nil {
				a.failed = errors.New("audit tail unavailable")
			} else {
				var last [1]byte
				readInfo, statErr := reader.Stat()
				_, readErr := reader.ReadAt(last[:], st.Size()-1)
				reader.Close()
				if statErr != nil || readErr != nil || !os.SameFile(st, readInfo) {
					a.failed = errors.New("audit tail unavailable")
				} else if last[0] != '\n' {
					a.failed = errors.New("audit tail is incomplete")
				}
			}
		}
	}
	a.f = f
	return nil
}

// Log records a best-effort event. Privileged account authorization uses
// LogRequired so an unavailable sink cannot silently permit owner access.
func (a *Auditor) Log(ev AuditEvent) {
	_ = a.log(ev, false)
}

// LogRequired appends and syncs an event before privileged access is granted.
// Disabled, closed and failed sinks are errors, never successful audit writes.
// A successful Sync is an OS acknowledgment, not a power-loss recovery proof.
func (a *Auditor) LogRequired(ev AuditEvent) error { return a.log(ev, true) }

func (a *Auditor) log(ev AuditEvent, required bool) error {
	if a == nil {
		if required {
			return errors.New("audit unavailable")
		}
		return nil
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f == nil {
		if required {
			return errors.New("audit unavailable")
		}
		return nil
	}
	if a.failed != nil {
		return a.failed
	}
	if a.size+int64(len(b)) > a.maxSize {
		if err := a.f.Close(); err != nil {
			a.f = nil
			a.failed = err
			return err
		}
		a.f = nil
		if err := os.Rename(a.path, a.path+".1"); err != nil {
			// Keep the existing file untouched and require normal sink
			// reinitialization after an operator resolves the failure.
			a.failed = err
			return err
		}
		if err := a.open(); err != nil {
			a.failed = err
			return err
		}
	}
	n, err := a.f.Write(b)
	a.size += int64(n)
	if err != nil {
		a.failed = err
		return err
	}
	if n != len(b) {
		a.failed = io.ErrShortWrite
		return io.ErrShortWrite
	}
	if required {
		if err := a.f.Sync(); err != nil {
			a.failed = err
			return err
		}
	}
	return nil
}

// Close closes the file.
func (a *Auditor) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f == nil {
		return nil
	}
	err := a.f.Close()
	a.f = nil
	return err
}
