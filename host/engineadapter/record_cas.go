package engineadapter

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"

	"redx/box"
	"redx/engine"
	"redx/host"
)

var recordKeyRE = regexp.MustCompile(`^[A-Za-z0-9_-]{3,64}$`)

var _ host.RecordCASBackend = (*store)(nil)

func recordPath(path string) error {
	p, err := box.ParsePath(path)
	if err != nil || p.String() != path || !strings.HasSuffix(p.File, ".red-xai.db") || len(p.Segs) != 1 || p.HasWild() {
		return fmt.Errorf("%w: record CAS requires a canonical full persistent record path", host.ErrInvalid)
	}
	return nil
}

func recordValue(record host.CASRecord) (box.Value, error) {
	if !recordKeyRE.MatchString(record.Key) || record.Revision == 0 || record.Revision > host.MaxRecordRevision {
		return box.Value{}, fmt.Errorf("%w: invalid record key or revision", host.ErrInvalid)
	}
	b := box.NewBox()
	b.Put(&box.Entry{Key: "key", Value: box.String(record.Key)})
	b.Put(&box.Entry{Key: "revision", Value: box.Int(int64(record.Revision))})
	b.Put(&box.Entry{Key: "payload", Value: box.String(record.Payload)})
	return box.BoxValue(b), nil
}

func decodeRecord(v box.Value) (host.CASRecord, error) {
	r := host.CASRecord{}
	if v.Kind != box.KindBox || v.Box == nil || v.Box.Len() != 3 || v.Box.HasFlag || len(v.Box.Meta) != 0 {
		return r, host.ErrCorrupt
	}
	for _, e := range v.Box.Entries() {
		if len(e.Attrs) != 0 || e.TTL.Kind != box.TTLNone {
			return r, host.ErrCorrupt
		}
		switch e.Key {
		case "key":
			if e.Value.Kind != box.KindString {
				return r, host.ErrCorrupt
			}
			r.Key = e.Value.Str
		case "revision":
			if e.Value.Kind != box.KindNumber || math.IsNaN(e.Value.Num) || math.IsInf(e.Value.Num, 0) || e.Value.Num < 1 || e.Value.Num > float64(host.MaxRecordRevision) || math.Trunc(e.Value.Num) != e.Value.Num {
				return r, host.ErrCorrupt
			}
			r.Revision = uint64(e.Value.Num)
		case "payload":
			if e.Value.Kind != box.KindString {
				return r, host.ErrCorrupt
			}
			r.Payload = e.Value.Str
		default:
			return r, host.ErrCorrupt
		}
	}
	if !recordKeyRE.MatchString(r.Key) || r.Revision == 0 {
		return r, host.ErrCorrupt
	}
	return r, nil
}

func (s *store) casAvailable(path string) error {
	if err := recordPath(path); err != nil {
		return err
	}
	if strings.EqualFold(s.cfg.Durability, "async") || s.hasRules.Load() {
		return fmt.Errorf("%w: record CAS requires durable storage without active Pulse rules", host.ErrUnavailable)
	}
	p, _ := box.ParsePath(path)
	files := s.db.Files()
	// Native Txn.Get records absence only after binding to an existing file.
	// Explicit provisioning prevents a missing full filename from resolving to
	// a similarly prefixed file, and isolates checkpoint maintenance from any
	// unrelated data. Provision a separate Bridge database, never the legacy
	// canonical account store. No file or application record is auto-created.
	if len(files) != 1 || files[p.File] != "cold" {
		return fmt.Errorf("%w: provision exactly one persistent ledger file in an isolated database", host.ErrUnavailable)
	}
	return nil
}

func (s *store) casReadAllowed(p host.SecPrincipal, path string, value box.Value) error {
	text := value.String()
	filtered, err := s.SecRead(p, path, text)
	if err != nil {
		return err
	}
	if filtered != text {
		return host.ErrForbidden
	} // no partial envelopes
	return nil
}

func (s *store) ReadCASRecord(p host.SecPrincipal, path string) (host.CASRecord, error) {
	if err := s.casAvailable(path); err != nil {
		return host.CASRecord{}, err
	}
	for attempt := 0; attempt < 4; attempt++ {
		tx := s.db.Begin()
		v, readErr := tx.Get(path)
		if readErr != nil && !errors.Is(readErr, engine.ErrNotFound) {
			tx.Rollback()
			return host.CASRecord{}, mapErr(readErr)
		}
		if readErr == nil {
			if err := s.casReadAllowed(p, path, v); err != nil {
				tx.Rollback()
				return host.CASRecord{}, err
			}
		}
		// Existing read methods can see a group commit before fsync or even a
		// failed WAL's in-memory state. Checkpoint flushes all captured writes
		// and detects failed/closed files. Commit then verifies that the exact
		// snapshot (including absence) remained valid during that barrier.
		if err := s.db.Checkpoint(); err != nil {
			tx.Rollback()
			return host.CASRecord{}, fmt.Errorf("%w: ledger durability barrier failed", host.ErrUnavailable)
		}
		if err := tx.Commit(); err != nil {
			if errors.Is(err, engine.ErrConflict) {
				continue
			}
			return host.CASRecord{}, mapErr(err)
		}
		if readErr != nil {
			return host.CASRecord{}, host.ErrNotFound
		}
		return decodeRecord(v)
	}
	return host.CASRecord{}, fmt.Errorf("%w: ledger changed during durability verification", host.ErrUnavailable)
}

func (s *store) CompareAndSwapRecord(p host.SecPrincipal, path string, expectedRevision uint64, next host.CASRecord) (uint64, error) {
	if err := s.casAvailable(path); err != nil {
		return 0, err
	}
	if expectedRevision >= host.MaxRecordRevision || next.Revision != expectedRevision+1 {
		return 0, fmt.Errorf("%w: next revision must increase by exactly one", host.ErrInvalid)
	}
	v, err := recordValue(next)
	if err != nil {
		return 0, err
	}
	if err := s.casReadAllowed(p, path, v); err != nil {
		return 0, err
	}
	if err := s.SecWrite(p, path, v.String(), false); err != nil {
		return 0, err
	}
	tx := s.db.Begin()
	defer tx.Rollback()
	current, err := tx.Get(path)
	if err == nil {
		if err := s.casReadAllowed(p, path, current); err != nil {
			return 0, err
		}
		r, err := decodeRecord(current)
		if err != nil {
			return 0, err
		}
		if expectedRevision == 0 || r.Revision != expectedRevision || r.Key != next.Key {
			return 0, host.ErrConflict
		}
	} else if !errors.Is(err, engine.ErrNotFound) {
		return 0, mapErr(err)
	} else if expectedRevision != 0 {
		return 0, host.ErrConflict
	}
	if err := tx.Set(path, v, engine.SetOpts{}); err != nil {
		return 0, mapErr(err)
	}
	// The unchanged native engine validates the observed record version under
	// its own table lock, including against ordinary REST/BoxQL writers, and
	// persists this complete replacement in one synchronous/group WAL frame.
	if err := tx.Commit(); err != nil {
		switch {
		case errors.Is(err, engine.ErrConflict):
			return 0, host.ErrConflict
		default:
			return 0, mapErr(err)
		}
	}
	s.observePath(path)
	// The host commit hook may fail independently of the native WAL. Capture
	// the exact file's existing native LSN instead of an unrelated host offset.
	// A concurrent ordinary writer may be included; checkpoint after capture
	// makes this a durable watermark covering at least our committed write.
	parsed, _ := box.ParsePath(path)
	_, localSeq, err := s.db.ExportSnapshot(parsed.File)
	if err != nil || localSeq == 0 || localSeq > host.MaxRecordRevision {
		return 0, fmt.Errorf("%w: record committed but native watermark capture failed", host.ErrUnavailable)
	}
	if err := s.db.Checkpoint(); err != nil {
		return 0, fmt.Errorf("%w: record committed but native watermark durability barrier failed", host.ErrUnavailable)
	}
	return localSeq, nil
}
