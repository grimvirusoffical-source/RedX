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
		// Never silently omit configured Pulse side effects or promise fsync
		// under async durability. This isolated ledger primitive runs no rules.
		return fmt.Errorf("%w: record CAS requires durable storage without active Pulse rules", host.ErrUnavailable)
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
	v, err := s.db.ReadCASRecord(path)
	if err != nil {
		return host.CASRecord{}, mapErr(err)
	}
	if err := s.casReadAllowed(p, path, v); err != nil {
		return host.CASRecord{}, err
	}
	return decodeRecord(v)
}

func (s *store) CompareAndSwapRecord(p host.SecPrincipal, path string, expectedRevision uint64, next host.CASRecord) error {
	if err := s.casAvailable(path); err != nil {
		return err
	}
	if expectedRevision >= host.MaxRecordRevision || next.Revision != expectedRevision+1 {
		return fmt.Errorf("%w: next revision must increase by exactly one", host.ErrInvalid)
	}
	v, err := recordValue(next)
	if err != nil {
		return err
	}
	if err := s.casReadAllowed(p, path, v); err != nil {
		return err
	}
	if err := s.SecWrite(p, path, v.String(), false); err != nil {
		return err
	}
	var previous *box.Value
	current, err := s.db.ReadCASRecord(path)
	if err == nil {
		if err := s.casReadAllowed(p, path, current); err != nil {
			return err
		}
		r, err := decodeRecord(current)
		if err != nil {
			return err
		}
		if expectedRevision == 0 || r.Revision != expectedRevision || r.Key != next.Key {
			return host.ErrConflict
		}
		previous = &current
	} else if !errors.Is(err, engine.ErrNotFound) {
		return mapErr(err)
	} else if expectedRevision != 0 {
		return host.ErrConflict
	}
	if err := s.db.CompareAndSwap(path, previous, v); err != nil {
		switch {
		case errors.Is(err, engine.ErrConflict):
			return host.ErrConflict
		case errors.Is(err, engine.ErrCASDurability):
			return host.ErrUnavailable
		default:
			return mapErr(err)
		}
	}
	s.observePath(path)
	return nil
}
