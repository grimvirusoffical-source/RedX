package host

// This optional capability is deliberately separate from Backend/Extras: legacy
// and stub backends cannot silently substitute a racy Get+Set implementation.
import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

const MaxRecordRevision uint64 = 9007199254740991 // exact in JS and Box numbers

// CASRecord is a revisioned opaque service document, not an account identity.
// Key is an immutable namespace; Payload is an opaque string, usually JSON.
type CASRecord struct {
	Key      string `json:"key"`
	Revision uint64 `json:"revision"`
	Payload  string `json:"payload"`
}

// RecordCASBackend must use native atomic durable commits and apply complete
// read/write policy checks. Writes return a durable watermark of the exact
// native file, not a host replication offset or a claim of replica durability.
type RecordCASBackend interface {
	ReplBackend
	ReadCASRecord(SecPrincipal, string) (CASRecord, error)
	CompareAndSwapRecord(SecPrincipal, string, uint64, CASRecord) (uint64, error)
}

func (h *Host) withRecordCAS(db string, operation func(RecordCASBackend) error) error {
	// Do not hold these host locks while reading an HTTP body, writing a
	// response or waiting for replicas. Configuration and snapshot swaps stay
	// excluded only while the real database policy/read/commit runs.
	h.pause.RLock()
	defer h.pause.RUnlock()
	h.Cluster.recordGate.RLock()
	defer h.Cluster.recordGate.RUnlock()
	h.opMu.Lock()
	defer h.opMu.Unlock()
	// Authentication/forwarding happens before a possibly slow request body
	// or lock wait. Recheck the authoritative leader boundary at the actual
	// operation; a fenced former leader must supply neither reads nor writes.
	if !h.Cluster.IsLeader() {
		return ErrReadOnly
	}
	if h.Cluster.WritableErr() != nil {
		return fmt.Errorf("%w: cluster no longer accepts authoritative record operations", ErrUnavailable)
	}
	if err := h.Cluster.recordCASMode(); err != nil {
		return err
	}
	b, err := h.Reg.Get(db)
	if err != nil {
		return err
	}
	backend, ok := b.(RecordCASBackend)
	if !ok {
		return fmt.Errorf("%w: this backend does not support durable record CAS", ErrUnsupported)
	}
	return operation(backend)
}

func (h *Host) recordCASHandler(w http.ResponseWriter, r *http.Request, db, path string) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		writeErr(w, 405, "method not allowed")
		return
	}
	if err := ValidPath(path); err != nil || r.URL.RawQuery != "" {
		writeErr(w, 400, "a concrete record path without query options is required")
		return
	}
	need := ScopeRead
	if r.Method == http.MethodPost {
		need = ScopeWrite
	}
	pr, ok := h.authz(w, r, need, db, path, false)
	if !ok {
		return
	}
	// This capability has only local native-file durability. Refuse replica
	// expectations before reading a body or committing any application change.
	if r.Header.Get("X-Redx-Wait-Replicas") != "" || r.Header.Get("X-Redx-Wait-Seq") != "" {
		writeErr(w, 400, "record CAS supports local native-file durability only")
		return
	}
	if h.maybeForward(w, r) {
		return
	}
	sp := secPrincipal(&pr.Key)
	if r.Method == http.MethodGet {
		var record CASRecord
		err := h.withRecordCAS(db, func(backend RecordCASBackend) error {
			w.Header().Set("X-Redx-Record-CAS", "1")
			var err error
			record, err = backend.ReadCASRecord(sp, path)
			return err
		})
		if err != nil {
			h.auditPolicy(r, pr, db, err)
			if errors.Is(err, ErrNotFound) {
				writeJSON(w, 404, map[string]string{"code": "record_not_found", "error": "record not found"})
			} else {
				h.extrasMapErr(w, err)
			}
			return
		}
		writeJSON(w, 200, map[string]interface{}{"record": record})
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.extrasMapErr(w, err)
		return
	}
	var req struct {
		Expected *uint64    `json:"expected_revision"`
		Record   *CASRecord `json:"record"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&req) != nil || decoder.Decode(new(interface{})) != io.EOF || req.Expected == nil || req.Record == nil || *req.Expected >= MaxRecordRevision || req.Record.Revision != *req.Expected+1 {
		writeErr(w, 400, "expected_revision and record with the next exact safe revision are required")
		return
	}
	if !h.checkStorageQuota(w, pr, int64(len(req.Record.Payload))) {
		return
	}
	var localSeq uint64
	if err := h.withRecordCAS(db, func(backend RecordCASBackend) error {
		w.Header().Set("X-Redx-Record-CAS", "1")
		var err error
		localSeq, err = backend.CompareAndSwapRecord(sp, path, *req.Expected, *req.Record)
		if err != nil {
			return err
		}
		if localSeq == 0 || localSeq > MaxRecordRevision {
			// A commit may already exist. Never label receipt uncertainty as a
			// conflict: callers must reconcile instead of replaying a mutation.
			return fmt.Errorf("%w: record committed but local durability acknowledgement unavailable", ErrUnavailable)
		}
		return nil
	}); err != nil {
		h.auditPolicy(r, pr, db, err)
		if errors.Is(err, ErrConflict) {
			writeJSON(w, 409, map[string]string{"code": "record_conflict", "error": "record revision conflict"})
		} else {
			h.extrasMapErr(w, err)
		}
		return
	}
	h.noteStorage(pr, int64(len(req.Record.Payload)))
	// The receipt was captured and validated while role/fence transitions were
	// excluded. A later transition does not alter that completed local commit.
	w.Header().Set("X-Redx-Local-Seq", strconv.FormatUint(localSeq, 10))
	writeJSON(w, 200, map[string]interface{}{"ok": true, "revision": req.Record.Revision, "local_seq": localSeq, "sequence_scope": "native-file", "seq": localSeq})
}
