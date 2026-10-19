package query

import (
	"context"
	"fmt"
	"sync"

	"redx/box"
	"redx/engine/link"
	"redx/engine/sec"
)

// WatchSpec is a prepared {Watch[]} command: it says what to subscribe to and filters the
// events the subscription yields. Watch commands are not run by Exec; a server opens the
// subscription and passes each change through Admit.
type WatchSpec struct {
	Pulse bool   // a pulse topic pattern (Topic) instead of data changes
	Topic string // Pulse: the topic pattern, e.g. "player.*"
	File  string // data: the resolved file
	Box   string // data: the box ("" = every box of the file)

	mu sync.Mutex
	r  *run
	f  []Expr
}

// Watch parses and authorizes a {Watch[]} command. The principal must be allowed to read what
// it watches; records the filter names fields of are checked as for Get.
func (db *DB) Watch(ctx context.Context, pr sec.Principal, q string, params map[string]interface{}) (*WatchSpec, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	st, names, err := parseWith(q, db.lim)
	if err != nil {
		return nil, err
	}
	w, ok := st.(*Watch)
	if !ok {
		return nil, fmt.Errorf("%w: expected {Watch[]} = ..., got %s", ErrBadStatement, infoOf(st, nil).Verb)
	}
	vals, err := db.bindParams(names, params)
	if err != nil {
		return nil, err
	}
	if w.Pulse {
		return &WatchSpec{Pulse: true, Topic: w.Topic}, nil
	}
	r := &run{db: db, ctx: ctx, az: newAuthz(db.cfg.Auth, pr), lim: db.lim, params: vals}
	aliases := []string{w.Target.alias()}
	bindExpr(w.Where, aliases)
	if err := r.validateExpr(w.Where); err != nil {
		return nil, err
	}
	file, err := r.resolveSource(w.Target, sec.ActionRead, false)
	if err != nil {
		return nil, err
	}
	if w.Target.Box != "" {
		if err := r.az.check(sec.ActionRead, sec.Resource{File: file, Box: w.Target.Box}); err != nil && db.cfg.OwnerOf == nil {
			return nil, err
		}
	}
	if err := r.staticRead(file, w.Target.Box, fieldsOf(w.Where)); err != nil {
		return nil, err
	}
	return &WatchSpec{File: file, Box: w.Target.Box, r: r, f: flattenAnd(w.Where, nil)}, nil
}

// Admit reports whether a change to the record at addr belongs to the subscription and, if so,
// returns the record as the principal may see it (fields they may not read removed).
func (w *WatchSpec) Admit(addr link.Addr, ent *box.Entry) (box.Value, bool) {
	if w.Pulse || ent == nil || addr.File != w.File || (w.Box != "" && addr.Box != w.Box) {
		return box.Value{}, false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	rc, ok := w.r.gate(addr, ent, ent.Value)
	if !ok {
		return box.Value{}, false
	}
	if !w.r.all(w.f, tuple{rc}) {
		return box.Value{}, false
	}
	return w.r.maskRecord(rc), true
}

// maskRecord returns the record's value with the fields the principal may not read removed.
func (r *run) maskRecord(rc *rec) box.Value {
	if rc.val.Kind != box.KindBox || rc.val.Box == nil {
		return rc.val
	}
	nb := box.NewBox()
	nb.HasFlag, nb.Flag, nb.Meta = rc.val.Box.HasFlag, rc.val.Box.Flag, rc.val.Box.Meta
	for _, e := range rc.val.Box.Entries() {
		if !r.az.pathAllowed(sec.ActionRead, rc.addr.File, rc.addr.Box, rc.owner, []string{e.Key}) {
			continue
		}
		c := e.Clone()
		c.Value = r.mask(rc, e.Key, e.Value)
		nb.Put(c)
	}
	return box.BoxValue(nb)
}

// AdmitGone reports whether the removal of the record at addr may be announced. The record is
// gone, so the filter cannot be evaluated: every removal of a record of the watched box that
// the principal may read the box of is announced (without a value).
func (w *WatchSpec) AdmitGone(addr link.Addr) bool {
	if w.Pulse || addr.File != w.File || (w.Box != "" && addr.Box != w.Box) || w.r.db.cfg.OwnerOf != nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.r.az.ok(sec.ActionRead, sec.Resource{File: addr.File, Box: addr.Box})
}
