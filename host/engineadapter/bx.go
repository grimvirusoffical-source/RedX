package engineadapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"redx/box"
	"redx/engine"
	"redx/engine/idx"
	"redx/engine/link"
	"redx/engine/query"
	"redx/engine/sec"
	"redx/host"
)

// bxStore is the link.Store BoxQL reads and writes through. Writes go through the rule engine
// when rules are active (so BoxQL writes fire rules and timers like REST writes do) and always
// through the index observers.
type bxStore struct{ s *store }

func (q bxStore) rs() *engine.RecordStore { return q.s.db.Records() }

func (q bxStore) Get(a link.Addr) (*box.Entry, bool, error) { return q.rs().Get(a) }
func (q bxStore) Scan(file string, fn func(link.Addr, *box.Entry) bool) error {
	return q.rs().Scan(file, fn)
}
func (q bxStore) Files() []string { return q.rs().Files() }

func (q bxStore) Put(a link.Addr, e *box.Entry) error {
	if eng := q.s.pulseP.Load(); eng != nil && q.s.hasRules.Load() && !q.s.follower.Load() {
		_, err := eng.Put(a, e)
		return err
	}
	return obsStore{Store: q.rs(), s: q.s}.Put(a, e)
}

func (q bxStore) Delete(a link.Addr) (bool, error) {
	if eng := q.s.pulseP.Load(); eng != nil && q.s.hasRules.Load() && !q.s.follower.Load() {
		return eng.Delete(a)
	}
	return obsStore{Store: q.rs(), s: q.s}.Delete(a)
}

const (
	linkExt = ".red-xai-db-link"
)

// loadLinks reads every standalone link file (.red-xai-db-link) of the database into one set.
func (s *store) loadLinks() {
	names, err := globFiles(s.dir, linkExt)
	if err != nil || len(names) == 0 {
		s.links.Store(link.NewLinkSet())
		return
	}
	set := link.NewLinkSet()
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(s.dir, n))
		if err != nil {
			s.warnf("links: %s: %v", n, err)
			continue
		}
		ls, err := link.ParseLinkFile(string(b))
		if err != nil {
			s.warnf("links: %s did not load: %v", n, err)
			continue
		}
		for _, nl := range ls.All() {
			if err := set.Add(nl.Name, nl.Link); err != nil {
				s.warnf("links: %s: %s: %v", n, nl.Name, err)
			}
		}
	}
	s.links.Store(set)
}

func (s *store) warnf(format string, a ...interface{}) {
	if s.logf != nil {
		s.logf(format, a...)
	}
}

func (s *store) linkSet() *link.LinkSet {
	if ls := s.links.Load(); ls != nil {
		return ls
	}
	return link.NewLinkSet()
}

// bxManager returns one index manager over every declared index of the database, for the
// BoxQL planner (nil when there are none, or on a follower: replicated writes bypass the observers).
func (s *store) bxManager() *idx.Manager {
	if s.follower.Load() {
		return nil
	}
	s.opening.Add(1)
	defer s.opening.Add(-1)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bxMgr != nil || s.bxTried {
		return s.bxMgr
	}
	s.bxTried = true
	names, err := globFiles(s.dir, idxExt)
	if err != nil || len(names) == 0 {
		return nil
	}
	var parts []string
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(s.dir, n))
		if err != nil {
			return nil
		}
		parts = append(parts, string(b))
	}
	mgr, err := idx.ParseManager(strings.Join(parts, "\n"))
	if err != nil {
		s.warnf("boxql: planner indexes unavailable (index names must be unique across sets): %v", err)
		return nil
	}
	s.imu.Lock()
	err = mgr.RebuildAll(s.db.Records())
	s.imu.Unlock()
	if err != nil {
		s.warnf("boxql: planner indexes unavailable: %v", err)
		return nil
	}
	s.bxMgr = mgr
	s.bxOn.Store(true)
	return mgr
}

// invalidateBX drops the planner's indexes and the cached query engine (index sets changed,
// or this node was demoted).
func (s *store) invalidateBX() {
	s.mu.Lock()
	s.bxMgr, s.bxTried = nil, false
	s.bxOn.Store(false)
	s.mu.Unlock()
	s.qmu.Lock()
	s.qdb = nil
	s.qmu.Unlock()
}

func (s *store) queryDB() (*query.DB, error) {
	mgr := s.bxManager()
	s.qmu.Lock()
	defer s.qmu.Unlock()
	if s.qdb != nil && s.qdbMgr == mgr {
		return s.qdb, nil
	}
	st := bxStore{s}
	db, err := query.New(query.Config{
		Store: st, Auth: keyAuthz{s}, Indexes: mgr,
		Links: link.New(st, link.Options{Links: s.linkSet()}),
	})
	if err != nil {
		return nil, err
	}
	s.qdb, s.qdbMgr = db, mgr
	return db, nil
}

// notFoundErr is a not-found (404) whose message is the BoxQL error itself.
type notFoundErr struct{ err error }

func (e notFoundErr) Error() string { return e.err.Error() }
func (e notFoundErr) Unwrap() error { return host.ErrNotFound }

func bxErr(err error) error {
	var se *query.SyntaxError
	switch {
	case err == nil:
		return nil
	case errors.Is(err, sec.ErrDenied):
		return fmt.Errorf("%w: %v", host.ErrForbidden, err)
	case errors.As(err, &se), errors.Is(err, query.ErrSyntax), errors.Is(err, query.ErrTooLarge), errors.Is(err, query.ErrParams),
		errors.Is(err, query.ErrLimit), errors.Is(err, query.ErrAmbiguous), errors.Is(err, query.ErrBadStatement),
		errors.Is(err, query.ErrType), errors.Is(err, query.ErrNoLinks):
		return fmt.Errorf("%w: %v", host.ErrInvalid, err)
	case errors.Is(err, query.ErrNoFile):
		return notFoundErr{err} // keep the documented text: query: unknown file: "name"
	case errors.Is(err, query.ErrExists), errors.Is(err, query.ErrConflict):
		return fmt.Errorf("%w: %v", host.ErrConflict, err)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("%w: command cancelled: %v", host.ErrInvalid, err)
	}
	return mapErr(err)
}

// BXInfo classifies a BoxQL command without running it.
func (s *store) BXInfo(q string) (host.BXInfo, error) {
	in, err := query.Analyze(q)
	if err != nil {
		return host.BXInfo{}, bxErr(err)
	}
	return host.BXInfo{Verb: in.Verb, Writes: in.Writes, Watch: in.Watch}, nil
}

func (s *store) BX(ctx context.Context, p host.SecPrincipal, q string, params map[string]interface{}, explain bool) (host.BXResult, error) {
	if !explain && s.follower.Load() {
		if in, err := query.Analyze(q); err == nil && in.Writes {
			return host.BXResult{}, host.ErrReadOnly
		}
	}
	pr, err := s.secP.Load().principalFor(p)
	if err != nil {
		return host.BXResult{}, err
	}
	db, err := s.queryDB()
	if err != nil {
		return host.BXResult{}, err
	}
	var res *query.Result
	if explain {
		res, err = db.Explain(ctx, pr, q, params)
	} else {
		res, err = db.Exec(ctx, pr, q, params)
	}
	if err != nil {
		return host.BXResult{}, bxErr(err)
	}
	if !explain {
		s.slideRead(res)
	}
	return toBXResult(res), nil
}

// slideRead makes a BoxQL Get refresh sliding TTLs like a REST read does: every record a Get row came
// from has the live sliding entries inside it pushed out (and the move is replicated as a touch op).
func (s *store) slideRead(res *query.Result) {
	var addrs []link.Addr
	var walk func(r *query.Result)
	walk = func(r *query.Result) {
		if r == nil {
			return
		}
		if r.Kind == "get" {
			addrs = append(addrs, r.Addrs...)
		}
		for _, c := range r.Results {
			walk(c)
		}
	}
	walk(res)
	if len(addrs) > 0 {
		s.db.Records().Touch(addrs)
	}
}

func toBXResult(res *query.Result) host.BXResult {
	out := host.BXResult{Kind: res.Kind, Columns: res.Columns, Affected: res.Affected, Matched: res.Matched, Access: res.Access, Scanned: res.Scanned, Plan: res.Plan}
	if out.Columns == nil {
		out.Columns = []string{}
	}
	out.Rows, out.RowsBox = [][]json.RawMessage{}, [][]string{}
	for _, row := range res.Rows {
		r, t := make([]json.RawMessage, len(row)), make([]string, len(row))
		for i, v := range row {
			t[i] = v.String()
			if b, err := v.MarshalJSON(); err == nil {
				r[i] = b
			} else {
				r[i] = json.RawMessage("null")
			}
		}
		out.Rows, out.RowsBox = append(out.Rows, r), append(out.RowsBox, t)
	}
	for _, a := range res.Addrs {
		out.Paths = append(out.Paths, recPath(a))
	}
	for _, a := range res.Cascaded {
		out.Cascaded = append(out.Cascaded, recPath(a))
	}
	for _, sub := range res.Results {
		out.Results = append(out.Results, toBXResult(sub))
	}
	return out
}

// BXWatch prepares a {Watch[]} subscription. Data watches subscribe to the file and box and pass
// each change through the command's filter and the caller's read rules; the record is read
// again so that a change deep inside a record is announced as the whole (masked) record.
func (s *store) BXWatch(ctx context.Context, p host.SecPrincipal, q string, params map[string]interface{}) (host.BXWatchPlan, error) {
	pr, err := s.secP.Load().principalFor(p)
	if err != nil {
		return host.BXWatchPlan{}, err
	}
	db, err := s.queryDB()
	if err != nil {
		return host.BXWatchPlan{}, err
	}
	spec, err := db.Watch(ctx, pr, q, params)
	if err != nil {
		return host.BXWatchPlan{}, bxErr(err)
	}
	if spec.Pulse {
		return host.BXWatchPlan{Pulse: true, Topic: spec.Topic}, nil
	}
	pattern := spec.File + ":*"
	if spec.Box != "" {
		pattern = spec.File + ":" + spec.Box
	}
	rs := s.db.Records()
	filter := func(ev host.Event) (host.Event, bool) {
		pp, err := box.ParsePath(ev.Path)
		if err != nil || len(pp.Segs) == 0 || pp.Segs[0].Wild || pp.Segs[0].AnyID {
			return ev, false
		}
		first := pp.Segs[0]
		addr := link.Addr{File: pp.File, Box: first.Name, ID: first.ID, HasID: first.HasID}
		if len(pp.Segs) == 1 && (ev.Op == "delete" || ev.Op == "expire") {
			if !spec.AdmitGone(addr) {
				return ev, false
			}
			return host.Event{Path: recPath(addr), Op: ev.Op, At: ev.At}, true
		}
		ent, ok, err := rs.Get(addr)
		if err != nil || !ok {
			return ev, false
		}
		v, ok := spec.Admit(addr, ent)
		if !ok {
			return ev, false
		}
		return host.Event{Path: recPath(addr), Op: ev.Op, Value: v.String(), At: ev.At}, true
	}
	return host.BXWatchPlan{Pattern: pattern, Filter: filter}, nil
}
