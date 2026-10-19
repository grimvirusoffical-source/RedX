package query

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"redx/box"
	"redx/engine/link"
	"redx/engine/sec"
)

// put writes a record through the link engine when there is one (so it is
// serialized with cascades), else straight to the store.
func (r *run) put(a link.Addr, e *box.Entry) error {
	if r.db.cfg.Links != nil {
		return r.db.cfg.Links.Put(a, e, link.PutOptions{})
	}
	return r.db.cfg.Store.Put(a, e)
}

// setPath sets the value at segs inside the record, creating intermediate
// boxes. With replace=false an existing final entry is an error.
func setPath(ent *box.Entry, segs []box.Seg, v box.Value, replace bool) error {
	if ent.Value.Kind == box.KindNell && ent.Value.Box == nil {
		ent.Value = box.BoxValue(box.NewBox())
	}
	if ent.Value.Kind != box.KindBox || ent.Value.Box == nil {
		return fmt.Errorf("%w: record %s is not a box, cannot set a field in it", ErrType, ent.Key)
	}
	b := ent.Value.Box
	for i, s := range segs {
		cur := b.Get(s.Name, s.ID, s.HasID)
		last := i == len(segs)-1
		if last {
			if cur != nil {
				if !replace {
					return fmt.Errorf("%w: field %s is set twice", ErrType, box.SegsString(segs))
				}
				cur.Value = v
				return nil
			}
			var idp *int64
			if s.HasID {
				id := s.ID
				idp = &id
			}
			b.Put(box.NewEntry(s.Name, idp, v))
			return nil
		}
		if cur == nil {
			var idp *int64
			if s.HasID {
				id := s.ID
				idp = &id
			}
			cur = box.NewEntry(s.Name, idp, box.BoxValue(box.NewBox()))
			b.Put(cur)
		}
		if cur.Value.Kind != box.KindBox || cur.Value.Box == nil {
			return fmt.Errorf("%w: %s is not a box (in %s)", ErrType, s.Name, box.SegsString(segs))
		}
		b = cur.Value.Box
	}
	return nil
}

func checkNames(f *Field) error {
	for _, s := range f.Path {
		if !validIdentName(s.Name) {
			return synErr(f.P, f.Raw, "field name %q cannot be stored (letters, digits, _ and - only; not TRUE, FALSE, NELL or ID)", s.Name)
		}
	}
	return nil
}

func (r *run) checkWritable(f *Field) error {
	if f.Pseudo != "" {
		return synErr(f.P, f.Raw, "%s is read-only", f.Pseudo)
	}
	if len(f.Path) == 0 {
		return synErr(f.P, f.Raw, "empty field path")
	}
	return checkNames(f)
}

// ---- helpers -------------------------------------------------------------

func isIDField(f *Field) bool {
	return len(f.Segs) == 1 && !f.Segs[0].HasID && strings.EqualFold(f.Segs[0].Name, "ID")
}

// targetID reads the record ID out of a source written as Box[ID=n]; nil means "a record
// without an ID" (the source had no filter).
func (r *run) targetID(src Source, verb string) (*int64, error) {
	if src.All {
		return nil, synErr(src.P, src.Box, "%s names one record: %s[ID=n], not [ID=*]", verb, src.Box)
	}
	if src.Where == nil {
		return nil, nil
	}
	if b, ok := src.Where.(*Binary); ok && b.Op == "=" {
		if f, ok := b.L.(*Field); ok && isIDField(f) && isConst(b.R) {
			id, ok := wholeID(r.constEval(b.R))
			if !ok {
				return nil, fmt.Errorf("%w: ID must be a whole number, got %s", ErrParams, fmtValue(r.constEval(b.R)))
			}
			return &id, nil
		}
	}
	return nil, synErr(src.P, src.Box, "%s names a single record as %s[ID=n] (or plain %s for a record without an ID), not a filter", verb, src.Box, src.Box)
}

func (r *run) needBox(src Source, verb string) error {
	if src.Box == "" {
		return synErr(src.P, src.File, "%s needs a box: file:Box[...]", verb)
	}
	if !validIdentName(src.Box) {
		return synErr(src.P, src.Box, "box name %q cannot be stored", src.Box)
	}
	return nil
}

func (r *run) needScope(src Source, verb string) error {
	if !src.scoped() {
		return fmt.Errorf("%w: %s must say which records: %s[ID=1], a filter such as %s[Level < 3], or %s[ID=*] for every record", ErrBadStatement, verb, src.Box, src.Box, src.Box)
	}
	return nil
}

// recPaths lists the dotted field names (without IDs) of every leaf of a record literal.
func recPaths(x *RecLit, prefix []string, out *[][]string) {
	for _, en := range x.Entries {
		names := append(append([]string(nil), prefix...), cumName(prefix, en.Key))
		if sub, ok := en.Value.(*RecLit); ok && len(sub.Entries) > 0 {
			recPaths(sub, names, out)
			continue
		}
		*out = append(*out, names)
	}
}

func cumName(prefix []string, key string) string {
	if len(prefix) == 0 {
		return key
	}
	return prefix[len(prefix)-1] + "." + key
}

// diffPaths lists the paths (cumulative names) at which two boxes differ.
func diffPaths(oldB, newB *box.Box, prefix []string, out *[][]string) {
	names := func(key string) []string {
		return append(append([]string(nil), prefix...), cumName(prefix, key))
	}
	seen := map[box.EKey]bool{}
	for _, ne := range newB.Entries() {
		seen[ne.EKey()] = true
		oe := oldB.Get(ne.Key, idOf(ne), hasID(ne))
		switch {
		case oe == nil:
			*out = append(*out, names(ne.Key))
		case oe.Value.Kind == box.KindBox && ne.Value.Kind == box.KindBox && oe.Value.Box != nil && ne.Value.Box != nil:
			diffPaths(oe.Value.Box, ne.Value.Box, names(ne.Key), out)
		case !oe.Value.Equal(ne.Value) || oe.Value.Kind != ne.Value.Kind:
			*out = append(*out, names(ne.Key))
		}
	}
	for _, oe := range oldB.Entries() {
		if !seen[oe.EKey()] {
			*out = append(*out, names(oe.Key))
		}
	}
}

func idOf(e *box.Entry) int64 { id, _ := e.ID(); return id }
func hasID(e *box.Entry) bool { _, ok := e.ID(); return ok }

func (r *run) denyWrite(file, boxName string, names []string) error {
	return fmt.Errorf("%w: write on %s:%s.%s", sec.ErrDenied, file, boxName, names[len(names)-1])
}

func applyTTL(e *box.Entry, t TTLSpec) {
	if t.Kind != box.TTLNone {
		e.TTL.Kind, e.TTL.Seconds = t.Kind, t.Seconds
	}
}

// ---- Add -----------------------------------------------------------------

func (r *run) doAdd(a *Add, explain bool) (*Result, error) {
	if err := r.needBox(a.Target, "Add"); err != nil {
		return nil, err
	}
	id, err := r.targetID(a.Target, "Add")
	if err != nil {
		return nil, err
	}
	if err := r.validateExpr(a.Rec); err != nil {
		return nil, err
	}
	file, err := r.resolveSource(a.Target, sec.ActionWrite, true)
	if err != nil {
		return nil, err
	}
	rl := a.Rec.(*RecLit)
	var paths [][]string
	recPaths(rl, nil, &paths)
	if r.db.cfg.OwnerOf == nil {
		if err := r.az.check(sec.ActionWrite, sec.Resource{File: file, Box: a.Target.Box}); err != nil {
			return nil, err
		}
		for _, p := range paths {
			if !r.az.pathAllowed(sec.ActionWrite, file, a.Target.Box, "", p) {
				return nil, r.denyWrite(file, a.Target.Box, p)
			}
		}
	}
	if explain {
		return planResult([]string{
			fmt.Sprintf("Add %s:%s%s with %d field(s)", file, a.Target.Box, idText(id), len(rl.Entries)),
			"  authorize write on the box and on every field, fail if the record already exists, then store",
			fmt.Sprintf("  max writes: %d", r.lim.MaxWrites),
		}), nil
	}
	r.arithErr = nil
	ent := box.NewEntry(a.Target.Box, id, r.evalRec(rl))
	if r.arithErr != nil {
		return nil, r.writeArithErr()
	}
	applyTTL(ent, a.TTL)
	addr := link.EntryAddr(file, ent)
	if r.db.cfg.OwnerOf != nil {
		owner := r.owner(addr, ent)
		if err := r.az.check(sec.ActionWrite, sec.Resource{File: file, Box: addr.Box, Owner: owner}); err != nil {
			return nil, err
		}
		for _, p := range paths {
			if !r.az.pathAllowed(sec.ActionWrite, file, addr.Box, owner, p) {
				return nil, r.denyWrite(file, addr.Box, p)
			}
		}
	}
	if _, ok, err := r.db.cfg.Store.Get(addr); err != nil {
		return nil, err
	} else if ok {
		return nil, fmt.Errorf("%w: %s", ErrExists, addr)
	}
	if err := r.ctx.Err(); err != nil {
		return nil, err
	}
	if err := r.before(addr); err != nil {
		return nil, err
	}
	if err := r.put(addr, ent); err != nil {
		return nil, err
	}
	return &Result{Kind: "add", Affected: 1}, nil
}

func idText(id *int64) string {
	if id == nil {
		return ""
	}
	return "[ID=" + strconv.FormatInt(*id, 10) + "]"
}

// ---- Set -----------------------------------------------------------------

func (r *run) planWriteTarget(src Source, where Expr, act sec.Action) (file string, pre []Expr, acc access, err error) {
	file, err = r.resolveSource(src, act, true)
	if err != nil {
		return
	}
	pre = flattenAnd(where, nil)
	if a, ok := r.accessAnd(pre, file, src.Box, r.params); ok {
		acc = a
	}
	return
}

func (r *run) doSet(s *Set, explain bool) (*Result, error) {
	if err := r.needBox(s.Target, "Set"); err != nil {
		return nil, err
	}
	if s.Replace != nil {
		return r.doReplace(s, explain)
	}
	if err := r.needScope(s.Target, "Set"); err != nil {
		return nil, err
	}
	aliases := []string{s.Target.alias()}
	var fields []*Field
	seen := map[string]bool{}
	for _, as := range s.Assigns {
		bindField(as.Target, aliases)
		if err := r.checkWritable(as.Target); err != nil {
			return nil, err
		}
		k := box.SegsString(as.Target.Path)
		if seen[k] {
			return nil, synErr(as.Target.P, as.Target.Raw, "field %s is assigned twice", as.Target.Raw)
		}
		seen[k] = true
		bindExpr(as.Value, aliases)
		if err := r.validateExpr(as.Value); err != nil {
			return nil, err
		}
		fields = append(fields, fieldsOf(as.Value)...)
	}
	bindExpr(s.Where, aliases)
	if err := r.validateExpr(s.Where); err != nil {
		return nil, err
	}
	fields = append(fields, fieldsOf(s.Where)...)
	file, pre, acc, err := r.planWriteTarget(s.Target, s.Where, sec.ActionWrite)
	if err != nil {
		return nil, err
	}
	if err := r.staticRead(file, s.Target.Box, fields); err != nil {
		return nil, err
	}
	if r.db.cfg.OwnerOf == nil {
		for _, as := range s.Assigns {
			if !r.az.pathAllowed(sec.ActionWrite, file, s.Target.Box, "", as.Target.Names) {
				return nil, r.denyWrite(file, s.Target.Box, as.Target.Names)
			}
		}
	}
	if explain {
		lines := []string{fmt.Sprintf("Set on %s:%s", file, s.Target.Box)}
		lines = append(lines, acc.describe("  access: ")...)
		if len(pre) > 0 {
			lines = append(lines, "  filter: "+condString(pre, r.params))
		} else {
			lines = append(lines, "  filter: every record (ID=*)")
		}
		for _, as := range s.Assigns {
			lines = append(lines, fmt.Sprintf("  assign: %s = %s", as.Target.Raw, exprString(as.Value, r.params)))
		}
		lines = append(lines, fmt.Sprintf("  max writes: %d; every changed field is authorized for write before the first record is stored", r.lim.MaxWrites))
		return planResult(lines), nil
	}
	cands, err := r.candidates(file, s.Target.Box, acc, pre, 1)
	if err != nil {
		return nil, err
	}
	if len(cands) > r.lim.MaxWrites {
		return nil, fmt.Errorf("%w: Set matches %d records, more than the maximum of %d writes", ErrLimit, len(cands), r.lim.MaxWrites)
	}
	type pend struct {
		addr link.Addr
		ent  *box.Entry
	}
	var pending []pend
	for _, c := range cands {
		t := tuple{c}
		vals := make([]box.Value, len(s.Assigns))
		r.arithErr = nil
		for i, as := range s.Assigns {
			vals[i] = r.eval(as.Value, t)
		}
		if r.arithErr != nil {
			return nil, r.writeArithErr()
		}
		ne := c.ent.Clone()
		for i, as := range s.Assigns {
			if !r.az.pathAllowed(sec.ActionWrite, c.addr.File, c.addr.Box, c.owner, as.Target.Names) {
				return nil, r.denyWrite(c.addr.File, c.addr.Box, as.Target.Names)
			}
			if err := setPath(ne, as.Target.Path, vals[i].Clone(), true); err != nil {
				return nil, err
			}
		}
		applyTTL(ne, s.TTL)
		if ne.Value.Equal(c.ent.Value) && s.TTL.Kind == box.TTLNone {
			continue
		}
		pending = append(pending, pend{c.addr, ne})
	}
	res := &Result{Kind: "set", Access: acc.label(), Scanned: r.scanned}
	for _, p := range pending {
		if err := r.ctx.Err(); err != nil {
			return res, err
		}
		if err := r.before(p.addr); err != nil {
			return res, err
		}
		if err := r.put(p.addr, p.ent); err != nil {
			return res, err
		}
		res.Affected++
	}
	return res, nil
}

// doReplace is Set Box[ID=n] = [ record ]: it stores the record whole, creating it if it is missing.
func (r *run) doReplace(s *Set, explain bool) (*Result, error) {
	id, err := r.targetID(s.Target, "Set")
	if err != nil {
		return nil, err
	}
	if err := r.validateExpr(s.Replace); err != nil {
		return nil, err
	}
	file, err := r.resolveSource(s.Target, sec.ActionWrite, true)
	if err != nil {
		return nil, err
	}
	rl := s.Replace.(*RecLit)
	if explain {
		return planResult([]string{
			fmt.Sprintf("Set (replace) %s:%s%s with %d field(s)", file, s.Target.Box, idText(id), len(rl.Entries)),
			"  authorize write on the box and on every field that differs from the stored record, then store (creates the record if missing)",
			fmt.Sprintf("  max writes: %d", r.lim.MaxWrites),
		}), nil
	}
	if r.db.cfg.OwnerOf == nil {
		if err := r.az.check(sec.ActionWrite, sec.Resource{File: file, Box: s.Target.Box}); err != nil {
			return nil, err
		}
	}
	r.arithErr = nil
	ent := box.NewEntry(s.Target.Box, id, r.evalRec(rl))
	if r.arithErr != nil {
		return nil, r.writeArithErr()
	}
	applyTTL(ent, s.TTL)
	addr := link.EntryAddr(file, ent)
	old, exists, err := r.db.cfg.Store.Get(addr)
	if err != nil {
		return nil, err
	}
	owner := r.owner(addr, ent)
	if exists {
		owner = r.owner(addr, old)
	}
	if err := r.az.check(sec.ActionWrite, sec.Resource{File: file, Box: addr.Box, Owner: owner}); err != nil {
		return nil, err
	}
	var paths [][]string
	if exists && old.Value.Kind == box.KindBox && old.Value.Box != nil {
		diffPaths(old.Value.Box, ent.Value.Box, nil, &paths)
	} else {
		recPaths(rl, nil, &paths)
	}
	for _, p := range paths {
		if !r.az.pathAllowed(sec.ActionWrite, file, addr.Box, owner, p) {
			return nil, r.denyWrite(file, addr.Box, p)
		}
	}
	if exists && old.Value.Equal(ent.Value) && s.TTL.Kind == box.TTLNone {
		return &Result{Kind: "set"}, nil
	}
	if err := r.ctx.Err(); err != nil {
		return nil, err
	}
	if err := r.before(addr); err != nil {
		return nil, err
	}
	if err := r.put(addr, ent); err != nil {
		return nil, err
	}
	return &Result{Kind: "set", Affected: 1}, nil
}

// ---- Require -------------------------------------------------------------

func (r *run) doRequire(q *Require, explain bool) (*Result, error) {
	aliases := []string{q.Target.alias()}
	bindExpr(q.Where, aliases)
	if err := r.validateExpr(q.Where); err != nil {
		return nil, err
	}
	want := -1
	if q.Count != nil {
		n, err := r.countArg(q.Count, "Count")
		if err != nil {
			return nil, err
		}
		want = n
	}
	file, err := r.resolveSource(q.Target, sec.ActionRead, false)
	if err != nil {
		return nil, err
	}
	pre := flattenAnd(q.Where, nil)
	var acc access
	if a, ok := r.accessAnd(pre, file, q.Target.Box, r.params); ok {
		acc = a
	}
	if err := r.staticRead(file, q.Target.Box, fieldsOf(q.Where)); err != nil {
		return nil, err
	}
	if explain {
		lines := []string{fmt.Sprintf("Require on %s:%s", file, orStar(q.Target.Box))}
		lines = append(lines, acc.describe("  access: ")...)
		if len(pre) > 0 {
			lines = append(lines, "  filter: "+condString(pre, r.params))
		}
		if want >= 0 {
			lines = append(lines, fmt.Sprintf("  needs exactly %d matching record(s)", want))
		} else {
			lines = append(lines, "  needs at least 1 matching record")
		}
		return planResult(lines), nil
	}
	cands, err := r.candidates(file, q.Target.Box, acc, pre, 1)
	if err != nil {
		return nil, err
	}
	n := len(cands)
	if (want < 0 && n == 0) || (want >= 0 && n != want) {
		need := "at least 1"
		if want >= 0 {
			need = fmt.Sprintf("exactly %d", want)
		}
		return nil, fmt.Errorf("%w: %s matched %d record(s), needed %s", ErrConflict, q.Target, n, need)
	}
	return &Result{Kind: "require", Matched: n, Access: acc.label(), Scanned: r.scanned}, nil
}

// ---- Delete --------------------------------------------------------------

// removePath deletes the entry at segs inside the record; it reports whether it existed.
func removePath(ent *box.Entry, segs []box.Seg) bool {
	if ent.Value.Kind != box.KindBox || ent.Value.Box == nil || len(segs) == 0 {
		return false
	}
	parent := ent.Value.Box
	if len(segs) > 1 {
		pe, err := box.Resolve(parent, segs[:len(segs)-1])
		if err != nil || pe == nil || pe.Value.Kind != box.KindBox || pe.Value.Box == nil {
			return false
		}
		parent = pe.Value.Box
	}
	last := segs[len(segs)-1]
	e := parent.Get(last.Name, last.ID, last.HasID)
	if e == nil {
		return false
	}
	return parent.Remove(e)
}

func (r *run) doDelete(d *Delete, explain bool) (*Result, error) {
	if err := r.needBox(d.Target, "Delete"); err != nil {
		return nil, err
	}
	if err := r.needScope(d.Target, "Delete"); err != nil {
		return nil, err
	}
	aliases := []string{d.Target.alias()}
	bindExpr(d.Where, aliases)
	if err := r.validateExpr(d.Where); err != nil {
		return nil, err
	}
	act := sec.ActionDelete
	if d.Path != nil {
		bindField(d.Path, aliases)
		if err := r.checkWritable(d.Path); err != nil {
			return nil, err
		}
		act = sec.ActionWrite
	}
	file, pre, acc, err := r.planWriteTarget(d.Target, d.Where, act)
	if err != nil {
		return nil, err
	}
	if err := r.staticRead(file, d.Target.Box, fieldsOf(d.Where)); err != nil {
		return nil, err
	}
	if r.db.cfg.OwnerOf == nil {
		if err := r.az.check(act, sec.Resource{File: file, Box: d.Target.Box}); err != nil {
			return nil, err
		}
		if d.Path != nil && !r.az.pathAllowed(sec.ActionWrite, file, d.Target.Box, "", d.Path.Names) {
			return nil, r.denyWrite(file, d.Target.Box, d.Path.Names)
		}
	}
	if explain {
		what := "Delete from"
		if d.Path != nil {
			what = "Delete field " + d.Path.Raw + " from"
		}
		lines := []string{fmt.Sprintf("%s %s:%s", what, file, d.Target.Box)}
		lines = append(lines, acc.describe("  access: ")...)
		if len(pre) > 0 {
			lines = append(lines, "  filter: "+condString(pre, r.params))
		} else {
			lines = append(lines, "  filter: every record (ID=*)")
		}
		switch {
		case d.Path != nil:
		case r.db.cfg.Links != nil:
			lines = append(lines, "  cascade: follows @!> links (every cascaded record is authorized for delete first)")
		default:
			lines = append(lines, "  cascade: no link engine; records with embedded @!> links are refused")
		}
		lines = append(lines, fmt.Sprintf("  max writes (cascades included): %d", r.lim.MaxWrites))
		return planResult(lines), nil
	}
	cands, err := r.candidates(file, d.Target.Box, acc, pre, 1)
	if err != nil {
		return nil, err
	}
	if len(cands) > r.lim.MaxWrites {
		return nil, fmt.Errorf("%w: Delete matches %d records, more than the maximum of %d writes", ErrLimit, len(cands), r.lim.MaxWrites)
	}
	if d.Path != nil {
		return r.deleteField(d, cands, acc)
	}
	// Pass 1: work out everything that would go (cascades included) and
	// authorize every record before the first delete.
	planned := map[link.Addr]bool{}
	plans := map[link.Addr][]link.Addr{}
	total := 0
	for _, c := range cands {
		if err := r.az.check(sec.ActionDelete, sec.Resource{File: c.addr.File, Box: c.addr.Box, Owner: c.owner}); err != nil {
			return nil, err
		}
		if r.db.cfg.Links == nil {
			for _, e := range link.EmbeddedEdges(c.addr, c.ent) {
				if e.Op == link.OpCascade {
					return nil, fmt.Errorf("%w: %s has a cascade link (%s) but the query engine has no link engine to follow it", ErrNoLinks, c.addr, e.Via)
				}
			}
			total++
			plans[c.addr] = []link.Addr{c.addr}
			continue
		}
		plan, err := r.db.cfg.Links.PlanDelete(c.addr, link.DeleteOptions{MaxRecords: r.lim.MaxWrites})
		if errors.Is(err, link.ErrTooManyRecords) {
			return nil, fmt.Errorf("%w: Delete would remove more than %d records including cascades: %w", ErrLimit, r.lim.MaxWrites, err)
		}
		if err != nil {
			return nil, err
		}
		plans[c.addr] = plan.Planned
		for _, a := range plan.Planned {
			if planned[a] {
				continue
			}
			planned[a] = true
			total++
			if a == c.addr {
				continue
			}
			ent, ok, err := r.db.cfg.Store.Get(a)
			if err != nil {
				return nil, err
			}
			owner := ""
			if ok {
				owner = r.owner(a, ent)
			}
			if err := r.az.check(sec.ActionDelete, sec.Resource{File: a.File, Box: a.Box, Owner: owner}); err != nil {
				return nil, fmt.Errorf("%w (reached by cascade from %s)", err, c.addr)
			}
		}
		if total > r.lim.MaxWrites {
			return nil, fmt.Errorf("%w: Delete would remove more than %d records including cascades", ErrLimit, r.lim.MaxWrites)
		}
	}
	// Pass 2: delete.
	res := &Result{Kind: "delete", Access: acc.label(), Scanned: r.scanned}
	primary := map[link.Addr]bool{}
	for _, c := range cands {
		primary[c.addr] = true
	}
	for _, c := range cands {
		if err := r.ctx.Err(); err != nil {
			return res, err
		}
		for _, a := range plans[c.addr] {
			if err := r.before(a); err != nil {
				return res, err
			}
		}
		if r.db.cfg.Links == nil {
			ok, err := r.db.cfg.Store.Delete(c.addr)
			if err != nil {
				return res, err
			}
			if ok {
				res.Affected++
			}
			continue
		}
		dr, err := r.db.cfg.Links.Delete(c.addr, link.DeleteOptions{MaxRecords: r.lim.MaxWrites})
		for _, a := range dr.Deleted {
			if a == c.addr || primary[a] {
				res.Affected++
			} else {
				res.Cascaded = append(res.Cascaded, a)
			}
		}
		if err != nil && !errors.Is(err, link.ErrDangling) {
			return res, err
		}
	}
	return res, nil
}

func (r *run) deleteField(d *Delete, cands []*rec, acc access) (*Result, error) {
	res := &Result{Kind: "delete", Access: acc.label(), Scanned: r.scanned}
	type pend struct {
		addr link.Addr
		ent  *box.Entry
	}
	var pending []pend
	for _, c := range cands {
		if !r.az.pathAllowed(sec.ActionWrite, c.addr.File, c.addr.Box, c.owner, d.Path.Names) {
			return nil, r.denyWrite(c.addr.File, c.addr.Box, d.Path.Names)
		}
		ne := c.ent.Clone()
		if removePath(ne, d.Path.Path) {
			pending = append(pending, pend{c.addr, ne})
		}
	}
	for _, p := range pending {
		if err := r.ctx.Err(); err != nil {
			return res, err
		}
		if err := r.before(p.addr); err != nil {
			return res, err
		}
		if err := r.put(p.addr, p.ent); err != nil {
			return res, err
		}
		res.Affected++
	}
	return res, nil
}

// writeArithErr is returned when evaluating a value to store hit division by zero or overflow: reads
// still give NELL, but a write must not silently replace data with NELL, so the command fails and
// nothing is changed.
func (r *run) writeArithErr() error {
	return fmt.Errorf("%w (nothing was changed)", r.arithErr)
}
