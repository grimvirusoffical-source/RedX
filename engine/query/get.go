package query

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"redx/box"
	"redx/engine/link"
	"redx/engine/sec"
)

type getPlan struct {
	get       *Get
	aliases   []string
	file, box string
	pre, post []Expr
	acc       access
	limit     int // -1 = none
	offset    int
	items     []Proj
	sort      []SortKey
	agg       bool
	names     []string // output column name of each item (aggregate mode)
	sortCols  []int    // aggregate mode: output column behind each sort key
}

func (r *run) countArg(e Expr, what string) (int, error) {
	if e == nil {
		return -1, nil
	}
	v := r.constEval(e)
	if v.Kind != box.KindNumber || v.Num != math.Trunc(v.Num) || v.Num < 0 || v.Num > 1<<40 {
		return 0, fmt.Errorf("%w: %s must be a non-negative whole number, got %s", ErrParams, what, fmtValue(v))
	}
	return int(v.Num), nil
}

func isAgg(e Expr) bool { _, ok := e.(*Agg); return ok }

// itemName is the column name of a projection item.
func itemName(it Proj) string {
	switch {
	case it.As != "":
		return it.As
	}
	if f, ok := it.Expr.(*Field); ok {
		return box.SegsString(f.Segs)
	}
	if a, ok := it.Expr.(*Agg); ok && a.Fn == "count" {
		return "Count"
	}
	return it.Text
}

func lastName(f *Field) string { return f.Segs[len(f.Segs)-1].Name }

func (r *run) planGet(g *Get) (*getPlan, error) {
	pl := &getPlan{get: g, items: append([]Proj(nil), g.Items...), sort: append([]SortKey(nil), g.Sort...)}
	if len(pl.items) == 0 {
		pl.items = []Proj{{Star: true, Text: "*", P: g.P}}
	}
	pl.aliases = []string{g.From.alias()}
	followAlias := make([]string, len(g.Follows))
	for i, f := range g.Follows {
		a := f.Alias
		if a == "" {
			a = lastName(f.Via)
		}
		for _, x := range pl.aliases {
			if x == a {
				return nil, synErr(f.P, a, "name %q is used twice; give the follow its own name: @> other = %s", a, f.Via.Raw)
			}
		}
		pl.aliases = append(pl.aliases, a)
		followAlias[i] = a
	}
	if len(g.Follows) > 0 && r.db.cfg.Links == nil {
		return nil, fmt.Errorf("%w: @> follows links", ErrNoLinks)
	}
	for i, f := range g.Follows {
		visible := pl.aliases[:i+1]
		bindField(f.Via, visible)
		if f.Via.Pseudo != "" {
			return nil, synErr(f.Via.P, f.Via.Raw, "@> needs a field that holds a link (optionally qualified by an earlier name: %s)", strings.Join(visible, ", "))
		}
	}
	for _, it := range pl.items {
		if it.Star && it.StarAlias != "" {
			found := false
			for _, a := range pl.aliases {
				found = found || a == it.StarAlias
			}
			if !found {
				return nil, synErr(it.P, it.Text, "unknown name %q in %s (known: %s)", it.StarAlias, it.Text, strings.Join(pl.aliases, ", "))
			}
		}
	}
	for _, it := range pl.items {
		if !it.Star && isAgg(it.Expr) {
			pl.agg = true
		}
	}
	if len(g.Group) > 0 {
		pl.agg = true
	}
	// Sort may name a projected column (as with Total = Sum(Price), Sort = -Total)
	if !pl.agg {
		for i, o := range pl.sort {
			if f, ok := o.Expr.(*Field); ok && len(f.Segs) == 1 && !f.Segs[0].HasID {
				for _, it := range pl.items {
					if !it.Star && it.As != "" && it.As == f.Segs[0].Name {
						pl.sort[i].Expr = it.Expr
						break
					}
				}
			}
		}
	}
	var exprs []Expr
	for _, it := range pl.items {
		if it.Star {
			continue
		}
		if a, ok := it.Expr.(*Agg); ok {
			if a.Arg != nil {
				exprs = append(exprs, a.Arg)
			}
			continue
		}
		exprs = append(exprs, it.Expr)
	}
	exprs = append(exprs, g.Where)
	exprs = append(exprs, g.Group...)
	if !pl.agg {
		for _, o := range pl.sort {
			exprs = append(exprs, o.Expr)
		}
	}
	var allFields []*Field
	for _, e := range exprs {
		if e == nil {
			continue
		}
		bindExpr(e, pl.aliases)
		if err := r.validateExpr(e); err != nil {
			return nil, err
		}
		allFields = append(allFields, fieldsOf(e)...)
	}
	for _, f := range g.Follows {
		allFields = append(allFields, f.Via)
	}
	if pl.agg {
		if err := r.planAgg(pl); err != nil {
			return nil, err
		}
	}
	var err error
	if pl.limit, err = r.countArg(g.Limit, "Limit"); err != nil {
		return nil, err
	}
	if pl.offset, err = r.countArg(g.Offset, "Offset"); err != nil {
		return nil, err
	}
	if pl.offset < 0 {
		pl.offset = 0
	}
	if pl.limit > r.lim.MaxRows {
		return nil, fmt.Errorf("%w: Limit %d exceeds the maximum of %d rows per query", ErrLimit, pl.limit, r.lim.MaxRows)
	}
	pl.box = g.From.Box
	if pl.file, err = r.resolveSource(g.From, sec.ActionRead, false); err != nil {
		return nil, err
	}
	if err := r.staticRead(pl.file, pl.box, allFields); err != nil {
		return nil, err
	}
	for _, c := range flattenAnd(g.Where, nil) {
		if onlyPrimary(c) {
			pl.pre = append(pl.pre, c)
		} else {
			pl.post = append(pl.post, c)
		}
	}
	pl.acc = access{}
	if len(pl.pre) > 0 {
		if a, ok := r.accessAnd(pl.pre, pl.file, pl.box, r.params); ok {
			pl.acc = a
		}
	}
	return pl, nil
}

// planAgg checks an aggregate Get: every plain item must be a Group key, and Sort must name result columns.
func (r *run) planAgg(pl *getPlan) error {
	g := pl.get
	keys := map[string]bool{}
	for _, k := range g.Group {
		keys[exprString(k, nil)] = true
	}
	pl.names = make([]string, len(pl.items))
	for i, it := range pl.items {
		if it.Star {
			return synErr(it.P, it.Text, "`*` cannot be combined with aggregates or Group; list the columns")
		}
		pl.names[i] = itemName(it)
		if isAgg(it.Expr) {
			continue
		}
		if !keys[exprString(it.Expr, nil)] {
			return synErr(it.P, it.Text, "%s is neither an aggregate nor a Group key; add it to Group = ;[...]: or aggregate it", it.Text)
		}
	}
	for _, o := range pl.sort {
		col := -1
		if f, ok := o.Expr.(*Field); ok && len(f.Segs) == 1 && !f.Segs[0].HasID {
			for i, n := range pl.names {
				if n == f.Segs[0].Name {
					col = i
				}
			}
		}
		if col < 0 {
			// a plain key expression may also be sorted by its text
			for i, it := range pl.items {
				if !isAgg(it.Expr) && exprString(it.Expr, nil) == exprString(o.Expr, nil) {
					col = i
				}
			}
		}
		if col < 0 {
			return synErr(o.Expr.exprPos(), exprString(o.Expr, nil), "in a Get with aggregates, Sort names a result column (%s)", strings.Join(pl.names, ", "))
		}
		pl.sortCols = append(pl.sortCols, col)
	}
	return nil
}

func (r *run) explainGet(pl *getPlan) *Result {
	g := pl.get
	var lines []string
	lines = append(lines, fmt.Sprintf("Get from %s:%s as %s", pl.file, orStar(pl.box), pl.aliases[0]))
	lines = append(lines, pl.acc.describe("  access: ")...)
	if len(pl.pre) > 0 {
		lines = append(lines, "  filter: "+condString(pl.pre, r.params)+"  (applied to every fetched record, including after an idx lookup)")
	}
	for i, f := range g.Follows {
		kind := "inner"
		if f.Left {
			kind = "optional"
		}
		lines = append(lines, fmt.Sprintf("  follow: %s @> %s as %s (one lookup per link)", kind, f.Via.Raw, pl.aliases[i+1]))
	}
	if len(pl.post) > 0 {
		lines = append(lines, "  after-follow filter: "+condString(pl.post, r.params))
	}
	if pl.agg {
		parts := make([]string, len(g.Group))
		for i, k := range g.Group {
			parts[i] = exprString(k, nil)
		}
		if len(parts) == 0 {
			lines = append(lines, "  aggregate: one result row over all matches")
		} else {
			lines = append(lines, "  aggregate: one row per distinct ("+strings.Join(parts, ", ")+")")
		}
	}
	if len(pl.sort) > 0 {
		parts := make([]string, len(pl.sort))
		for i, o := range pl.sort {
			parts[i] = exprString(o.Expr, r.params)
			if o.Desc {
				parts[i] = "-" + parts[i]
			}
		}
		lines = append(lines, "  sort: "+strings.Join(parts, ", "))
	} else {
		lines = append(lines, "  order: by record address (deterministic)")
	}
	lim := "none"
	if pl.limit >= 0 {
		lim = strconv.Itoa(pl.limit)
	}
	lines = append(lines, fmt.Sprintf("  limit: %s, offset: %d, max rows: %d, max records read: %d", lim, pl.offset, r.lim.MaxRows, r.lim.MaxScan))
	return planResult(lines)
}

func orStar(b string) string {
	if b == "" {
		return "*"
	}
	return b
}

func condString(conds []Expr, params []box.Value) string {
	parts := make([]string, len(conds))
	for i, c := range conds {
		parts[i] = exprString(c, params)
	}
	return strings.Join(parts, " & ")
}

func planResult(lines []string) *Result {
	res := &Result{Kind: "explain", Columns: []string{"plan"}, Plan: lines}
	for _, l := range lines {
		res.Rows = append(res.Rows, []box.Value{box.String(l)})
	}
	return res
}

type sortRow struct {
	t    tuple
	keys []box.Value
}

func (r *run) doGet(g *Get, explain bool) (*Result, error) {
	pl, err := r.planGet(g)
	if err != nil {
		return nil, err
	}
	if explain {
		return r.explainGet(pl), nil
	}
	n := len(pl.aliases)
	cands, err := r.candidates(pl.file, pl.box, pl.acc, pl.pre, n)
	if err != nil {
		return nil, err
	}
	if pl.agg {
		return r.doAggregate(pl, cands)
	}
	ordered := len(pl.sort) > 0
	maxCollect := math.MaxInt32
	if !ordered {
		if pl.limit >= 0 {
			maxCollect = pl.offset + pl.limit
		} else {
			maxCollect = pl.offset + r.lim.MaxRows + 1
		}
	}
	var rows []sortRow
	emit := func(t tuple) (bool, error) {
		sr := sortRow{t: t}
		if ordered {
			sr.keys = make([]box.Value, len(pl.sort))
			for i, o := range pl.sort {
				sr.keys[i] = r.eval(o.Expr, t)
			}
		}
		rows = append(rows, sr)
		if len(rows) > r.lim.MaxScan {
			return false, fmt.Errorf("%w: more than %d candidate rows", ErrLimit, r.lim.MaxScan)
		}
		return len(rows) < maxCollect, nil
	}
	if err := r.eachTuple(pl, cands, emit); err != nil {
		return nil, err
	}
	if ordered {
		sort.SliceStable(rows, func(i, j int) bool {
			for k, o := range pl.sort {
				c := cmpSort(rows[i].keys[k], rows[j].keys[k])
				if c == 0 {
					continue
				}
				if o.Desc {
					return c > 0
				}
				return c < 0
			}
			return false
		})
	}
	if pl.offset >= len(rows) {
		rows = nil
	} else {
		rows = rows[pl.offset:]
	}
	if pl.limit >= 0 && len(rows) > pl.limit {
		rows = rows[:pl.limit]
	}
	if pl.limit < 0 && len(rows) > r.lim.MaxRows {
		return nil, fmt.Errorf("%w: the query matches more than %d rows; add Limit = n (or raise Limits.MaxRows)", ErrLimit, r.lim.MaxRows)
	}
	return r.assemble(pl, rows)
}

func (r *run) eachTuple(pl *getPlan, cands []*rec, emit func(tuple) (bool, error)) error {
	n := len(pl.aliases)
	for _, c := range cands {
		t := make(tuple, n)
		t[0] = c
		cont, err := r.expandFollows(pl, t, 0, emit)
		if err != nil {
			return err
		}
		if !cont {
			break
		}
	}
	return nil
}

func (r *run) expandFollows(pl *getPlan, t tuple, j int, emit func(tuple) (bool, error)) (bool, error) {
	if err := r.tick(); err != nil {
		return false, err
	}
	if j == len(pl.get.Follows) {
		if !r.all(pl.post, t) {
			return true, nil
		}
		return emit(t)
	}
	fl := pl.get.Follows[j]
	var targets []*rec
	if src := t[fl.Via.Alias]; src != nil {
		var err error
		if targets, err = r.followLinks(src, fl.Via); err != nil {
			return false, err
		}
	}
	if len(targets) == 0 {
		if !fl.Left {
			return true, nil
		}
		return r.expandFollows(pl, append(tuple(nil), t...), j+1, emit)
	}
	for _, tg := range targets {
		t2 := append(tuple(nil), t...)
		t2[j+1] = tg
		cont, err := r.expandFollows(pl, t2, j+1, emit)
		if err != nil || !cont {
			return cont, err
		}
	}
	return true, nil
}

// linkTargets lists the @> (read) link targets held in a value: a link, or an
// array of links. @!> cascade links are not read links and are not followed.
func linkTargets(v box.Value) []box.Ref {
	var out []box.Ref
	one := func(x box.Value) {
		if x.Kind != box.KindLink || x.Link == nil {
			return
		}
		l := x.Link
		switch {
		case l.To == nil:
			out = append(out, l.From)
		case l.Op == link.OpRead:
			out = append(out, *l.To)
		}
	}
	if v.Kind == box.KindArray {
		for _, x := range v.Arr {
			one(x)
		}
	} else {
		one(v)
	}
	return out
}

func (r *run) followLinks(src *rec, via *Field) ([]*rec, error) {
	val := r.readPath(src, via)
	var out []*rec
	for _, ref := range linkTargets(val) {
		addr, err := link.AddrOf(ref)
		if err != nil {
			continue
		}
		r.scanned++
		if r.scanned > r.lim.MaxScan {
			return nil, fmt.Errorf("%w: command read more than %d records", ErrLimit, r.lim.MaxScan)
		}
		if r.db.cfg.OwnerOf == nil && !r.az.ok(sec.ActionRead, sec.Resource{File: addr.File, Box: addr.Box}) {
			continue // authorized before the target is read
		}
		v, err := r.db.cfg.Links.Resolve(ref)
		if err != nil {
			if errors.Is(err, link.ErrDangling) {
				continue
			}
			return nil, err
		}
		ent := &box.Entry{Key: addr.Box, Value: v}
		if addr.HasID {
			ent.Attrs = []box.Attr{{Name: "ID", Value: box.Int(addr.ID)}}
		}
		if rc, ok := r.gate(addr, ent, v); ok {
			out = append(out, rc)
		}
	}
	return out, nil
}

type cell struct {
	name string
	v    box.Value
}

func (r *run) starCells(rc *rec, prefix string) []cell {
	if rc == nil {
		return nil
	}
	if rc.val.Kind != box.KindBox || rc.val.Box == nil {
		return []cell{{prefix + "_value", rc.val}}
	}
	var out []cell
	for _, e := range rc.val.Box.Entries() {
		if !r.az.pathAllowed(sec.ActionRead, rc.addr.File, rc.addr.Box, rc.owner, []string{e.Key}) {
			continue
		}
		out = append(out, cell{prefix + e.EKey().String(), r.mask(rc, e.Key, e.Value)})
	}
	return out
}

func (r *run) assemble(pl *getPlan, rows []sortRow) (*Result, error) {
	res := &Result{Kind: "get", Access: pl.acc.label(), Scanned: r.scanned}
	colIdx := map[string]int{}
	size := 0
	multi := len(pl.aliases) > 1
	var all [][]cell
	for _, sr := range rows {
		var cells []cell
		for _, it := range pl.items {
			switch {
			case it.Star && it.StarAlias != "":
				for i, a := range pl.aliases {
					if a == it.StarAlias {
						cells = append(cells, r.starCells(sr.t[i], a+".")...)
					}
				}
			case it.Star:
				for i, a := range pl.aliases {
					p := ""
					if multi {
						p = a + "."
					}
					cells = append(cells, r.starCells(sr.t[i], p)...)
				}
			default:
				cells = append(cells, cell{itemName(it), r.eval(it.Expr, sr.t)})
			}
		}
		var err error
		if size, err = r.addRow(res, colIdx, &all, cells, size); err != nil {
			return nil, err
		}
		res.Addrs = append(res.Addrs, sr.t[0].addr)
	}
	r.fillRows(res, colIdx, all)
	return res, nil
}

// addRow registers one row of cells (names made unique inside the row) and tracks result size.
func (r *run) addRow(res *Result, colIdx map[string]int, all *[][]cell, cells []cell, size int) (int, error) {
	seen := map[string]int{}
	for i := range cells {
		seen[cells[i].name]++
		if c := seen[cells[i].name]; c > 1 {
			cells[i].name += "#" + strconv.Itoa(c)
		}
		size += valueSize(cells[i].v) + len(cells[i].name)
		if _, ok := colIdx[cells[i].name]; !ok {
			if len(colIdx) >= r.lim.MaxColumns {
				return size, fmt.Errorf("%w: result has more than %d columns", ErrLimit, r.lim.MaxColumns)
			}
			colIdx[cells[i].name] = len(res.Columns)
			res.Columns = append(res.Columns, cells[i].name)
		}
	}
	if size > r.lim.MaxResultBytes {
		return size, fmt.Errorf("%w: result larger than %d bytes", ErrLimit, r.lim.MaxResultBytes)
	}
	*all = append(*all, cells)
	return size, nil
}

func (r *run) fillRows(res *Result, colIdx map[string]int, all [][]cell) {
	for _, cells := range all {
		row := make([]box.Value, len(res.Columns))
		for _, c := range cells {
			row[colIdx[c.name]] = c.v
		}
		res.Rows = append(res.Rows, row)
	}
}

// ---- aggregates ----------------------------------------------------------

type accum struct {
	count  int
	sum    float64
	n      int
	best   box.Value
	hasVal bool
}

type group struct {
	plain []box.Value // values of the non-aggregate items (the Group keys)
	accs  []*accum
}

func valueKey(v box.Value) string { return strconv.Itoa(int(v.Kind)) + ":" + v.String() }

func (r *run) doAggregate(pl *getPlan, cands []*rec) (*Result, error) {
	g := pl.get
	groups := map[string]*group{}
	var order []*group
	newGroup := func(t tuple) *group {
		gr := &group{plain: make([]box.Value, len(pl.items)), accs: make([]*accum, len(pl.items))}
		for i, it := range pl.items {
			if isAgg(it.Expr) {
				gr.accs[i] = &accum{}
			} else if t != nil {
				gr.plain[i] = r.eval(it.Expr, t)
			}
		}
		order = append(order, gr)
		return gr
	}
	if len(g.Group) == 0 {
		groups[""] = newGroup(nil)
	}
	emit := func(t tuple) (bool, error) {
		var gr *group
		if len(g.Group) == 0 {
			gr = groups[""]
		} else {
			var sb strings.Builder
			for _, k := range g.Group {
				kv := valueKey(r.eval(k, t))
				sb.WriteString(strconv.Itoa(len(kv)))
				sb.WriteByte('|')
				sb.WriteString(kv)
			}
			key := sb.String()
			if gr = groups[key]; gr == nil {
				if len(groups) >= r.lim.MaxRows {
					return false, fmt.Errorf("%w: more than %d groups", ErrLimit, r.lim.MaxRows)
				}
				gr = newGroup(t)
				groups[key] = gr
			}
		}
		for i, it := range pl.items {
			a, ok := it.Expr.(*Agg)
			if !ok {
				continue
			}
			ac := gr.accs[i]
			ac.count++
			if a.Arg == nil {
				continue
			}
			v := r.eval(a.Arg, t)
			switch a.Fn {
			case "sum", "avg":
				if v.Kind == box.KindNumber {
					ac.sum += v.Num
					ac.n++
				}
			case "min", "max":
				if v.Kind == box.KindNell {
					continue
				}
				if !ac.hasVal {
					ac.best, ac.hasVal = v, true
				} else if c := cmpSort(v, ac.best); (a.Fn == "min" && c < 0) || (a.Fn == "max" && c > 0) {
					ac.best = v
				}
			}
		}
		return true, nil
	}
	if err := r.eachTuple(pl, cands, emit); err != nil {
		return nil, err
	}
	finish := func(a *Agg, ac *accum) box.Value {
		switch a.Fn {
		case "count":
			return box.Int(int64(ac.count))
		case "sum":
			if math.IsInf(ac.sum, 0) || math.IsNaN(ac.sum) {
				return box.Nell()
			}
			return box.Number(ac.sum)
		case "avg":
			if ac.n == 0 || math.IsInf(ac.sum, 0) || math.IsNaN(ac.sum) {
				return box.Nell()
			}
			return box.Number(ac.sum / float64(ac.n))
		}
		if ac.hasVal {
			return ac.best
		}
		return box.Nell()
	}
	type outRow struct{ vals []box.Value }
	rows := make([]outRow, 0, len(order))
	for _, gr := range order {
		vals := make([]box.Value, len(pl.items))
		for i, it := range pl.items {
			if a, ok := it.Expr.(*Agg); ok {
				vals[i] = finish(a, gr.accs[i])
			} else {
				vals[i] = gr.plain[i]
			}
		}
		rows = append(rows, outRow{vals})
	}
	if len(pl.sort) > 0 {
		sort.SliceStable(rows, func(i, j int) bool {
			for k, o := range pl.sort {
				c := cmpSort(rows[i].vals[pl.sortCols[k]], rows[j].vals[pl.sortCols[k]])
				if c == 0 {
					continue
				}
				if o.Desc {
					return c > 0
				}
				return c < 0
			}
			return false
		})
	}
	if pl.offset >= len(rows) {
		rows = nil
	} else {
		rows = rows[pl.offset:]
	}
	if pl.limit >= 0 && len(rows) > pl.limit {
		rows = rows[:pl.limit]
	}
	if pl.limit < 0 && len(rows) > r.lim.MaxRows {
		return nil, fmt.Errorf("%w: more than %d result rows; add Limit = n", ErrLimit, r.lim.MaxRows)
	}
	res := &Result{Kind: "get", Access: pl.acc.label(), Scanned: r.scanned, Columns: append([]string(nil), pl.names...)}
	size := 0
	for _, row := range rows {
		for _, v := range row.vals {
			size += valueSize(v)
		}
		res.Rows = append(res.Rows, row.vals)
	}
	if size > r.lim.MaxResultBytes {
		return nil, fmt.Errorf("%w: result larger than %d bytes", ErrLimit, r.lim.MaxResultBytes)
	}
	// duplicate column names get a #n suffix, as in a plain Get
	seen := map[string]int{}
	for i, n := range res.Columns {
		seen[n]++
		if seen[n] > 1 {
			res.Columns[i] = n + "#" + strconv.Itoa(seen[n])
		}
	}
	return res, nil
}
