package query

import (
	"fmt"
	"math"
	"strings"

	"redx/box"
)

// Parse parses one BoxQL command with the default limits. It returns the command and the
// distinct $parameter names in order of first use.
func Parse(src string) (Stmt, []string, error) { return parseWith(src, DefaultLimits()) }

var verbNames = []string{"Get", "Set", "Add", "Delete", "Require", "Tx", "Explain", "Watch"}

var aggFns = map[string]string{"Count": "count", "Sum": "sum", "Avg": "avg", "Min": "min", "Max": "max"}

type parser struct {
	src    string
	toks   []token
	i      int
	params []string
	depth  int
	lim    Limits
	inTx   bool
}

func parseWith(src string, lim Limits) (Stmt, []string, error) {
	lim = lim.withDefaults()
	if len(src) > lim.MaxQueryBytes {
		return nil, nil, fmt.Errorf("%w: %d bytes (limit %d)", ErrTooLarge, len(src), lim.MaxQueryBytes)
	}
	toks, err := lex(src, lim.MaxTokens)
	if err != nil {
		return nil, nil, err
	}
	p := &parser{src: src, toks: toks, lim: lim}
	st, err := p.statement(true)
	if err != nil {
		return nil, nil, err
	}
	if p.isPunct(";") {
		p.i++
	}
	if t := p.peek(); t.kind != tEOF {
		if t.kind == tPunct && t.text == "{" {
			return nil, nil, p.errAt(t, "one command per request; to run several together wrap them: {Tx[]} = [ {Set[]} = ..., {Add[]} = ... ]")
		}
		return nil, nil, p.errAt(t, "unexpected "+t.describe()+" after the end of the command")
	}
	return st, p.params, nil
}

func (p *parser) peek() token { return p.toks[p.i] }
func (p *parser) peekN(n int) token {
	if p.i+n >= len(p.toks) {
		return p.toks[len(p.toks)-1]
	}
	return p.toks[p.i+n]
}
func (p *parser) next() token {
	t := p.toks[p.i]
	if t.kind != tEOF {
		p.i++
	}
	return t
}
func (p *parser) prevEnd() int {
	if p.i == 0 {
		return 0
	}
	return p.toks[p.i-1].end
}

func (p *parser) errAt(t token, msg string) error {
	near := ""
	if t.kind != tEOF {
		near = p.src[t.pos.Offset:t.end]
		if len(near) > 40 {
			near = near[:40] + "..."
		}
	}
	return &SyntaxError{Pos: t.pos, Msg: msg, Near: near}
}

func (p *parser) expected(what string) error {
	t := p.peek()
	return p.errAt(t, fmt.Sprintf("expected %s, found %s", what, t.describe()))
}

func (p *parser) isKw(w string) bool {
	t := p.peek()
	return t.kind == tIdent && t.text == w
}

func (p *parser) isPunct(s string) bool { return p.isPunctN(0, s) }
func (p *parser) isPunctN(n int, s string) bool {
	t := p.peekN(n)
	return t.kind == tPunct && t.text == s
}

func (p *parser) acceptPunct(s string) bool {
	if p.isPunct(s) {
		p.i++
		return true
	}
	return false
}

func (p *parser) expectPunct(s string) (token, error) {
	if !p.isPunct(s) {
		return token{}, p.expected("`" + s + "`")
	}
	return p.next(), nil
}

func (p *parser) enter(t token) error {
	p.depth++
	if p.depth > p.lim.MaxDepth {
		return p.errAt(t, fmt.Sprintf("nested too deeply (limit %d)", p.lim.MaxDepth))
	}
	return nil
}
func (p *parser) leave() { p.depth-- }

func (p *parser) param(t token) *Param {
	for i, n := range p.params {
		if n == t.text {
			return &Param{P: t.pos, Name: t.text, N: i}
		}
	}
	p.params = append(p.params, t.text)
	return &Param{P: t.pos, Name: t.text, N: len(p.params) - 1}
}

// ---- commands ------------------------------------------------------------

// statement parses {Verb[]} = body.
func (p *parser) statement(top bool) (Stmt, error) {
	open := p.peek()
	if !p.isPunct("{") {
		return nil, p.errAt(open, fmt.Sprintf("expected a command such as {Get[]} = Box[...] -> [...], found %s", open.describe()))
	}
	if err := p.enter(open); err != nil {
		return nil, err
	}
	defer p.leave()
	p.i++
	vt := p.peek()
	if vt.kind != tIdent {
		return nil, p.expected("a command name (" + strings.Join(verbNames, ", ") + ")")
	}
	p.i++
	ok := false
	for _, v := range verbNames {
		if v == vt.text {
			ok = true
		}
	}
	if !ok {
		for _, v := range verbNames {
			if strings.EqualFold(v, vt.text) {
				return nil, p.errAt(vt, fmt.Sprintf("unknown command %q; command names are case-sensitive: did you mean %s?", vt.text, v))
			}
		}
		return nil, p.errAt(vt, fmt.Sprintf("unknown command %q (known: %s)", vt.text, strings.Join(verbNames, ", ")))
	}
	if p.acceptPunct("[") {
		if _, err := p.expectPunct("]"); err != nil {
			return nil, p.errAt(vt, "a command takes no attributes: write {"+vt.text+"[]}")
		}
	}
	if _, err := p.expectPunct("}"); err != nil {
		return nil, err
	}
	if _, err := p.expectPunct("="); err != nil {
		return nil, err
	}
	pos := open.pos
	switch vt.text {
	case "Get":
		return p.getStmt(pos)
	case "Add":
		return p.addStmt(pos)
	case "Set":
		return p.setStmt(pos)
	case "Delete":
		return p.deleteStmt(pos)
	case "Require":
		return p.requireStmt(pos)
	case "Watch":
		if p.inTx {
			return nil, p.errAt(vt, "Watch cannot run inside a transaction")
		}
		return p.watchStmt(pos)
	case "Explain":
		if p.inTx {
			return nil, p.errAt(vt, "Explain wraps a whole command; put it outside the transaction: {Explain[]} = [ {Tx[]} = [ ... ] ]")
		}
		return p.explainStmt(pos)
	default: // Tx
		if p.inTx {
			return nil, p.errAt(vt, "transactions do not nest")
		}
		return p.txStmt(pos)
	}
}

func (p *parser) explainStmt(pos Pos) (Stmt, error) {
	if _, err := p.expectPunct("["); err != nil {
		return nil, err
	}
	nt := p.peek()
	in, err := p.statement(false)
	if err != nil {
		return nil, err
	}
	if _, ok := in.(*Watch); ok {
		return nil, p.errAt(nt, "Explain cannot wrap Watch")
	}
	if _, ok := in.(*Explain); ok {
		return nil, p.errAt(nt, "Explain cannot wrap Explain")
	}
	p.acceptPunct(",")
	p.acceptPunct(";")
	if _, err := p.expectPunct("]"); err != nil {
		return nil, err
	}
	return &Explain{P: pos, Inner: in}, nil
}

func (p *parser) txStmt(pos Pos) (Stmt, error) {
	lb, err := p.expectPunct("[")
	if err != nil {
		return nil, err
	}
	p.inTx = true
	defer func() { p.inTx = false }()
	tx := &Tx{P: pos}
	for !p.isPunct("]") {
		if p.peek().kind == tEOF {
			return nil, p.errAt(lb, "unclosed `[` of the transaction")
		}
		st, err := p.statement(false)
		if err != nil {
			return nil, err
		}
		tx.Stmts = append(tx.Stmts, st)
		if len(tx.Stmts) > p.lim.MaxTxStmts {
			return nil, p.errAt(p.peek(), fmt.Sprintf("too many commands in one transaction (limit %d)", p.lim.MaxTxStmts))
		}
		if !p.acceptPunct(",") {
			p.acceptPunct(";")
		}
	}
	p.i++
	if len(tx.Stmts) == 0 {
		return nil, p.errAt(lb, "a transaction needs at least one command")
	}
	return tx, nil
}

func (p *parser) getStmt(pos Pos) (Stmt, error) {
	src, err := p.source()
	if err != nil {
		return nil, err
	}
	g := &Get{P: pos, From: src, Where: src.Where}
	if p.acceptPunct("->") {
		g.Items, err = p.projection()
		if err != nil {
			return nil, err
		}
	}
	for p.isPunct("@>") || p.isPunct("@!>") {
		if p.isPunct("@!>") {
			return nil, p.errAt(p.peek(), "@!> is the cascade-delete link; to read through a link use @> Field")
		}
		f, err := p.follow()
		if err != nil {
			return nil, err
		}
		g.Follows = append(g.Follows, f)
		if len(g.Follows) > p.lim.MaxJoins {
			return nil, p.errAt(p.peek(), fmt.Sprintf("too many @> follows (limit %d)", p.lim.MaxJoins))
		}
	}
	seen := map[string]bool{}
	err = p.options(seen, []string{"Sort", "Limit", "Offset", "Group"}, func(name token) error {
		var e error
		switch name.text {
		case "Sort":
			g.Sort, e = p.sortKeys()
		case "Group":
			g.Group, e = p.exprList()
		case "Limit":
			g.Limit, e = p.countExpr("Limit")
		case "Offset":
			g.Offset, e = p.countExpr("Offset")
		}
		return e
	})
	if err != nil {
		return nil, err
	}
	return g, nil
}

// options parses `, Name = value` options in any order.
func (p *parser) options(seen map[string]bool, allowed []string, one func(name token) error) error {
	for p.isPunct(",") {
		n1, n2 := p.peekN(1), p.peekN(2)
		if n1.kind == tEOF || (n1.kind == tPunct && (n1.text == "]" || n1.text == "{")) {
			p.i++ // trailing comma
			continue
		}
		if n1.kind != tIdent || n2.kind != tPunct || n2.text != "=" {
			return p.errAt(n1, "expected an option such as "+allowed[0]+"=... after `,`")
		}
		ok := false
		for _, a := range allowed {
			if a == n1.text {
				ok = true
			}
		}
		if !ok {
			return p.errAt(n1, fmt.Sprintf("unknown option %q here (allowed: %s)", n1.text, strings.Join(allowed, ", ")))
		}
		if seen[n1.text] {
			return p.errAt(n1, fmt.Sprintf("option %s given twice", n1.text))
		}
		seen[n1.text] = true
		p.i += 3
		if err := one(n1); err != nil {
			return err
		}
	}
	return nil
}

func (p *parser) countExpr(what string) (Expr, error) {
	t := p.peek()
	switch t.kind {
	case tNumber:
		if t.num != math.Trunc(t.num) || t.num < 0 || t.num > 1<<53 {
			return nil, p.errAt(t, what+" must be a non-negative whole number")
		}
		p.i++
		return &Lit{P: t.pos, V: box.Number(t.num)}, nil
	case tParam:
		p.i++
		return p.param(t), nil
	}
	return nil, p.expected(what + " as a whole number or $param")
}

func (p *parser) exprList() ([]Expr, error) {
	if p.isPunct(";") && p.isPunctN(1, "[") {
		a, err := p.arrayLit()
		if err != nil {
			return nil, err
		}
		return a.(*ArrLit).Items, nil
	}
	e, err := p.additive()
	if err != nil {
		return nil, err
	}
	return []Expr{e}, nil
}

func (p *parser) sortKeys() ([]SortKey, error) {
	one := func() (SortKey, error) {
		desc := false
		if p.isPunct("-") {
			desc = true
			p.i++
		} else if p.isPunct("+") {
			p.i++
		}
		e, err := p.additive()
		return SortKey{Expr: e, Desc: desc}, err
	}
	if p.isPunct(";") && p.isPunctN(1, "[") {
		p.i += 2
		var out []SortKey
		for !p.isPunct("]") {
			k, err := one()
			if err != nil {
				return nil, err
			}
			out = append(out, k)
			if !p.acceptPunct(",") {
				break
			}
		}
		if _, err := p.expectPunct("]"); err != nil {
			return nil, err
		}
		if _, err := p.expectPunct(":"); err != nil {
			return nil, err
		}
		if len(out) == 0 {
			return nil, p.errAt(p.peek(), "Sort needs at least one key")
		}
		return out, nil
	}
	k, err := one()
	if err != nil {
		return nil, err
	}
	return []SortKey{k}, nil
}

func (p *parser) projection() ([]Proj, error) {
	if p.isPunct("*") {
		t := p.next()
		return []Proj{{Star: true, P: t.pos, Text: "*"}}, nil
	}
	if !p.isPunct("[") {
		it, err := p.projItem()
		if err != nil {
			return nil, err
		}
		return []Proj{it}, nil
	}
	lb := p.next()
	var items []Proj
	for !p.isPunct("]") {
		if p.peek().kind == tEOF {
			return nil, p.errAt(lb, "unclosed `[` of the projection")
		}
		it, err := p.projItem()
		if err != nil {
			return nil, err
		}
		items = append(items, it)
		if !p.acceptPunct(",") {
			break
		}
	}
	if _, err := p.expectPunct("]"); err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, p.errAt(lb, "empty projection; use -> * for every field")
	}
	return items, nil
}

func (p *parser) projItem() (Proj, error) {
	t := p.peek()
	it := Proj{P: t.pos}
	switch {
	case p.isPunct("*"):
		p.i++
		it.Star, it.Text = true, "*"
		return it, nil
	case t.kind == tIdent && p.isPunctN(1, ".") && p.isPunctN(2, "*"):
		p.i += 3
		it.Star, it.StarAlias = true, t.text
		it.Text = t.text + ".*"
		return it, nil
	case t.kind == tIdent && p.isPunctN(1, "="):
		it.As = t.text
		p.i += 2
	}
	start := p.peek()
	e, err := p.expr()
	if err != nil {
		return it, err
	}
	it.Expr = e
	it.Text = strings.TrimSpace(p.src[start.pos.Offset:p.prevEnd()])
	return it, p.checkAgg(e, true)
}

// checkAgg allows aggregate calls only as a whole projection item.
func (p *parser) checkAgg(e Expr, top bool) error {
	if a, ok := e.(*Agg); ok && top {
		if a.Arg != nil {
			var bad *Agg
			walk(a.Arg, func(x Expr) {
				if g, ok := x.(*Agg); ok && bad == nil {
					bad = g
				}
			})
			if bad != nil {
				return &SyntaxError{Pos: bad.P, Msg: "aggregates cannot be nested"}
			}
		}
		return nil
	}
	var bad *Agg
	walk(e, func(x Expr) {
		if g, ok := x.(*Agg); ok && bad == nil {
			bad = g
		}
	})
	if bad != nil {
		return &SyntaxError{Pos: bad.P, Msg: "an aggregate (Count, Sum, Avg, Min, Max) must be a whole projection item, e.g. -> [Count(), Total = Sum(Price)]; it cannot be used inside another expression or a filter"}
	}
	return nil
}

func (p *parser) follow() (Follow, error) {
	t := p.next() // @>
	f := Follow{P: t.pos}
	if a := p.peek(); a.kind == tIdent && p.isPunctN(1, "=") {
		f.Alias = a.text
		p.i += 2
	}
	via, err := p.fieldPath()
	if err != nil {
		return f, err
	}
	f.Via = via
	if p.acceptPunct("?") {
		f.Left = true
	}
	return f, nil
}

// source parses [file:]Box[filters].
func (p *parser) source() (Source, error) {
	t := p.peek()
	s := Source{P: t.pos}
	switch {
	case (t.kind == tIdent || t.kind == tString) && p.isPunctN(1, ":"):
		s.File = t.text
		p.i += 2
		bt := p.peek()
		switch {
		case bt.kind == tIdent:
			s.Box = bt.text
			p.i++
		case p.isPunct("*"):
			p.i++
		default:
			return s, p.expected("a box name or * after `" + t.text + ":`")
		}
	case t.kind == tIdent:
		s.Box = t.text
		p.i++
	case t.kind == tString:
		return s, p.errAt(t, "a quoted file name must be followed by `:Box`")
	default:
		return s, p.expected("a source such as Player[...] or players:Player[...]")
	}
	if !p.isPunct("[") {
		return s, nil
	}
	lb := p.next()
	if err := p.enter(lb); err != nil {
		return s, err
	}
	defer p.leave()
	switch {
	case p.isPunct("*") && p.isPunctN(1, "]"):
		p.i += 2
		s.All = true
		return s, nil
	case p.peek().kind == tIdent && strings.EqualFold(p.peek().text, "ID") && p.isPunctN(1, "=") && p.isPunctN(2, "*"):
		p.i += 3
		if _, err := p.expectPunct("]"); err != nil {
			return s, err
		}
		s.All = true
		return s, nil
	case p.peek().kind == tNumber && p.isPunctN(1, "]"):
		nt := p.next()
		p.i++
		if nt.num != math.Trunc(nt.num) || math.Abs(nt.num) > 1<<53 {
			return s, p.errAt(nt, "an ID must be a whole number")
		}
		s.Where = &Binary{P: nt.pos, Op: "=", L: &Field{P: nt.pos, Segs: []box.Seg{{Name: "ID"}}, Raw: "ID"}, R: &Lit{P: nt.pos, V: box.Number(nt.num)}}
		return s, nil
	}
	if t := p.peek(); t.kind == tParam && p.isPunctN(1, "]") {
		p.i += 2 // [$id] is [ID=$id]
		s.Where = &Binary{P: t.pos, Op: "=", L: &Field{P: t.pos, Segs: []box.Seg{{Name: "ID"}}, Raw: "ID"}, R: p.param(t)}
		return s, nil
	}
	for {
		if p.isPunct("]") {
			break
		}
		if p.peek().kind == tEOF {
			return s, p.errAt(lb, "unclosed `[` of the filter")
		}
		e, err := p.expr()
		if err != nil {
			return s, err
		}
		if err := p.checkAgg(e, false); err != nil {
			return s, err
		}
		if s.Where == nil {
			s.Where = e
		} else {
			s.Where = &Binary{P: e.exprPos(), Op: "and", L: s.Where, R: e}
		}
		if !p.acceptPunct(",") {
			break
		}
	}
	if _, err := p.expectPunct("]"); err != nil {
		return s, err
	}
	return s, nil
}

func (p *parser) addStmt(pos Pos) (Stmt, error) {
	src, err := p.source()
	if err != nil {
		return nil, err
	}
	if _, err := p.expectPunct("="); err != nil {
		return nil, err
	}
	rec, err := p.recLit()
	if err != nil {
		return nil, err
	}
	a := &Add{P: pos, Target: src, Rec: rec}
	a.TTL, err = p.ttl()
	return a, err
}

func (p *parser) setStmt(pos Pos) (Stmt, error) {
	src, err := p.source()
	if err != nil {
		return nil, err
	}
	s := &Set{P: pos, Target: src, Where: src.Where}
	switch {
	case p.acceptPunct("."):
		if p.isPunct("[") {
			lb := p.next()
			for !p.isPunct("]") {
				if p.peek().kind == tEOF {
					return nil, p.errAt(lb, "unclosed `[` of the assignments")
				}
				a, err := p.assign()
				if err != nil {
					return nil, err
				}
				s.Assigns = append(s.Assigns, a)
				if !p.acceptPunct(",") {
					break
				}
			}
			if _, err := p.expectPunct("]"); err != nil {
				return nil, err
			}
			if len(s.Assigns) == 0 {
				return nil, p.errAt(lb, "empty assignment list")
			}
		} else {
			a, err := p.assign()
			if err != nil {
				return nil, err
			}
			s.Assigns = []Assign{a}
		}
	case p.isPunct("="):
		p.i++
		s.Replace, err = p.recLit()
		if err != nil {
			return nil, err
		}
	default:
		return nil, p.expected("`.field = value` or `= [ record ]` after the Set target")
	}
	s.TTL, err = p.ttl()
	return s, err
}

func (p *parser) assign() (Assign, error) {
	f, err := p.fieldPath()
	if err != nil {
		return Assign{}, err
	}
	if _, err := p.expectPunct("="); err != nil {
		return Assign{}, err
	}
	v, err := p.expr()
	if err != nil {
		return Assign{}, err
	}
	if err := p.checkAgg(v, false); err != nil {
		return Assign{}, err
	}
	return Assign{Target: f, Value: v}, nil
}

func (p *parser) deleteStmt(pos Pos) (Stmt, error) {
	src, err := p.source()
	if err != nil {
		return nil, err
	}
	d := &Delete{P: pos, Target: src, Where: src.Where}
	if p.acceptPunct(".") {
		d.Path, err = p.fieldPath()
	}
	return d, err
}

func (p *parser) requireStmt(pos Pos) (Stmt, error) {
	src, err := p.source()
	if err != nil {
		return nil, err
	}
	r := &Require{P: pos, Target: src, Where: src.Where}
	err = p.options(map[string]bool{}, []string{"Count"}, func(name token) error {
		var e error
		r.Count, e = p.countExpr("Count")
		return e
	})
	return r, err
}

func (p *parser) watchStmt(pos Pos) (Stmt, error) {
	if t := p.peek(); t.kind == tIdent && t.text == "Topic" && p.isPunctN(1, "=") {
		p.i += 2
		s := p.peek()
		if s.kind != tString {
			return nil, p.expected("a topic pattern in quotes, e.g. Topic = \"player.*\"")
		}
		p.i++
		return &Watch{P: pos, Pulse: true, Topic: s.text}, nil
	}
	src, err := p.source()
	if err != nil {
		return nil, err
	}
	return &Watch{P: pos, Target: src, Where: src.Where}, nil
}

// ttl parses an optional (N), (~N) or (N)* marker.
func (p *parser) ttl() (TTLSpec, error) {
	if !p.isPunct("(") {
		return TTLSpec{}, nil
	}
	lp := p.next()
	sliding := p.acceptPunct("~")
	nt := p.peek()
	if nt.kind != tNumber || nt.num != math.Trunc(nt.num) || nt.num < 1 || nt.num > math.MaxInt32 {
		return TTLSpec{}, p.errAt(nt, "a TTL is a whole number of seconds (N), (~N) or (N)*")
	}
	p.i++
	if _, err := p.expectPunct(")"); err != nil {
		return TTLSpec{}, p.errAt(lp, "unclosed `(` of the TTL")
	}
	star := p.acceptPunct("*")
	switch {
	case sliding && star:
		return TTLSpec{}, p.errAt(lp, "a TTL cannot be both sliding (~N) and a checkpoint (N)*")
	case sliding:
		return TTLSpec{Kind: box.TTLSliding, Seconds: int(nt.num)}, nil
	case star:
		return TTLSpec{Kind: box.TTLCheckpoint, Seconds: int(nt.num)}, nil
	}
	return TTLSpec{Kind: box.TTLFixed, Seconds: int(nt.num)}, nil
}

// ---- record literals -----------------------------------------------------

// recLit parses [ {Key[ID=n]} = value (ttl)? ... ].
func (p *parser) recLit() (*RecLit, error) {
	lb, err := p.expectPunct("[")
	if err != nil {
		return nil, err
	}
	if err := p.enter(lb); err != nil {
		return nil, err
	}
	defer p.leave()
	r := &RecLit{P: lb.pos}
	seen := map[string]bool{}
	for !p.isPunct("]") {
		if p.peek().kind == tEOF {
			return nil, p.errAt(lb, "unclosed `[` of the record")
		}
		ob, err := p.expectPunct("{")
		if err != nil {
			return nil, err
		}
		kt := p.peek()
		if kt.kind != tIdent {
			return nil, p.expected("a field name")
		}
		p.i++
		e := RecEntry{P: ob.pos, Key: kt.text}
		if p.acceptPunct("[") {
			if !p.isPunct("]") {
				if k := p.peek(); k.kind == tIdent && strings.EqualFold(k.text, "ID") && p.isPunctN(1, "=") {
					p.i += 2
				}
				nt := p.peek()
				if nt.kind != tNumber || nt.num != math.Trunc(nt.num) || math.Abs(nt.num) > 1<<53 {
					return nil, p.errAt(nt, "expected a whole number ID, as in {Item[ID=3]}")
				}
				p.i++
				id := int64(nt.num)
				e.ID = &id
			}
			if _, err := p.expectPunct("]"); err != nil {
				return nil, err
			}
		}
		if _, err := p.expectPunct("}"); err != nil {
			return nil, err
		}
		if _, err := p.expectPunct("="); err != nil {
			return nil, err
		}
		vt := p.peek()
		switch {
		case p.isPunct("["):
			e.Value, err = p.recLit()
		case vt.kind == tString && p.isPunctN(1, ":"):
			e.Value, err = p.linkLit()
		default:
			e.Value, err = p.expr()
		}
		if err != nil {
			return nil, err
		}
		var bad Expr
		walk(e.Value, func(x Expr) {
			switch x.(type) {
			case *Field, *Agg:
				if bad == nil {
					bad = x
				}
			}
		})
		if bad != nil {
			return nil, &SyntaxError{Pos: bad.exprPos(), Msg: "a record literal holds values only; it cannot refer to fields (use {Set[]} = Box[...].Field = expr for computed values)"}
		}
		e.TTL, err = p.ttl()
		if err != nil {
			return nil, err
		}
		id := "-"
		if e.ID != nil {
			id = fmt.Sprint(*e.ID)
		}
		if seen[e.Key+"\x00"+id] {
			return nil, p.errAt(kt, fmt.Sprintf("entry %s appears twice in the record", e.Key))
		}
		seen[e.Key+"\x00"+id] = true
		r.Entries = append(r.Entries, e)
		if !p.acceptPunct(",") {
			p.acceptPunct(";")
		}
	}
	p.i++
	return r, nil
}

// linkLit parses a link literal such as "players":Player[ID=1].Name @> "guilds":Guild[ID=2]
// by taking its text through the token stream and handing it to the Box parser.
func (p *parser) linkLit() (Expr, error) {
	start := p.peek()
	ref := func() error {
		if t := p.peek(); t.kind != tString || !p.isPunctN(1, ":") {
			return p.expected("a link reference \"file\":Box[ID=n]")
		}
		p.i += 2
		for {
			if t := p.peek(); t.kind != tIdent {
				return p.expected("a name in the link reference")
			}
			p.i++
			if p.isPunct("[") {
				for !p.isPunct("]") {
					if p.peek().kind == tEOF {
						return p.errAt(start, "unclosed `[` in the link")
					}
					p.i++
				}
				p.i++
			}
			if !p.acceptPunct(".") {
				return nil
			}
		}
	}
	if err := ref(); err != nil {
		return nil, err
	}
	if p.isPunct("@>") || p.isPunct("@!>") {
		p.i++
		if err := ref(); err != nil {
			return nil, err
		}
	}
	v, err := box.ParseValue(p.src[start.pos.Offset:p.prevEnd()])
	if err != nil {
		return nil, p.errAt(start, "bad link: "+err.Error())
	}
	return &Lit{P: start.pos, V: v}, nil
}

// ---- expressions ---------------------------------------------------------

func (p *parser) expr() (Expr, error) {
	t := p.peek()
	if err := p.enter(t); err != nil {
		return nil, err
	}
	defer p.leave()
	return p.orExpr()
}

func (p *parser) orExpr() (Expr, error) {
	l, err := p.andExpr()
	if err != nil {
		return nil, err
	}
	for p.isPunct("|") {
		t := p.next()
		r, err := p.andExpr()
		if err != nil {
			return nil, err
		}
		l = &Binary{P: t.pos, Op: "or", L: l, R: r}
	}
	return l, nil
}

func (p *parser) andExpr() (Expr, error) {
	l, err := p.notExpr()
	if err != nil {
		return nil, err
	}
	for p.isPunct("&") {
		t := p.next()
		r, err := p.notExpr()
		if err != nil {
			return nil, err
		}
		l = &Binary{P: t.pos, Op: "and", L: l, R: r}
	}
	return l, nil
}

func (p *parser) notExpr() (Expr, error) {
	if p.isPunct("!") {
		t := p.next()
		if err := p.enter(t); err != nil {
			return nil, err
		}
		defer p.leave()
		x, err := p.notExpr()
		if err != nil {
			return nil, err
		}
		return &Not{P: t.pos, X: x}, nil
	}
	return p.predicate()
}

func (p *parser) predicate() (Expr, error) {
	l, err := p.additive()
	if err != nil {
		return nil, err
	}
	t := p.peek()
	if t.kind == tPunct {
		switch t.text {
		case "=", "!=", "<", "<=", ">", ">=":
			p.i++
			r, err := p.additive()
			if err != nil {
				return nil, err
			}
			if isNell(r) || isNell(l) {
				if t.text != "=" && t.text != "!=" {
					return nil, p.errAt(t, "NELL can only be compared with = or !=")
				}
				x := l
				if isNell(l) {
					x = r
				}
				return &IsNell{P: t.pos, X: x, Neg: t.text == "!="}, nil
			}
			return &Binary{P: t.pos, Op: t.text, L: l, R: r}, nil
		}
		return l, nil
	}
	if t.kind != tIdent {
		return l, nil
	}
	switch t.text {
	case "in":
		p.i++
		return p.inExpr(t, l)
	case "starts":
		p.i++
		pat, err := p.additive()
		if err != nil {
			return nil, err
		}
		return &Starts{P: t.pos, X: l, Pat: pat}, nil
	case "has", "hasany":
		f, ok := l.(*Field)
		if !ok {
			return nil, p.errAt(t, t.text+" applies to a field: Field "+t.text+" \"words\"")
		}
		p.i++
		terms, err := p.additive()
		if err != nil {
			return nil, err
		}
		return &Match{P: t.pos, Field: f, Terms: terms, Any: t.text == "hasany"}, nil
	}
	return l, nil
}

func isNell(e Expr) bool {
	l, ok := e.(*Lit)
	return ok && l.V.Kind == box.KindNell
}

// inExpr parses what follows `in`: ;[a, b]: , lo..hi or $param.
func (p *parser) inExpr(op token, x Expr) (Expr, error) {
	t := p.peek()
	switch {
	case t.kind == tPunct && t.text == ";":
		a, err := p.arrayLit()
		if err != nil {
			return nil, err
		}
		items := a.(*ArrLit).Items
		if len(items) > p.lim.MaxInList {
			return nil, p.errAt(t, fmt.Sprintf("too many items in the list (limit %d)", p.lim.MaxInList))
		}
		return &In{P: op.pos, X: x, List: items}, nil
	case t.kind == tParam && !(p.isPunctN(1, "..")):
		p.i++
		return &In{P: op.pos, X: x, List: []Expr{p.param(t)}}, nil
	}
	lo, err := p.additive()
	if err != nil {
		return nil, err
	}
	if !p.acceptPunct("..") {
		return nil, p.errAt(p.peek(), "expected `..` (a range, as in Level in 5..10), a list ;[a, b]: or a $param after `in`")
	}
	hi, err := p.additive()
	if err != nil {
		return nil, err
	}
	return &InRange{P: op.pos, X: x, Lo: lo, Hi: hi}, nil
}

func (p *parser) additive() (Expr, error) {
	l, err := p.term()
	if err != nil {
		return nil, err
	}
	for p.isPunct("+") || p.isPunct("-") {
		t := p.next()
		r, err := p.term()
		if err != nil {
			return nil, err
		}
		l = &Binary{P: t.pos, Op: t.text, L: l, R: r}
	}
	return l, nil
}

func (p *parser) term() (Expr, error) {
	l, err := p.unary()
	if err != nil {
		return nil, err
	}
	for p.isPunct("*") || p.isPunct("/") {
		t := p.next()
		r, err := p.unary()
		if err != nil {
			return nil, err
		}
		l = &Binary{P: t.pos, Op: t.text, L: l, R: r}
	}
	return l, nil
}

func (p *parser) unary() (Expr, error) {
	if p.isPunct("-") {
		t := p.next()
		if err := p.enter(t); err != nil {
			return nil, err
		}
		defer p.leave()
		x, err := p.unary()
		if err != nil {
			return nil, err
		}
		return &Unary{P: t.pos, Op: "-", X: x}, nil
	}
	return p.primary()
}

func (p *parser) arrayLit() (Expr, error) {
	st := p.next() // ;
	if _, err := p.expectPunct("["); err != nil {
		return nil, err
	}
	if err := p.enter(st); err != nil {
		return nil, err
	}
	defer p.leave()
	a := &ArrLit{P: st.pos}
	for !p.isPunct("]") {
		if p.peek().kind == tEOF {
			return nil, p.errAt(st, "unclosed `;[` of the array")
		}
		e, err := p.expr()
		if err != nil {
			return nil, err
		}
		a.Items = append(a.Items, e)
		if !p.acceptPunct(",") {
			break
		}
	}
	if _, err := p.expectPunct("]"); err != nil {
		return nil, err
	}
	if _, err := p.expectPunct(":"); err != nil {
		return nil, p.errAt(st, "an array is written ;[a, b]: and needs its closing `:`")
	}
	return a, nil
}

func (p *parser) primary() (Expr, error) {
	t := p.peek()
	switch t.kind {
	case tNumber:
		p.i++
		return &Lit{P: t.pos, V: box.Number(t.num)}, nil
	case tString:
		if p.isPunctN(1, ":") {
			return p.linkLit()
		}
		p.i++
		if len(t.text) > p.lim.MaxParamBytes {
			return nil, p.errAt(t, "string literal too large")
		}
		return &Lit{P: t.pos, V: box.String(t.text)}, nil
	case tParam:
		p.i++
		return p.param(t), nil
	case tPunct:
		switch t.text {
		case "(":
			p.i++
			e, err := p.expr()
			if err != nil {
				return nil, err
			}
			if _, err := p.expectPunct(")"); err != nil {
				return nil, p.errAt(t, "unclosed `(`")
			}
			return e, nil
		case ";":
			if p.isPunctN(1, "[") {
				return p.arrayLit()
			}
		case "[":
			return p.recLit()
		}
	case tIdent:
		switch strings.ToUpper(t.text) {
		case "TRUE":
			p.i++
			return &Lit{P: t.pos, V: box.Bool(true)}, nil
		case "FALSE":
			p.i++
			return &Lit{P: t.pos, V: box.Bool(false)}, nil
		case "NELL":
			p.i++
			return &Lit{P: t.pos, V: box.Nell()}, nil
		}
		if fn, ok := aggFns[t.text]; ok && p.isPunctN(1, "(") {
			p.i += 2
			a := &Agg{P: t.pos, Fn: fn}
			if p.isPunct(")") {
				if fn != "count" {
					return nil, p.errAt(t, t.text+" needs an argument: "+t.text+"(Field)")
				}
				p.i++
				return a, nil
			}
			if fn == "count" {
				return nil, p.errAt(p.peek(), "Count() takes no argument")
			}
			arg, err := p.additive()
			if err != nil {
				return nil, err
			}
			if _, err := p.expectPunct(")"); err != nil {
				return nil, err
			}
			a.Arg = arg
			return a, nil
		}
		return p.fieldPath()
	}
	return nil, p.expected("a value, field or `(`")
}

// fieldPath parses name{[ID=n]}{.name{[ID=n]}}.
func (p *parser) fieldPath() (*Field, error) {
	first := p.peek()
	f := &Field{P: first.pos}
	for {
		t := p.peek()
		if t.kind != tIdent {
			if len(f.Segs) == 0 {
				return nil, p.expected("a field name")
			}
			return nil, p.expected("a field name after `.`")
		}
		seg := box.Seg{Name: t.text}
		p.i++
		if p.isPunct("[") {
			lb := p.next()
			if k := p.peek(); k.kind == tIdent && strings.EqualFold(k.text, "ID") && p.isPunctN(1, "=") {
				p.i += 2
			}
			nt := p.peek()
			if nt.kind != tNumber || nt.num != math.Trunc(nt.num) || math.Abs(nt.num) > 1<<53 {
				return nil, p.errAt(nt, "expected a whole number ID in [...]")
			}
			p.i++
			if _, err := p.expectPunct("]"); err != nil {
				return nil, p.errAt(lb, "unclosed `[` in field path")
			}
			seg.ID, seg.HasID = int64(nt.num), true
		}
		f.Segs = append(f.Segs, seg)
		if len(f.Segs) > p.lim.MaxPathDepth {
			return nil, p.errAt(t, fmt.Sprintf("field path too deep (limit %d)", p.lim.MaxPathDepth))
		}
		// "." continues the path unless it starts ".*" (Alias.*) or is part of a ".."
		if p.isPunct(".") && !p.isPunctN(1, "*") && p.peekN(1).kind == tIdent {
			p.i++
			continue
		}
		break
	}
	f.Raw = strings.TrimSpace(p.src[first.pos.Offset:p.prevEnd()])
	return f, nil
}

// walk visits e and all of its sub-expressions (pre-order).
func walk(e Expr, fn func(Expr)) {
	if e == nil {
		return
	}
	fn(e)
	switch x := e.(type) {
	case *Unary:
		walk(x.X, fn)
	case *Not:
		walk(x.X, fn)
	case *Binary:
		walk(x.L, fn)
		walk(x.R, fn)
	case *In:
		walk(x.X, fn)
		for _, v := range x.List {
			walk(v, fn)
		}
	case *Starts:
		walk(x.X, fn)
		walk(x.Pat, fn)
	case *InRange:
		walk(x.X, fn)
		walk(x.Lo, fn)
		walk(x.Hi, fn)
	case *IsNell:
		walk(x.X, fn)
	case *Match:
		fn(x.Field)
		walk(x.Terms, fn)
	case *ArrLit:
		for _, v := range x.Items {
			walk(v, fn)
		}
	case *RecLit:
		for _, en := range x.Entries {
			walk(en.Value, fn)
		}
	case *Agg:
		walk(x.Arg, fn)
	}
}
