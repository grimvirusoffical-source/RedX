package query

import (
	"strconv"
	"strings"

	"redx/box"
)

// quoteStr writes s as a Box string literal.
func quoteStr(s string) string {
	var sb strings.Builder
	sb.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\n':
			sb.WriteString(`\n`)
		case '\r':
			sb.WriteString(`\r`)
		case '\t':
			sb.WriteString(`\t`)
		default:
			if r < 0x20 {
				sb.WriteString(`\u00`)
				sb.WriteString(strconv.FormatInt(int64(r)+0x100, 16)[1:])
			} else {
				sb.WriteRune(r)
			}
		}
	}
	sb.WriteByte('"')
	return sb.String()
}

// litString renders a literal value in full, as BoxQL source.
func litString(v box.Value) string {
	switch v.Kind {
	case box.KindString:
		return quoteStr(v.Str)
	case box.KindNumber:
		return strconv.FormatFloat(v.Num, 'g', -1, 64)
	case box.KindLink:
		if v.Link != nil {
			return v.Link.String()
		}
	}
	return fmtValue(v)
}

// Operator precedence of the printer, loosest first.
const (
	pOr = iota + 1
	pAnd
	pNot
	pCmp
	pAdd
	pMul
	pUnary
	pPrimary
)

func precOf(e Expr) int {
	switch x := e.(type) {
	case *Binary:
		switch x.Op {
		case "or":
			return pOr
		case "and":
			return pAnd
		case "+", "-":
			return pAdd
		case "*", "/":
			return pMul
		}
		return pCmp
	case *Not:
		return pNot
	case *In, *InRange, *Starts, *IsNell, *Match:
		return pCmp
	case *Unary:
		return pUnary
	}
	return pPrimary
}

// exprString renders an expression as BoxQL source, with as few parentheses as the grammar
// allows. With params, $name placeholders are replaced by their bound values (used in plans);
// without, they are written as $name.
func exprString(e Expr, params []box.Value) string { return exprPrec(e, params, 0) }

func exprPrec(e Expr, params []box.Value, min int) string {
	s := exprStr(e, params)
	if e != nil && precOf(e) < min {
		return "(" + s + ")"
	}
	return s
}

func exprStr(e Expr, params []box.Value) string {
	sub := func(x Expr, min int) string { return exprPrec(x, params, min) }
	switch x := e.(type) {
	case nil:
		return ""
	case *Lit:
		if params == nil {
			return litString(x.V)
		}
		return fmtValue(x.V)
	case *Param:
		if params != nil && x.N < len(params) {
			return fmtValue(params[x.N])
		}
		return "$" + x.Name
	case *Field:
		return fieldStr(x)
	case *Unary:
		return "-" + sub(x.X, pUnary)
	case *Not:
		return "!" + sub(x.X, pPrimary)
	case *Binary:
		switch x.Op {
		case "and":
			return sub(x.L, pAnd) + " & " + sub(x.R, pAnd+1)
		case "or":
			return sub(x.L, pOr) + " | " + sub(x.R, pOr+1)
		case "+", "-":
			return sub(x.L, pAdd) + " " + x.Op + " " + sub(x.R, pAdd+1)
		case "*", "/":
			return sub(x.L, pMul) + " " + x.Op + " " + sub(x.R, pMul+1)
		}
		if f, ok := x.L.(*Field); ok && x.Op == "=" && isIDField(f) {
			return "ID=" + sub(x.R, pAdd)
		}
		return sub(x.L, pAdd) + " " + x.Op + " " + sub(x.R, pAdd)
	case *In:
		if len(x.List) == 1 {
			if _, ok := x.List[0].(*Param); ok {
				return sub(x.X, pAdd) + " in " + exprString(x.List[0], params)
			}
		}
		parts := make([]string, len(x.List))
		for i, v := range x.List {
			parts[i] = exprString(v, params)
		}
		return sub(x.X, pAdd) + " in ;[" + strings.Join(parts, ", ") + "]:"
	case *Starts:
		return sub(x.X, pAdd) + " starts " + sub(x.Pat, pAdd)
	case *InRange:
		return sub(x.X, pAdd) + " in " + sub(x.Lo, pAdd) + ".." + sub(x.Hi, pAdd)
	case *IsNell:
		if x.Neg {
			return sub(x.X, pAdd) + " != NELL"
		}
		return sub(x.X, pAdd) + " = NELL"
	case *Match:
		fn := "has"
		if x.Any {
			fn = "hasany"
		}
		return fieldStr(x.Field) + " " + fn + " " + sub(x.Terms, pAdd)
	case *ArrLit:
		parts := make([]string, len(x.Items))
		for i, v := range x.Items {
			parts[i] = exprString(v, params)
		}
		return ";[" + strings.Join(parts, ", ") + "]:"
	case *RecLit:
		parts := make([]string, len(x.Entries))
		for i, en := range x.Entries {
			k := "{" + en.Key
			if en.ID != nil {
				k += "[ID=" + strconv.FormatInt(*en.ID, 10) + "]"
			} else {
				k += "[]"
			}
			parts[i] = k + "} = " + exprString(en.Value, params) + ttlString(en.TTL)
		}
		return "[ " + strings.Join(parts, ", ") + " ]"
	case *Agg:
		name := strings.ToUpper(x.Fn[:1]) + x.Fn[1:]
		return name + "(" + exprString(x.Arg, params) + ")"
	}
	return "?"
}

func ttlString(t TTLSpec) string {
	switch t.Kind {
	case box.TTLFixed:
		return " (" + strconv.Itoa(t.Seconds) + ")"
	case box.TTLSliding:
		return " (~" + strconv.Itoa(t.Seconds) + ")"
	case box.TTLCheckpoint:
		return " (" + strconv.Itoa(t.Seconds) + ")*"
	}
	return ""
}

func (s Source) String() string {
	var sb strings.Builder
	if s.File != "" {
		if validBare(s.File) {
			sb.WriteString(s.File)
		} else {
			sb.WriteString(quoteStr(s.File))
		}
		sb.WriteByte(':')
	}
	if s.Box == "" && s.File != "" {
		sb.WriteByte('*')
	} else {
		sb.WriteString(s.Box)
	}
	switch {
	case s.All:
		sb.WriteString("[ID=*]")
	case s.Where != nil:
		conds := flattenAnd(s.Where, nil)
		parts := make([]string, len(conds))
		for i, c := range conds {
			parts[i] = exprPrec(c, nil, pOr)
		}
		sb.WriteString("[" + strings.Join(parts, ", ") + "]")
	}
	return sb.String()
}

func validBare(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if !(isIdentStart(r) || (i > 0 && (isIdentPart(r) || r == '-'))) {
			return false
		}
	}
	return !strings.HasSuffix(s, "-") && !strings.Contains(s, "--")
}

// String renders the command as canonical BoxQL; Parse(st.String()) yields an equal tree.
func StmtString(st Stmt) string {
	switch s := st.(type) {
	case *Get:
		var sb strings.Builder
		sb.WriteString("{Get[]} = " + s.From.String())
		if len(s.Items) == 1 && s.Items[0].Star && s.Items[0].StarAlias == "" {
			sb.WriteString(" -> *")
		} else if len(s.Items) > 0 {
			parts := make([]string, len(s.Items))
			for i, it := range s.Items {
				switch {
				case it.Star && it.StarAlias != "":
					parts[i] = it.StarAlias + ".*"
				case it.Star:
					parts[i] = "*"
				case it.As != "":
					parts[i] = it.As + " = " + exprString(it.Expr, nil)
				default:
					parts[i] = exprString(it.Expr, nil)
				}
			}
			sb.WriteString(" -> [" + strings.Join(parts, ", ") + "]")
		}
		for _, f := range s.Follows {
			sb.WriteString(" @> ")
			if f.Alias != "" {
				sb.WriteString(f.Alias + " = ")
			}
			sb.WriteString(fieldStr(f.Via))
			if f.Left {
				sb.WriteString("?")
			}
		}
		if len(s.Group) > 0 {
			keys := make([]string, len(s.Group))
			for i, k := range s.Group {
				keys[i] = exprString(k, nil)
			}
			sb.WriteString(", Group = ;[" + strings.Join(keys, ", ") + "]:")
		}
		if len(s.Sort) > 0 {
			keys := make([]string, len(s.Sort))
			for i, k := range s.Sort {
				keys[i] = exprString(k.Expr, nil)
				if k.Desc {
					keys[i] = "-" + keys[i]
				}
			}
			sb.WriteString(", Sort = ;[" + strings.Join(keys, ", ") + "]:")
		}
		if s.Limit != nil {
			sb.WriteString(", Limit = " + exprString(s.Limit, nil))
		}
		if s.Offset != nil {
			sb.WriteString(", Offset = " + exprString(s.Offset, nil))
		}
		return sb.String()
	case *Add:
		return "{Add[]} = " + s.Target.String() + " = " + exprString(s.Rec, nil) + ttlString(s.TTL)
	case *Set:
		if s.Replace != nil {
			return "{Set[]} = " + s.Target.String() + " = " + exprString(s.Replace, nil) + ttlString(s.TTL)
		}
		parts := make([]string, len(s.Assigns))
		for i, a := range s.Assigns {
			parts[i] = fieldStr(a.Target) + " = " + exprString(a.Value, nil)
		}
		return "{Set[]} = " + s.Target.String() + ".[" + strings.Join(parts, ", ") + "]" + ttlString(s.TTL)
	case *Delete:
		out := "{Delete[]} = " + s.Target.String()
		if s.Path != nil {
			out += "." + fieldStr(s.Path)
		}
		return out
	case *Require:
		out := "{Require[]} = " + s.Target.String()
		if s.Count != nil {
			out += ", Count = " + exprString(s.Count, nil)
		}
		return out
	case *Tx:
		parts := make([]string, len(s.Stmts))
		for i, x := range s.Stmts {
			parts[i] = StmtString(x)
		}
		return "{Tx[]} = [ " + strings.Join(parts, ", ") + " ]"
	case *Explain:
		return "{Explain[]} = [ " + StmtString(s.Inner) + " ]"
	case *Watch:
		if s.Pulse {
			return "{Watch[]} = Topic = " + quoteStr(s.Topic)
		}
		return "{Watch[]} = " + s.Target.String()
	}
	return ""
}

func fieldStr(f *Field) string {
	if len(f.Segs) == 0 {
		return f.Raw
	}
	if isIDField(f) {
		return "ID"
	}
	return box.SegsString(f.Segs)
}
