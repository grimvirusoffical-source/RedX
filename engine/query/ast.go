package query

import (
	"redx/box"
)

// Stmt is a parsed BoxQL command: *Get, *Add, *Set, *Delete, *Require, *Tx, *Explain or *Watch.
type Stmt interface{ stmtPos() Pos }

// Expr is a parsed expression.
type Expr interface{ exprPos() Pos }

// Source names the records a command reads or writes: [file:]Box[filters].
type Source struct {
	P     Pos
	File  string // as written; resolved against the store at run time ("" = find the file holding Box)
	Box   string // "" = every box of the file (file:*)
	Where Expr   // the [...] filters, AND-ed; nil if there are none
	All   bool   // [ID=*] or [*]: every record, written out on purpose
	Alias string // set when the source is a joined record (internal)
}

// scoped reports whether the source says which records it means (a filter or an explicit all).
func (s Source) scoped() bool { return s.Where != nil || s.All }

// Proj is one entry of a projection (the -> [...] list).
type Proj struct {
	Star      bool   // * or Alias.*
	StarAlias string // for Alias.*
	Expr      Expr
	As        string // Name = expr
	Text      string // source text (column name when As is empty)
	P         Pos
}

// Follow is @> [Alias =] field[?]: it follows the @> link(s) stored in a field.
type Follow struct {
	P     Pos
	Left  bool // field? keeps the row when there is no target
	Via   *Field
	Alias string
}

// SortKey is one Sort key.
type SortKey struct {
	Expr Expr
	Desc bool
}

// TTLSpec is a (N), (~N) or (N)* marker given to a write.
type TTLSpec struct {
	Kind    uint8
	Seconds int
}

// Get reads records.
type Get struct {
	P       Pos
	Items   []Proj
	From    Source
	Follows []Follow
	Where   Expr // From.Where
	Sort    []SortKey
	Group   []Expr
	Limit   Expr // *Lit or *Param, nil if absent
	Offset  Expr
}

// Add creates one record; it fails if the record exists.
type Add struct {
	P      Pos
	Target Source
	Rec    Expr // *RecLit
	TTL    TTLSpec
}

// Assign is one `field = expr` of a Set.
type Assign struct {
	Target *Field
	Value  Expr
}

// Set changes fields of the records a filter selects, or replaces one record (Replace).
type Set struct {
	P       Pos
	Target  Source
	Where   Expr
	Assigns []Assign
	Replace Expr // *RecLit: Box[ID=n] = [ ... ]
	TTL     TTLSpec
}

// Delete removes records, or one field (Path) of them.
type Delete struct {
	P      Pos
	Target Source
	Where  Expr
	Path   *Field
}

// Require fails (and aborts a Tx) unless the filter matches at least one record (or exactly Count).
type Require struct {
	P      Pos
	Target Source
	Where  Expr
	Count  Expr
}

// Tx runs its commands in order, all or nothing.
type Tx struct {
	P     Pos
	Stmts []Stmt
}

// Explain plans the command inside and runs nothing.
type Explain struct {
	P     Pos
	Inner Stmt
}

// Watch describes a subscription (data changes matching a filter, or pulse topics).
type Watch struct {
	P      Pos
	Target Source
	Where  Expr
	Topic  string // Topic = "player.*": a pulse topic pattern instead of a source
	Pulse  bool
}

func (s *Get) stmtPos() Pos     { return s.P }
func (s *Add) stmtPos() Pos     { return s.P }
func (s *Set) stmtPos() Pos     { return s.P }
func (s *Delete) stmtPos() Pos  { return s.P }
func (s *Require) stmtPos() Pos { return s.P }
func (s *Tx) stmtPos() Pos      { return s.P }
func (s *Explain) stmtPos() Pos { return s.P }
func (s *Watch) stmtPos() Pos   { return s.P }

// Expression nodes.
type (
	// Lit is a literal value.
	Lit struct {
		P Pos
		V box.Value
	}
	// Param is a $name placeholder; N indexes the query's distinct parameter names.
	Param struct {
		P    Pos
		Name string
		N    int
	}
	// Field is a field path such as Name, Stats.Level, Guild.Title or Inv[ID=3].Count.
	// Alias/Path/Pseudo are filled in by binding.
	Field struct {
		P    Pos
		Segs []box.Seg // as written
		Raw  string

		Alias  int       // index of the source alias the field reads from (0 = the primary source)
		Path   []box.Seg // path inside that record
		Pseudo string    // "_id", "_box" or "_file" for the pseudo fields
		// Names are the dotted field names of Path without ID selectors
		// ("Stats", "Stats.Level"), cumulative, used for authorization.
		Names []string
	}
	// Unary is -x.
	Unary struct {
		P  Pos
		Op string
		X  Expr
	}
	// Not is !x.
	Not struct {
		P Pos
		X Expr
	}
	// Binary is x op y: and, or, =, !=, <, <=, >, >=, +, -, *, /.
	Binary struct {
		P    Pos
		Op   string
		L, R Expr
	}
	// In is x in ;[a, b, ...]: (or x in $list).
	In struct {
		P    Pos
		X    Expr
		List []Expr
	}
	// Starts is x starts "prefix".
	Starts struct {
		P   Pos
		X   Expr
		Pat Expr
	}
	// InRange is x in lo..hi (inclusive).
	InRange struct {
		P      Pos
		X      Expr
		Lo, Hi Expr
	}
	// IsNell is x = NELL / x != NELL.
	IsNell struct {
		P   Pos
		X   Expr
		Neg bool
	}
	// Match is field has "words" (all words) or field hasany "words".
	Match struct {
		P     Pos
		Field *Field
		Terms Expr
		Any   bool
	}
	// ArrLit is ;[a, b]:.
	ArrLit struct {
		P     Pos
		Items []Expr
	}
	// RecLit is a Box literal: [ {Name[]} = "Ann", {Stats[]} = [ ... ] ].
	RecLit struct {
		P       Pos
		Entries []RecEntry
	}
	// Agg is Count(), Sum(x), Avg(x), Min(x) or Max(x); only valid as a whole projection item.
	Agg struct {
		P   Pos
		Fn  string // count, sum, avg, min, max
		Arg Expr   // nil for Count()
	}
)

// RecEntry is one {Key[ID=n]} = value entry of a RecLit.
type RecEntry struct {
	P     Pos
	Key   string
	ID    *int64
	Value Expr
	TTL   TTLSpec
}

func (e *Lit) exprPos() Pos     { return e.P }
func (e *Param) exprPos() Pos   { return e.P }
func (e *Field) exprPos() Pos   { return e.P }
func (e *Unary) exprPos() Pos   { return e.P }
func (e *Not) exprPos() Pos     { return e.P }
func (e *Binary) exprPos() Pos  { return e.P }
func (e *In) exprPos() Pos      { return e.P }
func (e *Starts) exprPos() Pos  { return e.P }
func (e *InRange) exprPos() Pos { return e.P }
func (e *IsNell) exprPos() Pos  { return e.P }
func (e *Match) exprPos() Pos   { return e.P }
func (e *ArrLit) exprPos() Pos  { return e.P }
func (e *RecLit) exprPos() Pos  { return e.P }
func (e *Agg) exprPos() Pos     { return e.P }
