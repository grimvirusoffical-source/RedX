package query

import (
	"errors"
	"strings"
	"testing"
)

func lexAll(t *testing.T, src string) []string {
	t.Helper()
	toks, err := lex(src, 1000)
	if err != nil {
		t.Fatalf("%q: %v", src, err)
	}
	var out []string
	for _, tk := range toks {
		switch tk.kind {
		case tEOF:
		case tString:
			out = append(out, "s:"+tk.text)
		case tParam:
			out = append(out, "$"+tk.text)
		case tNumber:
			out = append(out, "n:"+tk.text)
		default:
			out = append(out, tk.text)
		}
	}
	return out
}

func TestLexer(t *testing.T) {
	cases := []struct {
		src  string
		want string
	}{
		{`{Get[]} = A[ID=1]`, `{ Get [ ] } = A [ ID = n:1 ]`},
		{`A -> [x, y] @> G`, `A -> [ x , y ] @> G`},
		{`a-b_c d`, `a-b_c d`},    // hyphen inside a name
		{`Foo->`, `Foo ->`},       // ...but not before an operator
		{`Qty - 1`, `Qty - n:1`},  // arithmetic needs spaces
		{`Qty-1`, `Qty-1`},        // documented: one name
		{`a = -5`, `a = n:-5`},    // sign
		{`a - -5`, `a - n:-5`},    // binary minus then a negative number
		{`(a) -5`, `( a ) - n:5`}, // after an operand, "-" is an operator
		{`5..10`, `n:5 .. n:10`},  // a range, not a number
		{`1.5..2`, `n:1.5 .. n:2`},
		{`1e3 2E-2`, `n:1e3 n:2E-2`},
		{`"a\"b\\c\n\u0041"`, "s:a\"b\\c\nA"},
		{`$name $_x1`, `$name $_x1`},
		{`x << comment { ' " >> y`, `x y`},
		{`;[1]:`, `; [ n:1 ] :`},
		{`a @!> b`, `a @!> b`},
		{`<= >= != < > =`, `<= >= != < > =`},
		{`(30)* (~5)`, `( n:30 ) * ( ~ n:5 )`},
		{`a|b&c!d`, `a | b & c ! d`},
		{`x?`, `x ?`},
		{"a\n\tb", `a b`},
	}
	for _, c := range cases {
		got := strings.Join(lexAll(t, c.src), " ")
		if got != c.want {
			t.Errorf("%q\n got  %s\n want %s", c.src, got, c.want)
		}
	}
}

func TestLexerErrorsHavePositions(t *testing.T) {
	cases := []struct {
		src       string
		line, col int
		msg       string
	}{
		{"a 'x'", 1, 3, "double quotes"},
		{"a\n  \"open", 2, 3, "unterminated string"},
		{"x << never closed", 1, 3, "unterminated comment"},
		{"a $ b", 1, 3, "needs a name"},
		{"a $1x", 1, 3, "needs a name"},
		{"a @ b", 1, 3, "link operator"},
		{"a % b", 1, 3, "unexpected character"},
		{"a 12ab", 1, 3, "malformed number"},
		{"a 1e999", 1, 3, "out of range"},
		{`"bad \q"`, 1, 6, "unknown escape"},
		{`"\u12"`, 1, 2, "four hex digits"},
		{"a \x00", 1, 3, "control"},
		{"ok\n\n   \xff", 3, 4, "invalid UTF-8"},
		{"a `b`", 1, 3, "unexpected character"},
		{"a #", 1, 3, "unexpected character"},
	}
	for _, c := range cases {
		_, err := lex(c.src, 1000)
		var se *SyntaxError
		if !errors.As(err, &se) || !errors.Is(err, ErrSyntax) {
			t.Errorf("%q: %v", c.src, err)
			continue
		}
		if se.Pos.Line != c.line || se.Pos.Col != c.col || !strings.Contains(se.Msg, c.msg) {
			t.Errorf("%q: got %d:%d %q, want %d:%d %q", c.src, se.Pos.Line, se.Pos.Col, se.Msg, c.line, c.col, c.msg)
		}
	}
	if _, err := lex(strings.Repeat("a ", 2000), 100); err == nil || !strings.Contains(err.Error(), "too many tokens") {
		t.Fatal(err)
	}
}

// Every canonical form must parse, print back to itself and keep meaning the same.
var roundTrip = []string{
	`{Get[]} = players:Player[Role = "Admin", Gold > 1000] -> [Username, Gold] @> Guild, Sort = ;[-Gold]:, Limit = 50`,
	`{Get[]} = players:Player[ID=*]`,
	`{Get[]} = players:Player[Level > 3 | Name = "ann", !(Class = NELL)]`,
	`{Get[]} = players:Player[ID=3] -> [Name, Lvl = (Level + 1) * 2, Stats.Gold]`,
	`{Get[]} = Guild[ID=10]`,
	`{Get[]} = "odd file.db":Box[ID=1]`,
	`{Get[]} = players:*[Name = "x"]`,
	`{Get[]} = players:Player[Level in ;[1, 2, $x]:, Name starts $p, Bio has "a b", Bio hasany "c"]`,
	`{Get[]} = players:Player[Level in 5..10, Gold in $lo..9]`,
	`{Get[]} = players:Player[Tag in $tags]`,
	`{Get[]} = players:Player[Inv[ID=3].Qty > 0]`,
	`{Get[]} = players:Player[Class != NELL]`,
	`{Get[]} = players:Player[ID=*] -> [n = Count(), s = Sum(Gold), a = Avg(Gold), lo = Min(Level), hi = Max(Level)], Group = ;[Class, Guild.Title]:, Sort = ;[-n, Class]:, Limit = 3, Offset = 1`,
	`{Get[]} = players:Player[ID=*] -> [Name, g = Guild.Title] @> Guild? @> o = Guild.Owner`,
	`{Get[]} = players:Player[ID=*] -> [*, g.*]`,
	`{Get[]} = players:Player[ID=*] -> *`,
	`{Get[]} = players:Player[Name = "tab\there \"quoted\" \\ \u0001"]`,
	`{Add[]} = players:Player[ID=9] = [ {Name[]} = "ann", {Stats[]} = [ {Gold[]} = 5 ], {Tags[]} = ;["a", "b"]:, {Item[ID=3]} = [ {Qty[]} = 1 ] (60), {Z[]} = NELL, {T[]} = TRUE ] (30)`,
	`{Add[]} = players:Config = [ {Motd[]} = $m ]`,
	`{Add[]} = players:Player[ID=9] = [ {Guild[]} = "players.red-xai.db":Player[ID=9].Guild @> "guilds.red-xai.db":Guild[ID=10] ]`,
	`{Set[]} = players:Player[ID=7].[Level = Level + 1]`,
	`{Set[]} = players:Player[Level < 3].[Level = 3, Stats.Gold = Stats.Gold * 2] (~60)`,
	`{Set[]} = players:Player[ID=7].[Inventory[ID=10].Qty = 5]`,
	`{Set[]} = players:Player[ID=7] = [ {Name[]} = "x" ] (5)*`,
	`{Delete[]} = players:Player[Level < 1]`,
	`{Delete[]} = players:Player[ID=*]`,
	`{Delete[]} = players:Player[ID=2].Stats.Secret`,
	`{Require[]} = players:Player[ID=1, Gold >= 5]`,
	`{Require[]} = players:Player[Level > 5], Count = 3`,
	`{Tx[]} = [ {Require[]} = players:Player[ID=1], {Set[]} = players:Player[ID=1].[Gold = Gold - 5], {Add[]} = players:Log[ID=1] = [ {N[]} = 5 ] ]`,
	`{Explain[]} = [ {Get[]} = players:Player[Level > 3] ]`,
	`{Explain[]} = [ {Tx[]} = [ {Delete[]} = players:Player[ID=1] ] ]`,
	`{Watch[]} = players:Player[Level > 3]`,
	`{Watch[]} = Topic = "player.*"`,
}

func TestParseRoundTrip(t *testing.T) {
	for _, src := range roundTrip {
		st, _, err := Parse(src)
		if err != nil {
			t.Errorf("%s\n  %v", src, err)
			continue
		}
		out := StmtString(st)
		st2, _, err := Parse(out)
		if err != nil {
			t.Errorf("printed form does not parse:\n  in  %s\n  out %s\n  %v", src, out, err)
			continue
		}
		if again := StmtString(st2); again != out {
			t.Errorf("not a fixed point:\n  1 %s\n  2 %s", out, again)
		}
		// the canonical forms above are exactly what the printer produces
		if out != src {
			t.Errorf("printer changed the canonical text:\n  in  %s\n  out %s", src, out)
		}
	}
}

func TestSurfaceVariantsParseToTheSameCommand(t *testing.T) {
	same := [][]string{
		{`{Get[]} = players:Player[ID=3] -> Name`, `{Get} = players:Player[3] -> [Name]`, `{ Get[ ] }=players : Player [ id = 3 ] -> Name ;`},
		{`{Get[]} = P[Level > 1 & Name = "a"]`, `{Get[]} = P[Level > 1, Name = "a"]`, `{Get[]} = P[(Level > 1) & (Name = "a")]`},
		{`{Get[]} = P[ID=*]`, `{Get[]} = P[*]`, `{Get[]} = P[id=*]`},
		{`{Get[]} = P[ID=*] -> *, Sort = -Level`, `{Get[]} = P[ID=*] -> *, Sort = ;[-Level]:`},
		{`{Set[]} = f:P[1].A = 1`, `{Set[]} = f:P[1].[A = 1]`},
		{`{Get[]} = P[Level > 1] << a comment >> -> Name`, `{Get[]} = P[Level > 1] -> Name`},
		{`{Get[]} = P[ID=$id]`, `{Get[]} = P[$id]`},
		{`{Get[]} = P[ID=1] -> Name, Limit = 1, Sort = Name`, `{Get[]} = P[ID=1] -> Name, Sort = Name, Limit = 1,`},
	}
	for _, g := range same {
		var first string
		for i, src := range g {
			st, _, err := Parse(src)
			if err != nil {
				t.Fatalf("%s: %v", src, err)
			}
			s := StmtString(st)
			if i == 0 {
				first = s
			} else if s != first {
				t.Errorf("%s\n  %s\nvs\n  %s", src, s, first)
			}
		}
	}
}

func TestParamsAreCollectedInOrder(t *testing.T) {
	_, names, err := Parse(`{Get[]} = P[A = $b, B = $a, C = $b] -> x = $c, Limit = $a`)
	if err != nil || strings.Join(names, ",") != "b,a,c" {
		t.Fatal(names, err)
	}
	in, err := Analyze(`{Tx[]} = [ {Get[]} = P[A = $x], {Delete[]} = P[A = $y] ]`)
	if err != nil || !in.Writes || in.Verb != "Tx" || len(in.Params) != 2 {
		t.Fatalf("%+v %v", in, err)
	}
}

func TestAnalyze(t *testing.T) {
	cases := []struct {
		q      string
		verb   string
		writes bool
		watch  bool
	}{
		{`{Get[]} = P[1]`, "Get", false, false},
		{`{Require[]} = P[1]`, "Require", false, false},
		{`{Add[]} = f:P[1] = [ {A[]} = 1 ]`, "Add", true, false},
		{`{Set[]} = f:P[1].A = 1`, "Set", true, false},
		{`{Delete[]} = f:P[1]`, "Delete", true, false},
		{`{Tx[]} = [ {Get[]} = P[1] ]`, "Tx", false, false},
		{`{Tx[]} = [ {Get[]} = P[1], {Delete[]} = f:P[1] ]`, "Tx", true, false},
		{`{Explain[]} = [ {Delete[]} = f:P[1] ]`, "Explain", false, false},
		{`{Watch[]} = P[1]`, "Watch", false, true},
	}
	for _, c := range cases {
		in, err := Analyze(c.q)
		if err != nil || in.Verb != c.verb || in.Writes != c.writes || in.Watch != c.watch {
			t.Errorf("%s: %+v %v", c.q, in, err)
		}
	}
}

func TestSyntaxErrorMessages(t *testing.T) {
	cases := []struct {
		src       string
		line, col int
		msg       string
	}{
		{``, 1, 1, "expected a command such as {Get[]}"},
		{`Get[] = P`, 1, 1, "expected a command such as"},
		{`{Fetch[]} = P`, 1, 2, `unknown command "Fetch"`},
		{`{get[]} = P`, 1, 2, "did you mean Get"},
		{`{Get[ID=1]} = P`, 1, 2, "takes no attributes"},
		{`{Get[]} P`, 1, 9, "expected `=`"},
		{`{Get[]} = `, 1, 11, "expected a source"},
		{`{Get[]} = "f.db"`, 1, 11, "must be followed by `:Box`"},
		{`{Get[]} = f:`, 1, 13, "expected a box name"},
		{`{Get[]} = P[Level >`, 1, 20, "expected a value"},
		{`{Get[]} = P[Level > 1`, 1, 22, "expected `]`"},
		{`{Get[]} = P[Level 1]`, 1, 19, "expected `]`"},
		{`{Get[]} = P[Level > 1 > 2]`, 1, 23, "expected `]`"},
		{`{Get[]} = P[(Level > 1]`, 1, 13, "unclosed `(`"},
		{"{Get[]} = P[\n  Name =\n]", 3, 1, "expected a value"},
		{`{Get[]} = P[ID=1] -> `, 1, 22, "expected a value, field"},
		{`{Get[]} = P[ID=1] -> []`, 1, 22, "empty projection"},
		{`{Get[]} = P[ID=1] -> [a b]`, 1, 25, "expected `]`"},
		{`{Get[]} = P[ID=1], Sort`, 1, 20, "expected an option"},
		{`{Get[]} = P[ID=1], Sort =`, 1, 26, "expected a value"},
		{`{Get[]} = P[ID=1], Limit = x`, 1, 28, "expected Limit as a whole number"},
		{`{Get[]} = P[ID=1], Limit = 1, Limit = 2`, 1, 31, "given twice"},
		{`{Get[]} = P[ID=1], Offset = 1.5`, 1, 29, "non-negative whole number"},
		{`{Get[]} = P[ID=1], Colour = 1`, 1, 20, `unknown option "Colour"`},
		{`{Get[]} = P[ID=1] @!> G`, 1, 19, "@!> is the cascade-delete link"},
		{`{Get[]} = P[A in 5]`, 1, 19, "expected `..`"},
		{`{Get[]} = P[A in ;[1, 2]]`, 1, 18, "closing `:`"},
		{`{Get[]} = P[A in ;[1, 2]:`, 1, 26, "expected `]`"},
		{`{Get[]} = P[Level + > 1]`, 1, 21, "expected a value"},
		{`{Get[]} = P[NELL < A]`, 1, 18, "NELL can only be compared"},
		{`{Get[]} = P[1 has "x"]`, 1, 15, "has applies to a field"},
		{`{Get[]} = P[Count() > 1]`, 1, 13, "must be a whole projection item"},
		{`{Get[]} = P[ID=1] -> [Sum(Count())]`, 1, 27, "cannot be nested"},
		{`{Get[]} = P[ID=1] -> [Sum()]`, 1, 23, "needs an argument"},
		{`{Get[]} = P[ID=1] -> [Count(x)]`, 1, 29, "takes no argument"},
		{`{Get[]} = P[ID=1] {Get[]} = P[ID=2]`, 1, 19, "one command per request"},
		{`{Get[]} = P[ID=1] garbage`, 1, 19, "after the end of the command"},
		{`{Tx[]} = [ ]`, 1, 10, "at least one command"},
		{`{Tx[]} = [ {Get[]} = P[1]`, 1, 10, "unclosed"},
		{`{Tx[]} = [ {Tx[]} = [ {Get[]} = P[1] ] ]`, 1, 13, "do not nest"},
		{`{Explain[]} = [ {Explain[]} = [ {Get[]} = P[1] ] ]`, 1, 17, "cannot wrap Explain"},
		{`{Explain[]} = {Get[]} = P[1]`, 1, 15, "expected `[`"},
		{`{Watch[]} = Topic = 5`, 1, 21, "topic pattern in quotes"},
		{`{Add[]} = f:P[ID=1] = {A[]} = 1`, 1, 23, "expected `[`"},
		{`{Add[]} = f:P[ID=1] = [ {A[]} 1 ]`, 1, 31, "expected `=`"},
		{`{Add[]} = f:P[ID=1] = [ {A[x]} = 1 ]`, 1, 28, "whole number ID"},
		{`{Add[]} = f:P[ID=1] = [ {A[]} = B ]`, 1, 33, "holds values only"},
		{`{Add[]} = f:P[ID=1] = [ {A[]} = 1 ] (0)`, 1, 38, "whole number of seconds"},
		{`{Add[]} = f:P[ID=1] = [ {A[]} = 1 ] (5`, 1, 37, "unclosed `(`"},
		{`{Add[]} = f:P[ID=1] = [ {A[]} = "f":X[ID=1] @> ]`, 1, 48, "expected a link reference"},
		{`{Set[]} = f:P[1]`, 1, 17, "after the Set target"},
		{`{Set[]} = f:P[1].`, 1, 18, "expected a field name"},
		{`{Set[]} = f:P[1].A`, 1, 19, "expected `=`"},
		{`{Set[]} = f:P[1].[A = 1`, 1, 24, "expected `]`"},
		{`{Delete[]} = f:P[1].`, 1, 21, "expected a field name"},
		{`{Require[]} = f:P[1], Count = $`, 1, 31, "needs a name"},
		{`{Get[]} = P[ID=1] -> [x = ]`, 1, 27, "expected a value"},
		{`{Get[]} = P[$]`, 1, 13, "needs a name"},
	}
	for _, c := range cases {
		_, _, err := Parse(c.src)
		var se *SyntaxError
		if !errors.As(err, &se) {
			t.Errorf("%q: expected a SyntaxError, got %v", c.src, err)
			continue
		}
		if se.Pos.Line != c.line || se.Pos.Col != c.col || !strings.Contains(se.Msg, c.msg) {
			t.Errorf("%q:\n  got  %d:%d %s\n  want %d:%d %s", c.src, se.Pos.Line, se.Pos.Col, se.Msg, c.line, c.col, c.msg)
		}
	}
}

func TestErrorContextShowsACaret(t *testing.T) {
	src := "{Get[]} = P[\n  Name = \"a\",\n  Level >\n]"
	_, _, err := Parse(src)
	var se *SyntaxError
	if !errors.As(err, &se) {
		t.Fatal(err)
	}
	if se.Pos.Line != 4 || se.Pos.Col != 1 {
		t.Fatalf("%d:%d", se.Pos.Line, se.Pos.Col)
	}
	if got := se.Context(src); got != "]\n^" {
		t.Fatalf("%q", got)
	}
	if !strings.Contains(se.Error(), "syntax error at 4:1") {
		t.Fatal(se.Error())
	}
}

func TestNestingAndSizeLimits(t *testing.T) {
	deep := `{Get[]} = P[` + strings.Repeat("(", 200) + `A = 1` + strings.Repeat(")", 200) + `]`
	if _, _, err := Parse(deep); err == nil || !strings.Contains(err.Error(), "nested too deeply") {
		t.Fatal(err)
	}
	notChain := `{Get[]} = P[` + strings.Repeat("!", 500) + `A]`
	if _, _, err := Parse(notChain); err == nil || !strings.Contains(err.Error(), "nested too deeply") {
		t.Fatal(err)
	}
	rec := `{Add[]} = f:P[ID=1] = ` + strings.Repeat("[ {A[]} = ", 100) + "1" + strings.Repeat(" ]", 100)
	if _, _, err := Parse(rec); err == nil || !strings.Contains(err.Error(), "nested too deeply") {
		t.Fatal(err)
	}
	if _, _, err := parseWith(`{Get[]} = P[A = "`+strings.Repeat("x", 100)+`"]`, Limits{MaxQueryBytes: 50}); !errors.Is(err, ErrTooLarge) {
		t.Fatal(err)
	}
	list := `{Get[]} = P[A in ;[` + strings.Repeat("1,", 50) + `1]:]`
	if _, _, err := parseWith(list, Limits{MaxInList: 10}); err == nil || !strings.Contains(err.Error(), "too many items") {
		t.Fatal(err)
	}
	if _, _, err := parseWith(`{Get[]} = P[ID=1] @> A @> B @> C`, Limits{MaxJoins: 2}); err == nil || !strings.Contains(err.Error(), "too many @> follows") {
		t.Fatal(err)
	}
	path := `{Get[]} = P[` + strings.Repeat("a.", 40) + `a = 1]`
	if _, _, err := parseWith(path, Limits{MaxPathDepth: 8}); err == nil || !strings.Contains(err.Error(), "too deep") {
		t.Fatal(err)
	}
}

// Syntax borrowed from other languages is an error, never a silent reinterpretation.
func TestForeignSyntaxIsRejected(t *testing.T) {
	f := newFixture(t, fixOpt{})
	for _, q := range []string{
		`fetch everything`,
		`players.Player[Level > 1]`,
		`{Get[]} = players:Player[Name == "x"]`,
		`{Get[]} = players:Player[Name = 'x']`,
		`{Get[]} = players:Player[Name <> "x"]`,
		`{Get[]} = players:Player[Level > 1 AND Level < 5]`,
		`{Get[]} = players:Player[Name LIKE "a%"]`,
		`{Get[]} = players:Player[Level > ?]`,
		`{Get[]} = players:Player -> Name; {Delete[]} = players:Player[ID=*]`,
		`{Get[]} = players:Player -> Name /* x */`,
		`{Get[]} = players:Player -> Name ORDER 1`,
	} {
		if err := f.qerr(t, q); !errors.Is(err, ErrSyntax) {
			t.Errorf("%s: %v", q, err)
		}
	}
	// 5 records still there
	eq(t, col(f.q(t, `{Get[]} = players:Player[ID=*] -> ID`), "ID"), "1", "2", "3", "4", "5")
}
