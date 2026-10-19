package query

import (
	"context"
	"errors"
	"testing"

	"redx/box"
	"redx/engine/sec"
)

func TestWatchSpec(t *testing.T) {
	f := newFixture(t, fixOpt{})
	w, err := f.db.Watch(context.Background(), anyone, `{Watch[]} = players:Player[Level > $min, Class = "Mage"]`, P{"min": 3})
	if err != nil {
		t.Fatal(err)
	}
	if w.Pulse || w.File != playersFile || w.Box != "Player" {
		t.Fatalf("%+v", w)
	}
	ent := func(id int64, text string) (*box.Entry, bool) {
		v, err := box.ParseValue(text)
		if err != nil {
			t.Fatal(err)
		}
		e := box.NewEntry("Player", &id, v)
		_, ok := w.Admit(addrOf(playersFile, "Player", id), e)
		return e, ok
	}
	if _, ok := ent(1, `[ {Level[]} = 5, {Class[]} = "Mage" ]`); !ok {
		t.Fatal("matching change was not admitted")
	}
	if _, ok := ent(2, `[ {Level[]} = 1, {Class[]} = "Mage" ]`); ok {
		t.Fatal("non-matching change admitted")
	}
	if _, ok := ent(3, `[ {Level[]} = 9, {Class[]} = "healer" ]`); ok {
		t.Fatal("non-matching change admitted")
	}
	// other boxes and files never match
	e := box.NewEntry("Npc", idp(1), box.BoxValue(box.NewBox()))
	if _, ok := w.Admit(addrOf(playersFile, "Npc", 1), e); ok {
		t.Fatal("other box")
	}
	if _, ok := w.Admit(addrOf(guildsFile, "Player", 1), e); ok {
		t.Fatal("other file")
	}
	// a pulse topic watch
	p, err := f.db.Watch(context.Background(), anyone, `{Watch[]} = Topic = "player.*"`, nil)
	if err != nil || !p.Pulse || p.Topic != "player.*" {
		t.Fatal(p, err)
	}
	// other commands are not watches; missing params fail
	if _, err := f.db.Watch(context.Background(), anyone, `{Get[]} = players:Player`, nil); !errors.Is(err, ErrBadStatement) {
		t.Fatal(err)
	}
	if _, err := f.db.Watch(context.Background(), anyone, `{Watch[]} = players:Player[Level > $min]`, nil); !errors.Is(err, ErrParams) {
		t.Fatal(err)
	}
}

func TestWatchIsAuthorizedAndMasked(t *testing.T) {
	f := newFixture(t, fixOpt{auth: policy(t)})
	if _, err := f.db.Watch(context.Background(), as("nobody"), `{Watch[]} = players:Player`, nil); !errors.Is(err, sec.ErrDenied) {
		t.Fatal(err)
	}
	// reader may not filter on a field it cannot read
	if _, err := f.db.Watch(context.Background(), as("reader"), `{Watch[]} = players:Player[Bio = "x"]`, nil); !errors.Is(err, sec.ErrDenied) {
		t.Fatal(err)
	}
	w, err := f.db.Watch(context.Background(), as("reader"), `{Watch[]} = players:Player[Level > 1]`, nil)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := box.ParseValue(`[ {Name[]} = "ann", {Level[]} = 5, {Bio[]} = "private", {Stats[]} = [ {Gold[]} = 1, {Secret[]} = "s" ] ]`)
	got, ok := w.Admit(addrOf(playersFile, "Player", 1), box.NewEntry("Player", idp(1), v))
	if !ok {
		t.Fatal("not admitted")
	}
	if got.Box.Get("Bio", 0, false) != nil {
		t.Fatal("Bio leaked in a watch event")
	}
	st := got.Box.Get("Stats", 0, false)
	if st == nil || st.Value.Box.Get("Secret", 0, false) != nil || st.Value.Box.Get("Gold", 0, false) == nil {
		t.Fatalf("masking: %v", got)
	}
}
