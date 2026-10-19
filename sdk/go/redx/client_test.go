package redx_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/grimvirusoffical-source/RedX/sdk/go/redx"
)

// must panics on an error (the test then fails with the error and a stack).
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func TestOperationTableMatchesSpec(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "api", "redx-api.json"))
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Operations []struct{ ID, Path, Danger string }
	}
	if err := json.Unmarshal(b, &spec); err != nil {
		t.Fatal(err)
	}
	if len(spec.Operations) != len(redx.Operations) {
		t.Fatalf("spec has %d operations, table %d", len(spec.Operations), len(redx.Operations))
	}
	for _, o := range spec.Operations {
		op := redx.Operations[o.ID]
		if op.Path != o.Path || op.Danger.String() != o.Danger {
			t.Fatalf("%s: %+v vs %+v", o.ID, op, o)
		}
	}
	for _, id := range []string{"deleteDatabase", "createKey", "revokeKey", "rotateKey", "promote", "repoint", "connectApprove", "createJoinToken"} {
		if redx.DangerOf(id) != redx.DangerDangerous {
			t.Fatal(id, "should be dangerous")
		}
	}
	if redx.DangerOf("no-such-op") != redx.DangerDangerous || redx.DangerOf("getPath") != redx.DangerSafe {
		t.Fatal("DangerOf")
	}
}

func TestFromBox(t *testing.T) {
	cases := map[string]any{
		`"a\"b\u00e9"`:     `a"bé`,
		`-1.5e2`:           -150.0,
		`NELL`:             nil,
		`;["a", 2, TRUE]:`: []any{"a", 2.0, true},
		`[ {A[]} = 1, {B[ID=7]} = [ {C[]} = ;[]: ] ]`: map[string]any{"A": 1.0, "B[ID=7]": map[string]any{"C": []any{}}},
		`[ {S[]} = "x" (60) ]`:                        map[string]any{"S": "x"},
	}
	for in, want := range cases {
		got, err := redx.FromBox(in)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: %#v %v", in, got, err)
		}
	}
	if _, err := redx.FromBox(`[ {A[]} = `); err == nil {
		t.Fatal("truncated box decoded")
	}
}

func TestDangerousNeedsConfirmAndSendsNothing(t *testing.T) {
	c := must(redx.New("http://127.0.0.1:9", "rx_"+"live_"+strings.Repeat("x", 43)))
	for _, id := range []string{"deleteDatabase", "promote", "connectApprove", "createPairingCode", "revokeKey"} {
		_, err := c.Call(context.Background(), id, redx.Args{DB: "x", Params: map[string]string{"id": "k"}})
		var e *redx.Error
		if !errors.As(err, &e) || e.Code != "confirm_required" || e.Status != 0 {
			t.Fatalf("%s: %v", id, err)
		}
	}
	if s := fmt.Sprintf("%v %+v %#v", c, c, c); strings.Contains(s, "xxxx") {
		t.Fatal("key in formatted client")
	}
}

func TestAgainstRealHost(t *testing.T) {
	ctx := context.Background()
	h := startHost(t)
	admin := must(redx.New(h.URL, h.AdminKey))

	if m := must(admin.Health(ctx, redx.Args{})).Map(); m["status"] != "ok" {
		t.Fatal(m)
	}
	must(admin.CreateDatabase(ctx, redx.Args{Body: map[string]any{"name": "sdkgo"}}))
	if !strings.Contains(string(must(admin.ListDatabases(ctx, redx.Args{})).Body), "sdkgo") {
		t.Fatal("db not listed")
	}
	c := must(admin.WithDB("sdkgo"))

	t.Run("data", func(t *testing.T) {
		if err := c.Set(ctx, "p.red-xai.db:P[ID=1]", map[string]any{"Name": "Ann", "Level": 5}, nil); err != nil {
			t.Fatal(err)
		}
		v := must(c.Get(ctx, "p.red-xai.db:P[ID=1]"))
		if !reflect.DeepEqual(v, map[string]any{"Name": "Ann", "Level": 5.0}) {
			t.Fatalf("%#v", v)
		}
		if bt := must(c.GetBox(ctx, "p.red-xai.db:P[ID=1].Name")); bt != `"Ann"` {
			t.Fatal(bt)
		}
		if err := c.Set(ctx, "s.red-xai-db-qs:S[ID=1]", "short", &redx.WriteOptions{TTL: 1}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2500 * time.Millisecond)
		if _, err := c.Get(ctx, "s.red-xai-db-qs:S[ID=1]"); !redx.IsNotFound(err) {
			t.Fatal("ttl did not expire:", err)
		}
		r := must(c.Bx(ctx, "{Get[]} = p:P[Level >= $min] -> Name", map[string]any{"min": 3}))
		if r.Count != 1 {
			t.Fatalf("%+v", r)
		}
		tx := must(c.Tx(ctx, []string{"{Set[]} = p:P[ID=1].Level = $l", `{Add[]} = p:P[ID=3] = [ {Name[]} = "Cy" ]`}, map[string]any{"l": 9}))
		if len(tx.Results) != 2 {
			t.Fatalf("%+v", tx)
		}
		if _, err := c.Tx(ctx, []string{"{Require[]} = p:P[ID=1, Level > 100]", "{Delete[]} = p:P[ID=3]"}, nil); !redx.IsStatus(err, 409) {
			t.Fatal("failed Require should be 409:", err)
		}
		if err := c.Delete(ctx, "p.red-xai.db:P[ID=3]"); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.DeleteDatabase(ctx, redx.Args{DB: "sdkgo"}); err == nil {
			t.Fatal("unconfirmed delete went through")
		}
	})

	t.Run("keys", func(t *testing.T) {
		var k struct{ Key, ID string }
		mustOK(t, must(admin.CreateKey(ctx, redx.Args{Body: map[string]any{"db": "sdkgo", "scope": "read", "label": "go-ro"}, Confirm: true})).Decode(&k))
		ro := must(redx.New(h.URL, k.Key, redx.WithDB("sdkgo")))
		if s := fmt.Sprint(ro); strings.Contains(s, k.Key) {
			t.Fatal("key printed")
		}
		if v := must(ro.Get(ctx, "p.red-xai.db:P[ID=1].Name")); v != "Ann" {
			t.Fatal(v)
		}
		if err := ro.Set(ctx, "p.red-xai.db:P[ID=9]", 1, nil); !redx.IsStatus(err, 403) {
			t.Fatal(err)
		}
		must(admin.RevokeKey(ctx, k.ID, redx.Args{Confirm: true}))
		if _, err := ro.Get(ctx, "p.red-xai.db:P[ID=1]"); !redx.IsStatus(err, 401) {
			t.Fatal(err)
		}
		var pc struct{ Code string }
		mustOK(t, must(admin.CreatePairingCode(ctx, redx.Args{Body: map[string]any{"db": "sdkgo", "scope": "read"}, Confirm: true})).Decode(&pc))
		anon := must(redx.New(h.URL, ""))
		var paired struct{ Key string }
		mustOK(t, must(anon.PairExchange(ctx, redx.Args{Body: map[string]any{"code": pc.Code}})).Decode(&paired))
		if !strings.HasPrefix(paired.Key, "rx_live_") {
			t.Fatal("pairing gave no key")
		}
	})

	t.Run("files", func(t *testing.T) {
		data := make([]byte, 300000)
		rand.Read(data)
		if err := c.UploadFile(ctx, "assets", "lvl/one.bin", data); err != nil {
			t.Fatal(err)
		}
		if got := must(c.DownloadFile(ctx, "assets", "lvl/one.bin", 0, -1)); !bytes.Equal(got, data) {
			t.Fatal("download differs")
		}
		if got := must(c.DownloadFile(ctx, "assets", "lvl/one.bin", 10, 19)); !bytes.Equal(got, data[10:20]) {
			t.Fatal("range differs")
		}
		_, err := c.PackPut(ctx, "assets", "bad.bin", redx.Args{Raw: []byte("x"), Header: map[string][]string{"X-Redx-Sha256": {strings.Repeat("0", 64)}}})
		if !redx.IsStatus(err, 422) {
			t.Fatal("checksum mismatch should be 422:", err)
		}
		png := append([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}, data[:64]...)
		if err := c.UploadMedia(ctx, "art", "icon.png", png, "image/png"); err != nil {
			t.Fatal(err)
		}
		if got := must(c.DownloadMedia(ctx, "art", "icon.png", 0, -1)); !bytes.Equal(got, png) {
			t.Fatal("media differs")
		}
	})

	t.Run("streams with reconnect", func(t *testing.T) {
		reconnected := make(chan struct{}, 4)
		s := must(c.Subscribe(ctx, "w.red-xai.db:*", &redx.StreamOptions{Reconnect: true, MinBackoff: 50 * time.Millisecond, MaxBackoff: 200 * time.Millisecond,
			OnReconnect: func() { reconnected <- struct{}{} }}))
		defer s.Close()
		mustOK(t, c.Set(ctx, "w.red-xai.db:W[ID=1]", map[string]any{"A": 1}, nil))
		next := func() redx.Event {
			select {
			case ev := <-s.C:
				return ev
			case <-time.After(8 * time.Second):
				t.Fatal("no event")
			}
			return redx.Event{}
		}
		if ev := next(); !reflect.DeepEqual(ev.Data, map[string]any{"A": 1.0}) {
			t.Fatalf("%+v", ev)
		}
		h.restart(300 * time.Millisecond)
		select {
		case <-reconnected:
		case <-time.After(10 * time.Second):
			t.Fatal("did not reconnect")
		}
		mustOK(t, c.Set(ctx, "w.red-xai.db:W[ID=2]", map[string]any{"A": 2}, nil))
		if ev := next(); ev.Path != "w.red-xai.db:W[ID=2]" {
			t.Fatalf("%+v", ev)
		}
		w := must(c.Watch(ctx, "{Watch[]} = w:W[A > $min]", map[string]any{"min": 4}, nil))
		defer w.Close()
		mustOK(t, c.Set(ctx, "w.red-xai.db:W[ID=3]", map[string]any{"A": 5}, nil))
		select {
		case <-w.C:
		case <-time.After(8 * time.Second):
			t.Fatal("watch saw nothing")
		}
	})

	t.Run("cluster", func(t *testing.T) {
		if must(admin.ClusterStatus(ctx, redx.Args{})).Map()["role"] == nil {
			t.Fatal("no role")
		}
		if _, err := admin.Promote(ctx, redx.Args{Confirm: true}); err == nil {
			t.Fatal("promoting a leader should fail")
		}
	})

	t.Run("connect", func(t *testing.T) {
		rq := must(redx.NewConnectRequest())
		sum := sha256.Sum256([]byte(rq.Verifier))
		if rq.Challenge != base64.RawURLEncoding.EncodeToString(sum[:]) {
			t.Fatal("challenge")
		}
		link := must(redx.ConnectLink("gendragoon", rq, redx.LinkOptions{Callback: "gendragoon://redx-callback"}))
		if !strings.HasPrefix(link, "redx://connect?") {
			t.Fatal(link)
		}
		start := must(admin.ConnectStart(ctx, redx.Args{Body: map[string]any{"v": 1, "provider": "gendragoon", "state": rq.State,
			"pkce_challenge": rq.Challenge, "callback": "gendragoon://redx-callback"}})).Map()
		ap := must(admin.ConnectApprove(ctx, redx.Args{Body: map[string]any{"request_id": start["request_id"]}, Confirm: true})).Map()
		cbURL := strings.Replace(ap["callback_template"].(string), "{state}", rq.State, 1)
		if _, err := redx.ParseCallback(cbURL, strings.Repeat("x", len(rq.State))); err == nil {
			t.Fatal("state mismatch accepted")
		}
		cb := must(redx.ParseCallback(cbURL, rq.State))
		anon := must(redx.New(h.URL, ""))
		bad := rq
		bad.Verifier = strings.Repeat("A", 43)
		var e *redx.Error
		if _, err := anon.ExchangeConnectCode(ctx, cb.Code, bad, ""); !errors.As(err, &e) || e.Code != "pkce_mismatch" {
			t.Fatal(err)
		}
		ex := must(anon.ExchangeConnectCode(ctx, cb.Code, rq, "go test"))
		ws := ex["workspace"].(map[string]any)["db"].(string)
		app := must(redx.New(h.URL, ex["key"].(string), redx.WithDB(ws)))
		mustOK(t, app.Set(ctx, "save.red-xai.db:S[ID=1]", map[string]any{"L": 2}, nil))
		must(app.ConnectRevoke(ctx, redx.Args{}))
		if _, err := app.Get(ctx, "save.red-xai.db:S[ID=1]"); !redx.IsStatus(err, 401) {
			t.Fatal(err)
		}
	})

	t.Run("backup and delete", func(t *testing.T) {
		if b := must(admin.Backup(ctx, redx.Args{})).Body; len(b) < 100 {
			t.Fatal("backup too small")
		}
		must(admin.DeleteDatabase(ctx, redx.Args{DB: "sdkgo", Confirm: true}))
		if strings.Contains(string(must(admin.ListDatabases(ctx, redx.Args{})).Body), "sdkgo") {
			t.Fatal("db still listed")
		}
	})
}

func mustOK(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
