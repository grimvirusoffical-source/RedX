package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

func TestSubscribePin(t *testing.T) {
	up := websocket.Upgrader{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/subscribe" || r.Header.Get("Authorization") != "Bearer k1" {
			http.Error(w, "no", 401)
			return
		}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		c.WriteMessage(websocket.TextMessage, []byte(`{"ok":true}`))
		c.Close()
	}))
	defer srv.Close()
	sum := sha256.Sum256(srv.Certificate().Raw)
	fp := hex.EncodeToString(sum[:])

	dial := func(g globals) error {
		g.addr, g.key = srv.URL, "k1"
		c, _, err := dialSubscribe(g, "a.red-xai.db:B")
		if err == nil {
			_, msg, rerr := c.ReadMessage()
			c.Close()
			if rerr != nil || !strings.Contains(string(msg), "ok") {
				t.Fatalf("read: %v %s", rerr, msg)
			}
		}
		return err
	}
	if err := dial(globals{}); err == nil {
		t.Fatal("a self-signed server without --pin must be refused")
	}
	if err := dial(globals{pin: fp}); err != nil {
		t.Fatalf("matching --pin: %v", err)
	}
	colon := strings.ToUpper(fp[:2]) + ":" + fp[2:]
	if err := dial(globals{pin: "sha256:" + colon}); err != nil {
		t.Fatalf("pin with sha256: prefix and colons: %v", err)
	}
	wrong := strings.Repeat("0", 64)
	if err := dial(globals{pin: wrong}); err == nil || !strings.Contains(err.Error(), "--pin") {
		t.Fatalf("wrong --pin must be refused, got %v", err)
	}
	// --pin wins over --insecure: a wrong pin is never silently ignored
	if err := dial(globals{pin: wrong, insecure: true}); err == nil {
		t.Fatal("wrong --pin with --insecure must still be refused")
	}
}
