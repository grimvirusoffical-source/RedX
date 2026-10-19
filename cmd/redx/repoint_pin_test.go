package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// `redx node repoint` must be able to pass the new leader's fingerprint (self-signed TLS).
func TestRepointSendsLeaderPin(t *testing.T) {
	var mu sync.Mutex
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/cluster/leader" {
			mu.Lock()
			json.NewDecoder(r.Body).Decode(&got)
			mu.Unlock()
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	pin := "ab" + string(make([]byte, 0))
	for i := 0; i < 31; i++ {
		pin += "cd"
	}
	for _, flagName := range []string{"--leader-pin", "--fingerprint"} {
		mu.Lock()
		got = nil
		mu.Unlock()
		if _, se, code := runCLI(t, srv.URL, "k", "node", "repoint", "https://10.0.0.2:7777", "--token", "rxj_T", flagName, pin); code != 0 {
			t.Fatalf("%s: exit %d %s", flagName, code, se)
		}
		mu.Lock()
		if got["pin_sha256"] != pin || got["url"] != "https://10.0.0.2:7777" || got["join_token"] != "rxj_T" {
			t.Fatalf("%s: body %v", flagName, got)
		}
		mu.Unlock()
	}
	// a join link carries leader, code and pin
	mu.Lock()
	got = nil
	mu.Unlock()
	if _, se, code := runCLI(t, srv.URL, "k", "node", "repoint", "https://10.0.0.3:7777/#/join?c=RX-ABCDE-FGHJK&pin="+pin); code != 0 {
		t.Fatalf("join link: %d %s", code, se)
	}
	mu.Lock()
	defer mu.Unlock()
	if got["pin_sha256"] != pin || got["url"] != "https://10.0.0.3:7777" || got["join_token"] != "RX-ABCDE-FGHJK" {
		t.Fatalf("join link body %v", got)
	}
}
