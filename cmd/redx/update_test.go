package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"redx/host"
	"redx/host/engineadapter"
)

func TestUpdateCLI(t *testing.T) {
	cfg := host.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.ArgonMemKiB, cfg.ArgonTime = 64, 1
	cfg.LogLevel = "quiet"
	h, err := host.New(cfg, engineadapter.Opener(engineadapter.Config{SweepMS: 50}), t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h.Handler())
	t.Cleanup(func() { srv.Close(); h.Close() })
	key := h.BootstrapKey

	body := []byte(`{"version":"1.5.0","channel":"stable","notes_md":"CLI release","outcome_tags":["+perf"],"targets":["host"],"artifacts":[{"filename":"redx-1.5.0-linux-amd64.tar.gz","os":"linux","arch":"amd64","kind":"tar.gz"}]}`)
	req, _ := http.NewRequest("POST", srv.URL+"/v1/updates/apps/redx/publish", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-RedX-Confirm", "updatePublish")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("publish %d", resp.StatusCode)
	}

	out, se, code := runCLI(t, srv.URL, key, "update", "status", "redx")
	if code != 0 || !strings.Contains(out, "hosted=true") || !strings.Contains(out, "1.5.0") {
		t.Fatalf("status %d %q %s", code, out, se)
	}
	out, se, code = runCLI(t, srv.URL, key, "update", "check")
	if code != 0 || !strings.Contains(out, "redx 1.5.0") {
		t.Fatalf("check %d %q %s", code, out, se)
	}
	out, se, code = runCLI(t, srv.URL, key, "update", "apply", "redx", "--version", "1.5.0", "--source", "host")
	if code != 0 || !strings.Contains(out, "rollout ") || !strings.Contains(out, "snapshot ") {
		t.Fatalf("apply %d %q %s", code, out, se)
	}
	out, se, code = runCLI(t, srv.URL, key, "update", "status", "redx", "--json")
	if code != 0 || !strings.Contains(out, `"version": "1.5.0"`) {
		t.Fatalf("json status %d %q %s", code, out, se)
	}
	out, se, code = runCLI(t, srv.URL, key, "update", "snapshots", "redx", "--json")
	if code != 0 {
		t.Fatalf("snapshots %d %s", code, se)
	}
	var snaps struct {
		Snapshots []struct {
			ID string `json:"id"`
		} `json:"snapshots"`
	}
	if json.Unmarshal([]byte(out), &snaps) != nil || len(snaps.Snapshots) == 0 {
		t.Fatalf("snapshots json %s", out)
	}
	out, se, code = runCLI(t, srv.URL, key, "update", "source", "redx", "github")
	if code != 0 || !strings.Contains(out, "source github") {
		t.Fatalf("source %d %q %s", code, out, se)
	}
	if _, se, code = runCLI(t, srv.URL, key, "update", "source", "nope", "host"); code == 0 || !strings.Contains(se, "not_hosted") {
		t.Fatalf("not_hosted cli %d %s", code, se)
	}
}
