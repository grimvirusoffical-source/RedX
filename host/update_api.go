package host

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

func writeUpdateErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]interface{}{
		"error": map[string]string{"code": code, "message": msg},
	})
}

func (h *Host) updateFail(w http.ResponseWriter, err error) {
	switch {
	case err == nil:
		return
	case errors.Is(err, errNotHosted):
		writeUpdateErr(w, http.StatusConflict, "not_hosted", "app is not hosted with Red-XAI")
	case errors.Is(err, errSeq):
		writeUpdateErr(w, http.StatusConflict, "sequence_regression", "sequence regression")
	case errors.Is(err, errBadSig):
		writeUpdateErr(w, http.StatusBadRequest, "bad_signature", "bad signature")
	case errors.Is(err, errSnap):
		writeUpdateErr(w, http.StatusConflict, "snapshot_failed", "snapshot failed")
	case errors.Is(err, errRolloutConflict):
		writeUpdateErr(w, http.StatusConflict, "rollout_conflict", "rollout conflict")
	case errors.Is(err, errHealth):
		writeUpdateErr(w, http.StatusConflict, "rollout_conflict", "health threshold")
	case errors.Is(err, os.ErrNotExist):
		writeUpdateErr(w, http.StatusNotFound, "not_found", "not found")
	default:
		if os.IsNotExist(err) {
			writeUpdateErr(w, http.StatusNotFound, "not_found", "not found")
			return
		}
		writeUpdateErr(w, http.StatusBadRequest, "invalid", err.Error())
	}
}

func (h *Host) updateAuth(w http.ResponseWriter, r *http.Request, admin bool) (*Principal, bool) {
	pr, wait, err := h.Auth.Authenticate(r)
	switch {
	case errors.Is(err, ErrThrottled):
		w.Header().Set("Retry-After", strconv.Itoa(int(wait/time.Second)+1))
		writeUpdateErr(w, http.StatusTooManyRequests, "forbidden", "rate limit exceeded")
		return nil, false
	case err != nil:
		h.authBad.Add(1)
		w.Header().Set("WWW-Authenticate", `Bearer realm="redx"`)
		writeUpdateErr(w, http.StatusUnauthorized, "forbidden", "unauthorized")
		return nil, false
	}
	if admin && !pr.Key.IsHostAdmin() {
		h.Audit.Log(AuditEvent{Event: "auth.denied", KeyID: pr.Key.ID, Remote: remoteIP(r), Method: r.Method, Route: routeOf(r), Reason: "host-admin required"})
		writeUpdateErr(w, http.StatusForbidden, "forbidden", "host-admin required")
		return nil, false
	}
	return pr, true
}

func (h *Host) auditUpdate(r *http.Request, pr *Principal, event, detail string) {
	id := ""
	if pr != nil {
		id = pr.Key.ID
	}
	if len(detail) > 300 {
		detail = detail[:300]
	}
	h.Audit.Log(AuditEvent{Event: event, KeyID: id, Remote: remoteIP(r), Method: r.Method, Route: routeOf(r), Detail: detail})
}

func (h *Host) updateRoute(w http.ResponseWriter, r *http.Request) {
	if h.maybeForward(w, r) {
		return
	}
	if h.upd == nil {
		writeUpdateErr(w, http.StatusNotFound, "not_found", "updates are not available")
		return
	}
	p := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/updates"), "/")
	parts := []string{}
	if p != "" {
		parts = strings.Split(p, "/")
	}
	if len(parts) == 4 && parts[2] == "artifacts" && r.Method == http.MethodGet {
		h.updateArtifact(w, r, parts[0], parts[1], parts[3])
		return
	}
	switch {
	case p == "keys" && r.Method == http.MethodGet:
		h.updateKeys(w, r)
	case p == "events" && r.Method == http.MethodGet:
		h.updateEvents(w, r)
	case p == "github/webhook" && r.Method == http.MethodPost:
		h.updateGitHubWebhook(w, r)
	case p == "apps" && r.Method == http.MethodGet:
		h.updateAppList(w, r)
	case len(parts) >= 2 && parts[0] == "apps":
		h.updateAppRoute(w, r, parts[1], parts[2:])
	case len(parts) >= 2 && parts[0] == "rollouts":
		h.updateRolloutRoute(w, r, parts[1], parts[2:])
	default:
		writeUpdateErr(w, http.StatusNotFound, "not_found", "not found")
	}
}

func (h *Host) updateKeys(w http.ResponseWriter, r *http.Request) {
	kid, pub, until := h.upd.publicKeys()
	w.Header().Set("X-RedX-Key-Id", kid)
	writeJSON(w, 200, []map[string]string{{
		"kid": kid, "alg": "ed25519", "pub": pub, "not_after": until.UTC().Format(time.RFC3339),
	}})
}

func (h *Host) updateEvents(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.updateAuth(w, r, false); !ok {
		return
	}
	ch, cancel := h.upd.subscribe()
	defer cancel()
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn.SetReadLimit(1 << 10)
		_ = conn.SetReadDeadline(time.Now().Add(70 * time.Second))
		conn.SetPongHandler(func(string) error { return conn.SetReadDeadline(time.Now().Add(70 * time.Second)) })
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return
			}
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteJSON(ev); err != nil {
				return
			}
		case <-tick.C:
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		case <-done:
			return
		case <-r.Context().Done():
			return
		}
	}
}

func (h *Host) updateAppList(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.updateAuth(w, r, false); !ok {
		return
	}
	h.upd.mu.Lock()
	names := make([]string, 0, len(h.upd.st.Apps))
	for n := range h.upd.st.Apps {
		names = append(names, n)
	}
	h.upd.mu.Unlock()
	out := make([]interface{}, 0, len(names))
	for _, n := range names {
		out = append(out, h.upd.status(n))
	}
	writeJSON(w, 200, map[string]interface{}{"apps": out})
}

func (h *Host) updateAppRoute(w http.ResponseWriter, r *http.Request, app string, rest []string) {
	if !validAppID(app) {
		writeUpdateErr(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	if len(rest) == 0 && r.Method == http.MethodGet {
		pr, ok := h.updateAuth(w, r, false)
		if !ok || !h.refuseHiddenDB(w, r, pr, app) {
			return
		}
		writeJSON(w, 200, h.upd.status(app))
		return
	}
	if len(rest) == 0 {
		writeUpdateErr(w, http.StatusMethodNotAllowed, "not_found", "method not allowed")
		return
	}
	switch rest[0] {
	case "history":
		if r.Method != http.MethodGet {
			writeUpdateErr(w, http.StatusMethodNotAllowed, "not_found", "method not allowed")
			return
		}
		pr, ok := h.updateAuth(w, r, false)
		if !ok || !h.refuseHiddenDB(w, r, pr, app) {
			return
		}
		writeJSON(w, 200, map[string]interface{}{"history": h.upd.history(app)})
	case "snapshots":
		if r.Method != http.MethodGet {
			writeUpdateErr(w, http.StatusMethodNotAllowed, "not_found", "method not allowed")
			return
		}
		pr, ok := h.updateAuth(w, r, false)
		if !ok || !h.refuseHiddenDB(w, r, pr, app) {
			return
		}
		writeJSON(w, 200, map[string]interface{}{"snapshots": h.upd.snapshots(app)})
	case "source":
		h.updateSource(w, r, app)
	case "policy":
		h.updatePolicy(w, r, app)
	case "apply":
		h.updateApply(w, r, app)
	case "rollback":
		h.updateRestore(w, r, app)
	case "publish":
		h.updatePublish(w, r, app)
	case "manifests":
		h.updateManifestRoute(w, r, app, rest[1:])
	default:
		writeUpdateErr(w, http.StatusNotFound, "not_found", "not found")
	}
}

func (h *Host) updateManifestRoute(w http.ResponseWriter, r *http.Request, app string, rest []string) {
	if r.Method != http.MethodGet || len(rest) < 1 {
		writeUpdateErr(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	pr, ok := h.updateAuth(w, r, false)
	if !ok || !h.refuseHiddenDB(w, r, pr, app) {
		return
	}
	ver := rest[0]
	sig := false
	if strings.HasSuffix(ver, ".sig") {
		sig = true
		ver = strings.TrimSuffix(ver, ".sig")
	}
	if len(rest) >= 2 && rest[1] == "manifest.sig" {
		sig = true
	}
	if len(rest) >= 3 && rest[1] == "artifacts" {
		h.serveArtifact(w, r, app, ver, rest[2])
		return
	}
	if !validVersion(ver) {
		writeUpdateErr(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	source, err := h.upd.chooseSource(app, ver, r.URL.Query().Get("source"))
	if err != nil {
		h.updateFail(w, err)
		return
	}
	_, body, signature, err := h.upd.loadManifest(app, ver, source)
	if err != nil {
		h.updateFail(w, err)
		return
	}
	w.Header().Set("X-RedX-Signature", signature)
	w.Header().Set("X-RedX-Key-Id", h.upd.kid)
	if sig {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, signature)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(body)
}

func (h *Host) updateArtifact(w http.ResponseWriter, r *http.Request, app, version, id string) {
	pr, ok := h.updateAuth(w, r, false)
	if !ok || !h.refuseHiddenDB(w, r, pr, app) {
		return
	}
	h.serveArtifact(w, r, app, version, id)
}

func (h *Host) serveArtifact(w http.ResponseWriter, r *http.Request, app, version, id string) {
	if !validVersion(version) || !validArtifactID(id) {
		writeUpdateErr(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	source, err := h.upd.chooseSource(app, version, r.URL.Query().Get("source"))
	if err != nil {
		h.updateFail(w, err)
		return
	}
	b, err := h.upd.blob(app, version, source, id)
	if err != nil {
		h.updateFail(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Redx-SHA256", sha256Hex(b))
	w.WriteHeader(200)
	_, _ = w.Write(b)
}

func (h *Host) updateSource(w http.ResponseWriter, r *http.Request, app string) {
	if r.Method != http.MethodPut {
		writeUpdateErr(w, http.StatusMethodNotAllowed, "not_found", "method not allowed")
		return
	}
	pr, ok := h.updateAuth(w, r, true)
	if !ok || !h.guardUpdateMutation(w, r, pr, app, false, false) {
		return
	}
	var body struct {
		Source string `json:"source"`
	}
	if json.Unmarshal(readBody(r), &body) != nil {
		writeUpdateErr(w, 400, "invalid", "invalid JSON")
		return
	}
	switch body.Source {
	case "host", "github", "both":
	default:
		writeUpdateErr(w, 400, "invalid", "source must be host, github or both")
		return
	}
	if err := h.upd.setSource(app, body.Source); err != nil {
		h.updateFail(w, err)
		return
	}
	h.auditUpdate(r, pr, "update.source", "app="+app+" source="+body.Source)
	writeJSON(w, 200, map[string]interface{}{"app": app, "source": body.Source})
}

func (h *Host) updatePolicy(w http.ResponseWriter, r *http.Request, app string) {
	if r.Method != http.MethodPut {
		writeUpdateErr(w, http.StatusMethodNotAllowed, "not_found", "method not allowed")
		return
	}
	pr, ok := h.updateAuth(w, r, true)
	if !ok || !h.guardUpdateMutation(w, r, pr, app, false, false) {
		return
	}
	var body struct {
		AutoApply string  `json:"auto_apply"`
		Channel   string  `json:"channel"`
		Window    *string `json:"window"`
	}
	if json.Unmarshal(readBody(r), &body) != nil {
		writeUpdateErr(w, 400, "invalid", "invalid JSON")
		return
	}
	window := ""
	if body.Window != nil {
		window = *body.Window
	}
	if err := h.upd.setPolicy(app, body.AutoApply, body.Channel, window); err != nil {
		h.updateFail(w, err)
		return
	}
	h.auditUpdate(r, pr, "update.policy", "app="+app+" auto_apply="+body.AutoApply+" channel="+body.Channel)
	writeJSON(w, 200, map[string]interface{}{"app": app, "auto_apply": body.AutoApply, "channel": body.Channel, "window": window})
}

func (h *Host) updateApply(w http.ResponseWriter, r *http.Request, app string) {
	if r.Method != http.MethodPost {
		writeUpdateErr(w, http.StatusMethodNotAllowed, "not_found", "method not allowed")
		return
	}
	pr, ok := h.updateAuth(w, r, true)
	if !ok {
		return
	}
	var body struct {
		Version  string `json:"version"`
		Source   string `json:"source"`
		Strategy string `json:"strategy"`
		Canary   *struct {
			Percent    int `json:"percent"`
			MinMinutes int `json:"min_minutes"`
		} `json:"canary"`
		ScheduleAt *string `json:"schedule_at"`
		DryRun     bool    `json:"dry_run"`
	}
	if json.Unmarshal(readBody(r), &body) != nil {
		writeUpdateErr(w, 400, "invalid", "invalid JSON")
		return
	}
	strategy := body.Strategy
	if strategy == "" {
		strategy = "direct"
	}
	topology := strategy == "canary" || strategy == "blue_green"
	if !h.guardUpdateMutation(w, r, pr, app, topology, true) {
		return
	}
	in := applyInput{App: app, Version: body.Version, Source: body.Source, Strategy: strategy, DryRun: body.DryRun}
	if body.Canary != nil {
		in.Percent = body.Canary.Percent
		in.MinMinutes = body.Canary.MinMinutes
	}
	if body.ScheduleAt != nil && *body.ScheduleAt != "" {
		t, err := time.Parse(time.RFC3339, *body.ScheduleAt)
		if err != nil {
			writeUpdateErr(w, 400, "invalid", "schedule_at must be RFC3339")
			return
		}
		in.ScheduleAt = &t
	}
	ro, snap, err := h.upd.apply(in)
	if err != nil {
		h.auditUpdate(r, pr, "update.apply", "app="+app+" version="+body.Version+" error")
		h.updateFail(w, err)
		return
	}
	h.auditUpdate(r, pr, "update.apply", "app="+app+" version="+body.Version+" strategy="+strategy+" rollout="+ro+" snapshot="+snap)
	writeJSON(w, http.StatusAccepted, map[string]interface{}{"rollout_id": ro, "snapshot_id": snap})
}

func (h *Host) updateRestore(w http.ResponseWriter, r *http.Request, app string) {
	if r.Method != http.MethodPost {
		writeUpdateErr(w, http.StatusMethodNotAllowed, "not_found", "method not allowed")
		return
	}
	pr, ok := h.updateAuth(w, r, true)
	if !ok || !h.guardUpdateMutation(w, r, pr, app, true, true) {
		return
	}
	var body struct {
		SnapshotID string `json:"snapshot_id"`
	}
	if json.Unmarshal(readBody(r), &body) != nil || body.SnapshotID == "" {
		writeUpdateErr(w, 400, "invalid", `body must be {"snapshot_id":"snap_..."}`)
		return
	}
	if err := h.upd.restoreApp(app, body.SnapshotID, "restore"); err != nil {
		h.auditUpdate(r, pr, "update.restore", "app="+app+" snapshot="+body.SnapshotID+" error")
		h.updateFail(w, err)
		return
	}
	h.auditUpdate(r, pr, "update.restore", "app="+app+" snapshot="+body.SnapshotID)
	h.upd.emit(UpdateEvent{Type: "rollback.done", App: app, Version: "", Source: "", State: "rolled_back"})
	writeJSON(w, 200, map[string]interface{}{"ok": true, "snapshot_id": body.SnapshotID, "app": app})
}

func (h *Host) updateRolloutRoute(w http.ResponseWriter, r *http.Request, id string, rest []string) {
	if len(rest) == 0 && r.Method == http.MethodGet {
		if _, ok := h.updateAuth(w, r, false); !ok {
			return
		}
		view, err := h.upd.rolloutView(id)
		if err != nil {
			h.updateFail(w, err)
			return
		}
		writeJSON(w, 200, view)
		return
	}
	if len(rest) != 1 {
		writeUpdateErr(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	pr, ok := h.updateAuth(w, r, true)
	if !ok {
		return
	}
	app := h.upd.rolloutApp(id)
	switch rest[0] {
	case "promote":
		if r.Method != http.MethodPost {
			writeUpdateErr(w, http.StatusMethodNotAllowed, "not_found", "method not allowed")
			return
		}
		if !h.guardUpdateMutation(w, r, pr, app, true, false) {
			return
		}
		if err := h.upd.promote(id); err != nil {
			h.auditUpdate(r, pr, "update.promote", "rollout="+id+" error")
			h.updateFail(w, err)
			return
		}
		h.auditUpdate(r, pr, "update.promote", "rollout="+id)
		view, _ := h.upd.rolloutView(id)
		writeJSON(w, 200, view)
	case "rollback":
		if r.Method != http.MethodPost {
			writeUpdateErr(w, http.StatusMethodNotAllowed, "not_found", "method not allowed")
			return
		}
		if !h.guardUpdateMutation(w, r, pr, app, true, true) {
			return
		}
		var body struct {
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(readBody(r), &body)
		if body.Reason == "" {
			body.Reason = "rollback"
		}
		if err := h.upd.rollbackRollout(id, body.Reason); err != nil {
			h.auditUpdate(r, pr, "update.rollback", "rollout="+id+" error")
			h.updateFail(w, err)
			return
		}
		h.auditUpdate(r, pr, "update.rollback", "rollout="+id)
		view, _ := h.upd.rolloutView(id)
		writeJSON(w, 200, view)
	default:
		writeUpdateErr(w, http.StatusNotFound, "not_found", "not found")
	}
}
