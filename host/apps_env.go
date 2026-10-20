package host

import (
	"net/http"
	"strings"
	"time"
)

func (h *Host) hostedGetEnv(w http.ResponseWriter, r *http.Request, id string) {
	_, app, _, ok := h.readApp(w, r, id)
	if !ok {
		return
	}
	writeJSON(w, 200, map[string]any{"env": envView(app, h.apps.redxURL)})
}

func (h *Host) hostedPutEnv(w http.ResponseWriter, r *http.Request, id string) {
	act, ok := h.appActor(w, r, true)
	if !ok {
		return
	}
	var req struct {
		Vars map[string]string `json:"vars"`
	}
	if jsonUnmarshal(readBody(r), &req) != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	if len(req.Vars) > appsEnvMax {
		writeErr(w, 400, "too many variables")
		return
	}
	for k, v := range req.Vars {
		if !validEnvName(k) || k == "REDX_KEY" || k == "REDX_URL" || strings.ContainsAny(v, "\r\n") || len(v) > 8192 || guestURLBlocked(v) {
			writeErr(w, 400, "invalid environment variable")
			return
		}
	}
	h.apps.mu.Lock()
	defer h.apps.mu.Unlock()
	app := h.apps.apps[id]
	if !act.sees(app) {
		writeErr(w, http.StatusNotFound, "app not found")
		return
	}
	if app.Env == nil {
		app.Env = map[string]string{}
	}
	app.Env = req.Vars
	app.Updated = time.Now().UTC()
	if app.Current != "" {
		app.NeedsRedeploy = true
	}
	if _, err := h.writeEnvFile(app); err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	if err := h.apps.saveLocked(); err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	h.auditApp(r, act.pr, "app.env.set", id)
	writeJSON(w, 200, map[string]any{"env": envView(app, h.apps.redxURL), "needsRedeploy": app.NeedsRedeploy})
}

func (h *Host) hostedSecrets(w http.ResponseWriter, r *http.Request, id string) {
	_, app, _, ok := h.readApp(w, r, id)
	if !ok {
		return
	}
	writeJSON(w, 200, map[string]any{"secrets": secretViews(app)})
}

func (h *Host) hostedPutSecret(w http.ResponseWriter, r *http.Request, id, name string) {
	act, ok := h.appActor(w, r, true)
	if !ok {
		return
	}
	if !validEnvName(name) || name == "REDX_KEY" || name == "REDX_URL" {
		writeErr(w, 400, "invalid secret name")
		return
	}
	var req struct {
		Value string `json:"value"`
	}
	if jsonUnmarshal(readBody(r), &req) != nil || req.Value == "" || len(req.Value) > appsSecretMax || strings.ContainsAny(req.Value, "\r\n\x00") || guestURLBlocked(req.Value) {
		writeErr(w, 400, "invalid secret")
		return
	}
	h.apps.mu.Lock()
	defer h.apps.mu.Unlock()
	app := h.apps.apps[id]
	if !act.sees(app) {
		writeErr(w, http.StatusNotFound, "app not found")
		return
	}
	if len(app.Secrets) >= appsEnvMax {
		writeErr(w, 400, "too many secrets")
		return
	}
	sec, err := h.apps.seal(app.Account, app.ID, name, []byte(req.Value))
	if err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	replaced := false
	for i := range app.Secrets {
		if app.Secrets[i].Name == name {
			app.Secrets[i] = sec
			replaced = true
		}
	}
	if !replaced {
		app.Secrets = append(app.Secrets, sec)
	}
	app.Updated = time.Now().UTC()
	if app.Current != "" {
		app.NeedsRedeploy = true
	}
	if _, err := h.writeEnvFile(app); err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	if err := h.apps.saveLocked(); err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	h.auditApp(r, act.pr, "app.secret.set", id+" "+name)
	writeJSON(w, 200, map[string]any{"name": name, "set": true, "value": appsSecretMask, "needsRedeploy": app.NeedsRedeploy})
}

func (h *Host) hostedDelSecret(w http.ResponseWriter, r *http.Request, id, name string) {
	act, ok := h.appActor(w, r, true)
	if !ok {
		return
	}
	h.apps.mu.Lock()
	defer h.apps.mu.Unlock()
	app := h.apps.apps[id]
	if !act.sees(app) {
		writeErr(w, http.StatusNotFound, "app not found")
		return
	}
	next := app.Secrets[:0]
	found := false
	for _, s := range app.Secrets {
		if s.Name == name {
			found = true
			continue
		}
		next = append(next, s)
	}
	if !found {
		writeErr(w, http.StatusNotFound, "secret not found")
		return
	}
	app.Secrets = next
	app.Updated = time.Now().UTC()
	if app.Current != "" {
		app.NeedsRedeploy = true
	}
	_, _ = h.writeEnvFile(app)
	if err := h.apps.saveLocked(); err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	h.auditApp(r, act.pr, "app.secret.delete", id+" "+name)
	writeJSON(w, 200, map[string]any{"ok": true, "name": name, "needsRedeploy": app.NeedsRedeploy})
}
