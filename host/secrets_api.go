package host

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"redx/internal/rsx"
)

// secretsRoute serves Red-SecretsXAI password seal/open for new text.
//
//	GET  /v1/db/{db}/secrets
//	POST /v1/db/{db}/secrets/seal
//	POST /v1/db/{db}/secrets/open
//
// Neither POST writes a record, a pack, or any existing envelope. The console
// stores a seal only when the user later presses Save on that one record.
func (h *Host) secretsRoute(w http.ResponseWriter, r *http.Request, db, rest string) {
	switch rest {
	case "":
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if _, ok := h.authz(w, r, ScopeRead, db, "", false); !ok {
			return
		}
		h.writeSecretsStatus(w)
	case "seal":
		h.secretsSeal(w, r, db)
	case "open":
		h.secretsOpen(w, r, db)
	default:
		writeErr(w, http.StatusNotFound, "not found")
	}
}

func (h *Host) writeSecretsStatus(w http.ResponseWriter) {
	kp, profile := h.secretsKDF()
	writeJSON(w, 200, map[string]interface{}{
		"enabled":          true,
		"engine":           secretsEngine,
		"binding":          "pure-go",
		"cgo":              false,
		"js_binding":       false,
		"pin":              secretsPin,
		"mode":             "password",
		"migrates":         false,
		"touches_existing": false,
		"kdf":              kdfView(profile, kp),
		"notes":            secretsNotes(),
	})
}

func kdfView(profile string, kp rsx.KDFParams) map[string]interface{} {
	return map[string]interface{}{
		"profile": profile,
		"name":    "argon2id",
		"t":       kp.T,
		"m_kib":   kp.M,
		"p":       kp.P,
	}
}

func secretsNotes() []string {
	return []string{
		"Password mode of Red-SecretsXAI (Argon2id and an RSXC container). This password is not your Red-XAI Account password.",
		"The password is sent to this host for this request only. It is not stored, not logged, and not written on the audit line.",
		"Seal returns Box text and does not write it. Save the record yourself if you want to keep the envelope. Open does not write either.",
		"This seals one value. Database files are still not encrypted by RedX. Pack files stay on AES-256-GCM when a policy Encrypt rule names them.",
		"Existing sealed packs and existing Red-SecretsXAI payloads are not read, re-wrapped, migrated, or rewritten by this.",
		"The pure-Go port runs inside redxd (CGO stays off). The browser does not load a JavaScript copy of the library.",
	}
}

type secretsSealBody struct {
	Password  string  `json:"password"`
	Plaintext *string `json:"plaintext"`
	Path      string  `json:"path"`
}

type secretsOpenBody struct {
	Password string  `json:"password"`
	Box      *string `json:"box"`
	Path     string  `json:"path"`
}

func (h *Host) secretsSeal(w http.ResponseWriter, r *http.Request, db string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req secretsSealBody
	if err := decodeSecretsBody(w, r, &req); err != nil {
		return
	}
	defer func() { req.Password = "" }()
	pw := []byte(req.Password)
	defer rsx.Wipe(pw)
	if req.Plaintext == nil {
		writeErr(w, 400, `JSON body needs "plaintext". Nothing was written.`)
		return
	}
	if strings.Contains(*req.Plaintext, secretsFormat) {
		writeErr(w, 400, "this text already contains a Red-SecretsXAI envelope. Sealing it again would wrap existing ciphertext. Nothing was written.")
		return
	}
	if err := checkSecretsPath(req.Path); err != nil {
		h.writeSecretsErr(w, err)
		return
	}
	// One authorisation check, using the record path when the caller sent one.
	// An empty path does not match a prefix-restricted key. Argon2id runs only
	// after this succeeds.
	pr, ok := h.authz(w, r, ScopeWrite, db, req.Path, false)
	if !ok {
		return
	}
	if req.Path == "" && pr.Key.Prefix != "" {
		writeErr(w, http.StatusForbidden, "a prefix-restricted key must name the record path. Nothing was written.")
		return
	}
	if err := checkSecretsPassword(req.Password); err != nil {
		h.writeSecretsErr(w, err)
		return
	}
	boxText, profile, kp, err := h.sealWithPassword(pw, secretsAAD(db, req.Path), []byte(*req.Plaintext))
	if err != nil {
		h.writeSecretsErr(w, err)
		return
	}
	h.Audit.Log(AuditEvent{
		Event: "secrets.seal", KeyID: pr.Key.ID, DB: db, Remote: remoteIP(r),
		Detail: "bytes=" + strconv.Itoa(len(*req.Plaintext)) + " profile=" + profile + " stored=false",
	})
	writeJSON(w, 200, map[string]interface{}{
		"ok": true, "sealed": true, "stored": false,
		"format": secretsFormat, "engine": secretsEngine, "binding": "pure-go", "cgo": false,
		"box": boxText, "kdf": kdfView(profile, kp),
		"note": "Nothing was written. Save this box text on the record yourself. Existing packs and other sealed data were not modified.",
	})
}

func (h *Host) secretsOpen(w http.ResponseWriter, r *http.Request, db string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req secretsOpenBody
	if err := decodeSecretsBody(w, r, &req); err != nil {
		return
	}
	defer func() { req.Password = "" }()
	pw := []byte(req.Password)
	defer rsx.Wipe(pw)
	if req.Box == nil || strings.TrimSpace(*req.Box) == "" {
		writeErr(w, 400, `JSON body needs "box" (the envelope text). Nothing was written.`)
		return
	}
	if err := checkSecretsPath(req.Path); err != nil {
		h.writeSecretsErr(w, err)
		return
	}
	// Authorise with the record path. An empty path does not match a prefix key.
	pr, ok := h.authz(w, r, ScopeRead, db, req.Path, false)
	if !ok {
		return
	}
	if req.Path == "" && pr.Key.Prefix != "" {
		writeErr(w, http.StatusForbidden, "a prefix-restricted key must name the record path. Nothing was written.")
		return
	}
	if h.secretsBlocked(pr.Key.ID) {
		writeErr(w, http.StatusTooManyRequests, "too many Red-SecretsXAI password attempts. Wait a minute and try again. Nothing was written.")
		return
	}
	if err := checkSecretsPassword(req.Password); err != nil {
		h.writeSecretsErr(w, err)
		return
	}
	pt, err := h.openWithPassword(pw, secretsAAD(db, req.Path), *req.Box)
	if err != nil {
		var se *secretsError
		if errors.As(err, &se) && se.status == 422 {
			h.noteSecretsFail(pr.Key.ID)
		}
		h.Audit.Log(AuditEvent{
			Event: "secrets.open.denied", KeyID: pr.Key.ID, DB: db, Remote: remoteIP(r),
			Reason: "open failed", Detail: "stored=false",
		})
		h.writeSecretsErr(w, err)
		return
	}
	h.Audit.Log(AuditEvent{
		Event: "secrets.open", KeyID: pr.Key.ID, DB: db, Remote: remoteIP(r),
		Detail: "bytes=" + strconv.Itoa(len(pt)) + " stored=false",
	})
	writeJSON(w, 200, map[string]interface{}{
		"ok": true, "stored": false, "plaintext": string(pt),
		"note": "Nothing was written. Saving the record afterwards stores this plaintext for this record only. Other sealed data was not modified.",
	})
}

func decodeSecretsBody(w http.ResponseWriter, r *http.Request, dst interface{}) error {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeErr(w, http.StatusUnsupportedMediaType, "content type must be application/json. Nothing was written.")
		return errors.New("content type")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxSecretsBody+1))
	if err != nil {
		writeErr(w, 400, "could not read the body. Nothing was written.")
		return err
	}
	if len(body) > maxSecretsBody {
		writeErr(w, http.StatusRequestEntityTooLarge, "request body too large. Nothing was written.")
		return errors.New("too large")
	}
	if err := json.Unmarshal(body, dst); err != nil {
		writeErr(w, 400, "invalid JSON body. Nothing was written.")
		return err
	}
	return nil
}

func (h *Host) writeSecretsErr(w http.ResponseWriter, err error) {
	var se *secretsError
	if errors.As(err, &se) {
		writeErr(w, se.status, se.msg)
		return
	}
	h.Logf("secrets: %v", err)
	writeErr(w, 500, "Red-SecretsXAI failed. Nothing was written.")
}

func (h *Host) secretsBlocked(id string) bool {
	h.secretsMu.Lock()
	defer h.secretsMu.Unlock()
	h.pruneSecretsLocked(id, time.Now())
	return len(h.secretsFail[id]) >= secretsFailMax
}

func (h *Host) noteSecretsFail(id string) {
	h.secretsMu.Lock()
	defer h.secretsMu.Unlock()
	if h.secretsFail == nil {
		h.secretsFail = map[string][]time.Time{}
	}
	now := time.Now()
	h.pruneSecretsLocked(id, now)
	h.secretsFail[id] = append(h.secretsFail[id], now)
}

func (h *Host) pruneSecretsLocked(id string, now time.Time) {
	if h.secretsFail == nil {
		return
	}
	cut := now.Add(-time.Minute)
	var keep []time.Time
	for _, t := range h.secretsFail[id] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(h.secretsFail, id)
		return
	}
	h.secretsFail[id] = keep
}
