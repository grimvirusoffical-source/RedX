package host

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func (h *Host) hostedLogs(w http.ResponseWriter, r *http.Request, id string, download bool) {
	act, ok := h.appActor(w, r, false)
	if !ok {
		return
	}
	if !act.all && act.mode == "none" {
		if refusePlan(w, act.mode, false) {
			return
		}
	}
	h.apps.mu.Lock()
	app := h.apps.apps[id]
	if !act.sees(app) {
		h.apps.mu.Unlock()
		writeErr(w, http.StatusNotFound, "app not found")
		return
	}
	kind := r.URL.Query().Get("kind")
	if kind == "" {
		kind = "runtime"
	}
	if kind != "runtime" && kind != "access" {
		h.apps.mu.Unlock()
		writeErr(w, 400, "kind must be runtime or access")
		return
	}
	lim := h.appLimit(act.pr)
	account := app.Account
	text := filterLog(h.readAppLog(app, kind, 0, lim), r.URL.Query().Get("q"))
	h.apps.mu.Unlock()
	h.meterApp(account, int64(len(text)))
	if download {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+kind+`.log"`)
		_, _ = io.WriteString(w, text)
		if text != "" && !strings.HasSuffix(text, "\n") {
			_, _ = io.WriteString(w, "\n")
		}
		return
	}
	if r.URL.Query().Get("stream") == "1" {
		h.streamLog(w, r, id, kind, lim, text, r.URL.Query().Get("q"))
		return
	}
	writeJSON(w, 200, map[string]any{"kind": kind, "log": text, "q": r.URL.Query().Get("q")})
}

func filterLog(text, q string) string {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return text
	}
	var keep []string
	for _, ln := range strings.Split(text, "\n") {
		if ln != "" && strings.Contains(strings.ToLower(ln), q) {
			keep = append(keep, ln)
		}
	}
	return strings.Join(keep, "\n")
}

func (h *Host) streamLog(w http.ResponseWriter, r *http.Request, id, kind string, lim AppLimit, first, q string) {
	fl, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, 200, map[string]any{"kind": kind, "log": first})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	for _, ln := range strings.Split(first, "\n") {
		if ln == "" {
			continue
		}
		fmt.Fprintf(w, "data: %s\n\n", ln)
	}
	fl.Flush()
	tick := time.NewTicker(300 * time.Millisecond)
	defer tick.Stop()
	seen := len(first)
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-deadline.C:
			fmt.Fprintf(w, "event: end\ndata: {}\n\n")
			fl.Flush()
			return
		case <-tick.C:
			h.apps.mu.Lock()
			app := h.apps.apps[id]
			var text string
			if app != nil {
				text = filterLog(h.readAppLog(app, kind, 2000, lim), q)
			}
			h.apps.mu.Unlock()
			if len(text) > seen {
				chunk := text[seen:]
				seen = len(text)
				for _, ln := range strings.Split(chunk, "\n") {
					if ln == "" {
						continue
					}
					fmt.Fprintf(w, "data: %s\n\n", ln)
				}
				fl.Flush()
			}
		}
	}
}
