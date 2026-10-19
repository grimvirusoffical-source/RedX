package host

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type publishArtifact struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Filename  string `json:"filename"`
	SHA256    string `json:"sha256"`
	UploadURL string `json:"upload_url"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	Kind      string `json:"kind"`
}

type publishInput struct {
	Version string
	Channel string
	Notes   string
	Tags    []string
	Targets []string
	Arts    []publishArtifact
	Repo    string
	BaseURL string
}

func (h *Host) updatePublish(w http.ResponseWriter, r *http.Request, app string) {
	if r.Method != http.MethodPost {
		writeUpdateErr(w, http.StatusMethodNotAllowed, "not_found", "method not allowed")
		return
	}
	pr, ok := h.updateAuth(w, r, true)
	if !ok {
		return
	}
	var body struct {
		Version     string            `json:"version"`
		Channel     string            `json:"channel"`
		NotesMD     string            `json:"notes_md"`
		OutcomeTags []string          `json:"outcome_tags"`
		Targets     []string          `json:"targets"`
		Artifacts   []publishArtifact `json:"artifacts"`
	}
	if json.Unmarshal(readBody(r), &body) != nil {
		writeUpdateErr(w, 400, "invalid", "invalid JSON")
		return
	}
	touchesMaster := h.IsMasterDB(app)
	if !h.guardUpdateMutation(w, r, pr, app, false, touchesMaster) {
		return
	}
	urls, err := h.upd.publish(r.Context(), publishInput{
		Version: body.Version, Channel: body.Channel, Notes: body.NotesMD, Tags: body.OutcomeTags,
		Targets: body.Targets, Arts: body.Artifacts, BaseURL: h.publicBase(r),
	}, app)
	if err != nil {
		h.auditUpdate(r, pr, "update.publish", "app="+app+" version="+body.Version+" error")
		h.updateFail(w, err)
		return
	}
	h.auditUpdate(r, pr, "update.publish", "app="+app+" version="+body.Version)
	writeJSON(w, 201, map[string]interface{}{"app": app, "version": body.Version, "manifests": urls})
}

func (u *updater) publish(ctx context.Context, in publishInput, app string) (map[string]string, error) {
	if !validAppID(app) || !validVersion(in.Version) {
		return nil, errString("invalid app or version")
	}
	if in.Channel == "" {
		in.Channel = "stable"
	}
	switch in.Channel {
	case "stable", "beta", "security":
	default:
		return nil, errString("channel must be stable, beta or security")
	}
	if len(in.Targets) == 0 {
		return nil, errString("targets must include host, github or both")
	}
	if err := validateOutcomeTags(in.Tags); err != nil {
		return nil, err
	}
	if len(in.Tags) == 0 {
		in.Tags = guessTags(in.Notes)
	}
	wantHost, wantGit := false, false
	for _, t := range in.Targets {
		switch t {
		case "host":
			wantHost = true
		case "github":
			wantGit = true
		default:
			return nil, errString("targets must be host and/or github")
		}
	}
	repo := in.Repo
	if repo == "" {
		repo = os.Getenv("REDX_GITHUB_REPO")
	}
	if repo == "" {
		repo = u.h.Cfg.GithubRepo
	}
	u.mu.Lock()
	if repo == "" && u.st.Apps[app] != nil {
		repo = u.st.Apps[app].GitHubRepo
	}
	u.mu.Unlock()
	if wantGit && (repo == "" || strings.TrimSpace(os.Getenv("REDX_GITHUB_TOKEN")) == "") {
		return nil, errString("github repo or token is not configured")
	}
	files, arts, err := u.materialize(ctx, app, in.Version, in.Arts, in.BaseURL)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	var signed *Manifest
	if wantHost {
		m, err := u.signBuilt(app, in, "host", arts, repo, 0, "")
		if err != nil {
			return nil, err
		}
		signed = m
		out["host"] = manifestURL(in.BaseURL, app, in.Version, "host")
		u.mu.Lock()
		u.appLocked(app).Hosted = true
		_ = u.saveLocked()
		u.mu.Unlock()
	}
	if wantGit {
		id, _, err := u.githubCreateRelease(ctx, repo, in.Version, in.Notes, files)
		if err != nil {
			return nil, err
		}
		m, err := u.signBuilt(app, in, "github", arts, repo, id, "")
		if err != nil {
			return nil, err
		}
		signed = m
		out["github"] = manifestURL(in.BaseURL, app, in.Version, "github")
	}
	if signed != nil {
		u.emit(UpdateEvent{Type: "update.available", App: app, Version: in.Version, Source: signed.Source.Kind})
		u.emit(UpdateEvent{Type: "update.analysed", App: app, Version: in.Version, Source: signed.Source.Kind})
		u.maybeAuto(app, in.Version, signed.Source.Kind, signed.Outcome.Tags, signed.Channel)
	}
	return out, nil
}

func manifestURL(base, app, version, source string) string {
	return strings.TrimRight(base, "/") + "/v1/updates/apps/" + url.PathEscape(app) + "/manifests/" + url.PathEscape(version) + "?source=" + source
}

func (u *updater) materialize(ctx context.Context, app, version string, in []publishArtifact, base string) (map[string][]byte, []Artifact, error) {
	files := map[string][]byte{}
	arts := make([]Artifact, 0, len(in))
	limit := int64(u.h.Cfg.MaxUploadMB) << 20
	if limit <= 0 {
		limit = 64 << 20
	}
	for _, a := range in {
		if a.Filename == "" {
			return nil, nil, errString("artifact filename is required")
		}
		if strings.Contains(a.Filename, "/") || strings.Contains(a.Filename, "..") {
			return nil, nil, errString("invalid artifact filename")
		}
		osName, arch, kind := a.OS, a.Arch, a.Kind
		if osName == "" || arch == "" || kind == "" {
			gOS, gArch, gKind := classifyFilename(a.Filename)
			if osName == "" {
				osName = gOS
			}
			if arch == "" {
				arch = gArch
			}
			if kind == "" {
				kind = gKind
			}
		}
		osName, arch = normOS(osName), normArch(arch)
		id := a.ID
		if id == "" {
			id = strings.TrimSuffix(strings.ToLower(a.Filename), "."+kind)
			id = strings.ReplaceAll(id, ".", "-")
		}
		if !validArtifactID(id) {
			return nil, nil, errString("invalid artifact id")
		}
		var body []byte
		if a.UploadURL != "" {
			b, err := u.fetch(ctx, a.UploadURL, limit)
			if err != nil {
				return nil, nil, err
			}
			if a.SHA256 != "" && !strings.EqualFold(sha256Hex(b), a.SHA256) {
				return nil, nil, errBadSig
			}
			if a.SHA256 == "" {
				a.SHA256 = sha256Hex(b)
			}
			body = b
			files[a.Filename] = b
		} else if a.SHA256 != "" && !validSHA256(a.SHA256) {
			return nil, nil, errString("invalid sha256")
		}
		if a.SHA256 != "" {
			a.SHA256 = strings.ToLower(a.SHA256)
		}
		mirror := strings.TrimRight(base, "/") + "/v1/updates/apps/" + url.PathEscape(app) + "/manifests/" + url.PathEscape(version) + "/artifacts/" + url.PathEscape(id)
		art := Artifact{
			ID: id, Label: a.Label, OS: osName, Arch: arch, Kind: kind, Filename: a.Filename,
			URL: a.UploadURL, Mirrors: []string{mirror}, Size: int64(len(body)), SHA256: a.SHA256,
		}
		arts = append(arts, art)
		if body != nil {
			if err := u.saveBlob(app, version, "host", id, body); err != nil {
				return nil, nil, err
			}
			if err := u.saveBlob(app, version, "github", id, body); err != nil {
				return nil, nil, err
			}
		}
	}
	applyDistinctLabels(app, version, arts)
	return files, arts, nil
}

func (u *updater) saveBlob(app, version, source, id string, b []byte) error {
	rel := filepath.Join("blobs", app, version, source, id)
	abs := filepath.Join(u.dir, rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(abs, b, 0o600); err != nil {
		return err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.st.Blobs[blobKey(app, version, source, id)] = rel
	return u.saveLocked()
}

func (u *updater) signBuilt(app string, in publishInput, kind string, arts []Artifact, repo string, releaseID int64, commit string) (*Manifest, error) {
	if commit == "" || !validCommit(commit) {
		commit = zeroCommit
	}
	tag := in.Version
	if !strings.HasPrefix(tag, "v") {
		tag = "v" + tag
	}
	copied := make([]Artifact, len(arts))
	copy(copied, arts)
	for i := range copied {
		copied[i].Mirrors = append([]string(nil), arts[i].Mirrors...)
		if len(copied[i].Mirrors) == 0 {
			continue
		}
		if q := strings.Index(copied[i].Mirrors[0], "?"); q >= 0 {
			copied[i].Mirrors[0] = copied[i].Mirrors[0][:q]
		}
		copied[i].Mirrors[0] += "?source=" + kind
	}
	m := &Manifest{
		Schema: updateManifestSchema, App: app, Version: in.Version, Channel: in.Channel,
		PublishedAt: time.Now().UTC().Format(time.RFC3339),
		Source:      ManifestSource{Kind: kind},
		Outcome:     outcomeFromNotes(in.Tags, in.Notes),
		Requires:    Requires{Restart: true, Migrations: []string{}},
		Artifacts:   copied,
	}
	if kind == "host" {
		m.Source.Host = &HostOrigin{BuildID: newUpdateID("hb_"), Commit: commit}
	} else {
		m.Source.GitHub = &GitHubOrigin{Repo: repo, Tag: tag, Commit: commit, ReleaseID: releaseID}
	}
	if _, _, err := u.putManifest(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (u *updater) maybeAuto(app, version, source string, tags []string, channel string) {
	if u.h.masterDB() != "" {
		return
	}
	u.mu.Lock()
	a := u.st.Apps[app]
	if a == nil {
		u.mu.Unlock()
		return
	}
	pol := a.Policy
	hosted := a.Hosted
	u.mu.Unlock()
	if pol.AutoApply == "" || pol.AutoApply == "off" {
		return
	}
	if pol.Channel == "stable" && channel != "stable" && channel != "security" {
		return
	}
	if pol.AutoApply == "security" {
		ok := false
		for _, t := range tags {
			if t == "+security" {
				ok = true
			}
			if t == "-breaking" {
				return
			}
		}
		if !ok {
			return
		}
	}
	if !cronMatches(pol.Window, time.Now().UTC()) {
		return
	}
	if source == "host" && !hosted {
		return
	}
	strat := "direct"
	pct := 0
	min := 0
	if len(u.membersOf()) > 1 {
		strat = "canary"
		pct = 10
		min = 15
	}
	_, _, _ = u.apply(applyInput{App: app, Version: version, Source: source, Strategy: strat, Percent: pct, MinMinutes: min})
}

func (u *updater) githubAPIBase() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.githubAPI != "" {
		return strings.TrimRight(u.githubAPI, "/")
	}
	if v := os.Getenv("REDX_GITHUB_API"); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "https://api.github.com"
}

func (u *updater) githubCreateRelease(ctx context.Context, repo, version, notes string, files map[string][]byte) (int64, string, error) {
	token := strings.TrimSpace(os.Getenv("REDX_GITHUB_TOKEN"))
	if token == "" {
		return 0, "", errString("github token is not configured")
	}
	tag := version
	if !strings.HasPrefix(tag, "v") {
		tag = "v" + tag
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"tag_name": tag, "name": tag, "body": notes, "draft": false,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.githubAPIBase()+"/repos/"+repo+"/releases", bytes.NewReader(payload))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := u.httpClient().Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, "", fmt.Errorf("github release: status %d", resp.StatusCode)
	}
	var out struct {
		ID      int64  `json:"id"`
		HTMLURL string `json:"html_url"`
		Upload  string `json:"upload_url"`
	}
	if json.Unmarshal(b, &out) != nil || out.ID == 0 {
		return 0, "", errors.New("github release: bad response")
	}
	for name, body := range files {
		if err := u.githubUpload(ctx, token, out.Upload, name, body); err != nil {
			return 0, "", err
		}
	}
	return out.ID, out.HTMLURL, nil
}

func (u *updater) githubUpload(ctx context.Context, token, uploadURL, name string, body []byte) error {
	if uploadURL == "" {
		return nil
	}
	uploadURL = strings.TrimSuffix(uploadURL, "{?name,label}")
	up, err := url.Parse(uploadURL)
	if err != nil {
		return err
	}
	q := up.Query()
	q.Set("name", name)
	up.RawQuery = q.Encode()
	if err := u.allowFetch(up.String()); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, up.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := u.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("github upload %s: status %d", name, resp.StatusCode)
	}
	return nil
}

func (u *updater) httpClient() *http.Client {
	return &http.Client{Timeout: 60 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		return u.allowFetch(req.URL.String())
	}}
}

func (u *updater) allowFetch(raw string) error {
	u.mu.Lock()
	lb := u.allowLoopback
	api := u.githubAPI
	u.mu.Unlock()
	if os.Getenv("REDX_UPDATE_ALLOW_LOOPBACK") == "1" {
		lb = true
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return errors.New("refused artifact url")
	}
	host := parsed.Hostname()
	if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
		if lb && ip.IsLoopback() {
			return nil
		}
		return errors.New("refused artifact url")
	}
	if strings.EqualFold(host, "localhost") {
		if lb {
			return nil
		}
		return errors.New("refused artifact url")
	}
	if api != "" {
		if au, err := url.Parse(api); err == nil && strings.EqualFold(au.Host, parsed.Host) {
			return nil
		}
	}
	if parsed.Scheme == "https" && githubHost(host) {
		return nil
	}
	return errors.New("refused artifact url")
}

func githubHost(h string) bool {
	h = strings.ToLower(h)
	switch h {
	case "github.com", "api.github.com", "uploads.github.com", "objects.githubusercontent.com",
		"release-assets.githubusercontent.com", "codeload.github.com":
		return true
	}
	return strings.HasSuffix(h, ".githubusercontent.com") || strings.HasSuffix(h, ".github.com")
}

func (u *updater) fetch(ctx context.Context, raw string, limit int64) ([]byte, error) {
	if err := u.allowFetch(raw); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	resp, err := u.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("artifact download status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("artifact is too large")
	}
	return b, nil
}

func (h *Host) updateGitHubWebhook(w http.ResponseWriter, r *http.Request) {
	body := readBody(r)
	secret := h.upd.webhookSecret()
	if len(secret) == 0 {
		writeUpdateErr(w, http.StatusServiceUnavailable, "forbidden", "webhook secret is not configured")
		return
	}
	if !hubSigOK(secret, body, r.Header.Get("X-Hub-Signature-256")) {
		h.Audit.Log(AuditEvent{Event: "update.webhook", Remote: remoteIP(r), Method: r.Method, Route: routeOf(r), Reason: "bad signature"})
		writeUpdateErr(w, http.StatusUnauthorized, "bad_signature", "bad signature")
		return
	}
	var payload gitHook
	if json.Unmarshal(body, &payload) != nil {
		writeUpdateErr(w, 400, "invalid", "invalid JSON")
		return
	}
	event := r.Header.Get("X-GitHub-Event")
	if event == "" {
		event = payload.Event
	}
	switch event {
	case "release":
		if payload.Action != "" && payload.Action != "published" && payload.Action != "released" && payload.Action != "created" && payload.Action != "edited" {
			writeJSON(w, 202, map[string]interface{}{"ok": true, "skipped": payload.Action})
			return
		}
		if err := h.upd.ingestRelease(r.Context(), h.publicBase(r), payload); err != nil {
			h.Audit.Log(AuditEvent{Event: "update.webhook", Remote: remoteIP(r), Method: r.Method, Route: routeOf(r), Reason: "rejected"})
			h.updateFail(w, err)
			return
		}
		h.Audit.Log(AuditEvent{Event: "update.webhook", Remote: remoteIP(r), Method: r.Method, Route: routeOf(r), Detail: "release " + payload.Repository.FullName + " " + payload.Release.TagName})
		writeJSON(w, 202, map[string]interface{}{"ok": true})
	case "push", "workflow_run":
		h.Audit.Log(AuditEvent{Event: "update.webhook", Remote: remoteIP(r), Method: r.Method, Route: routeOf(r), Detail: event})
		writeJSON(w, 202, map[string]interface{}{"ok": true, "skipped": event})
	default:
		writeJSON(w, 202, map[string]interface{}{"ok": true, "skipped": event})
	}
}

func (u *updater) webhookSecret() []byte {
	if s := os.Getenv("REDX_GITHUB_WEBHOOK_SECRET"); s != "" {
		return []byte(s)
	}
	path := u.h.Cfg.GithubWebhookSecretFile
	if path == "" {
		path = os.Getenv("REDX_GITHUB_WEBHOOK_SECRET_FILE")
	}
	if path == "" {
		return nil
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil
	}
	if os.PathSeparator == '/' && st.Mode().Perm()&0o077 != 0 {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return []byte(strings.TrimSpace(string(b)))
}

func hubSigOK(secret, body []byte, header string) bool {
	const pfx = "sha256="
	if !strings.HasPrefix(header, pfx) || len(secret) == 0 {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	want := mac.Sum(nil)
	got, err := hex.DecodeString(strings.TrimSpace(header[len(pfx):]))
	if err != nil || len(got) != len(want) {
		return false
	}
	return hmac.Equal(got, want)
}

type gitHook struct {
	Event      string `json:"event"`
	Action     string `json:"action"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	Release struct {
		ID              int64  `json:"id"`
		TagName         string `json:"tag_name"`
		Body            string `json:"body"`
		TargetCommitish string `json:"target_commitish"`
		Prerelease      bool   `json:"prerelease"`
		Assets          []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
			Size               int64  `json:"size"`
		} `json:"assets"`
	} `json:"release"`
}

func (u *updater) ingestRelease(ctx context.Context, base string, p gitHook) error {
	repo := p.Repository.FullName
	app := appFromRepo(repo)
	if !validAppID(app) {
		return errString("cannot derive an app id from the repository")
	}
	ver := strings.TrimPrefix(p.Release.TagName, "v")
	if !validVersion(ver) {
		return errString("invalid release version")
	}
	commit := p.Release.TargetCommitish
	if !validCommit(commit) {
		return errBadSig
	}
	var sumsName, sumsURL string
	type asset struct {
		name, url string
		size      int64
	}
	var assets []asset
	for _, a := range p.Release.Assets {
		low := strings.ToLower(a.Name)
		if low == "sha256sums" || low == "sha256sums.txt" {
			sumsName, sumsURL = a.Name, a.BrowserDownloadURL
			continue
		}
		assets = append(assets, asset{a.Name, a.BrowserDownloadURL, a.Size})
	}
	if sumsURL == "" {
		return errBadSig
	}
	limit := int64(u.h.Cfg.MaxUploadMB) << 20
	if limit <= 0 {
		limit = 64 << 20
	}
	rawSums, err := u.fetch(ctx, sumsURL, 1<<20)
	if err != nil {
		return errBadSig
	}
	sums, err := parseSHA256SUMS(rawSums)
	if err != nil {
		return errBadSig
	}
	byName := map[string]asset{}
	for _, a := range assets {
		byName[a.name] = a
	}
	for name := range sums {
		if name == sumsName {
			continue
		}
		if _, ok := byName[name]; !ok {
			return errBadSig
		}
	}
	var arts []Artifact
	files := map[string][]byte{}
	for _, a := range assets {
		want, ok := sums[a.name]
		if !ok {
			return errBadSig
		}
		b, err := u.fetch(ctx, a.url, limit)
		if err != nil {
			return errBadSig
		}
		if !hmac.Equal([]byte(sha256Hex(b)), []byte(want)) {
			return errBadSig
		}
		files[a.name] = b
		osName, arch, kind := classifyFilename(a.name)
		id := strings.TrimSuffix(strings.ToLower(a.name), "."+kind)
		id = strings.NewReplacer(".", "-", "_", "-").Replace(id)
		if !validArtifactID(id) {
			id = "asset"
		}
		if err := u.saveBlob(app, ver, "github", id, b); err != nil {
			return err
		}
		mirror := strings.TrimRight(base, "/") + "/v1/updates/apps/" + url.PathEscape(app) + "/manifests/" + url.PathEscape(ver) + "/artifacts/" + url.PathEscape(id) + "?source=github"
		arts = append(arts, Artifact{
			ID: id, OS: osName, Arch: arch, Kind: kind, Filename: a.name, URL: a.url,
			Mirrors: []string{mirror}, Size: int64(len(b)), SHA256: want,
		})
	}
	_ = files
	applyDistinctLabels(app, ver, arts)
	channel := "stable"
	if p.Release.Prerelease || strings.Contains(strings.ToLower(p.Release.TagName), "beta") {
		channel = "beta"
	}
	if strings.Contains(strings.ToLower(p.Release.TagName), "security") {
		channel = "security"
	}
	notes := p.Release.Body
	tags := guessTags(notes)
	m := &Manifest{
		Schema: updateManifestSchema, App: app, Version: ver, Channel: channel,
		PublishedAt: time.Now().UTC().Format(time.RFC3339),
		Source: ManifestSource{Kind: "github", GitHub: &GitHubOrigin{
			Repo: repo, Tag: p.Release.TagName, Commit: commit, ReleaseID: p.Release.ID,
		}},
		Outcome:   outcomeFromNotes(tags, notes),
		Requires:  Requires{Restart: true, Migrations: []string{}},
		Artifacts: arts,
	}
	if _, _, err := u.putManifest(m); err != nil {
		return err
	}
	u.emit(UpdateEvent{Type: "update.available", App: app, Version: ver, Source: "github"})
	u.emit(UpdateEvent{Type: "update.analysed", App: app, Version: ver, Source: "github"})
	u.maybeAuto(app, ver, "github", tags, channel)
	return nil
}

func parseSHA256SUMS(b []byte) (map[string]string, error) {
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) < 66 {
			return nil, errors.New("bad SHA256SUMS")
		}
		sum := strings.ToLower(line[:64])
		rest := strings.TrimSpace(line[64:])
		rest = strings.TrimPrefix(rest, "*")
		rest = strings.TrimSpace(rest)
		if !validSHA256(sum) || rest == "" || strings.ContainsAny(rest, "/\\") || strings.Contains(rest, "..") {
			return nil, errors.New("bad SHA256SUMS")
		}
		out[rest] = sum
	}
	if len(out) == 0 {
		return nil, errors.New("empty SHA256SUMS")
	}
	return out, nil
}

func appFromRepo(full string) string {
	full = strings.TrimSpace(full)
	if i := strings.LastIndex(full, "/"); i >= 0 {
		full = full[i+1:]
	}
	var b strings.Builder
	for _, r := range strings.ToLower(full) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	s := b.String()
	for len(s) > 0 && (s[0] < 'a' || s[0] > 'z') && (s[0] < '0' || s[0] > '9') {
		s = s[1:]
	}
	if len(s) > 63 {
		s = s[:63]
	}
	return s
}
