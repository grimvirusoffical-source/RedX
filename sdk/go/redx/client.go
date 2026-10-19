// Package redx is the Go client for a RedX host (redxd).
//
//	c, err := redx.New("http://127.0.0.1:7777", os.Getenv("REDX_KEY"), redx.WithDB("game"))
//	err = c.Set(ctx, "players.red-xai.db:Player[ID=1]", map[string]any{"Name": "Ann"}, nil)
//	v, err := c.Get(ctx, "players.red-xai.db:Player[ID=1].Name") // "Ann"
//
// Every operation of the HTTP API (api/redx-api.json) is a method generated in operations_gen.go and can
// also be called by id with Call. Operations whose Danger is DangerDangerous are refused, without sending
// anything, unless Args.Confirm is true. The API key is never part of an error message or of %v output.
package redx

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Danger says how risky an operation is (see api/redx-api.json).
type Danger int

const (
	DangerSafe      Danger = 0 // reads only
	DangerWrite     Danger = 1 // changes data inside the key's own scope
	DangerAdmin     Danger = 2 // changes host or database definitions; reversible
	DangerDangerous Danger = 3 // irreversible, grants or removes access, or moves leadership; needs Confirm
)

func (d Danger) String() string {
	switch d {
	case DangerSafe:
		return "safe"
	case DangerWrite:
		return "write"
	case DangerAdmin:
		return "admin"
	case DangerDangerous:
		return "dangerous"
	}
	return "unknown"
}

// Operation is one row of the operation table.
type Operation struct {
	ID, Group, Method, Path, Shorthand, Auth string
	Danger                                   Danger
	Response, Request, HostConfirm, Summary  string
}

// DangerOf is the danger of an operation id (DangerDangerous for an unknown id, to be safe).
func DangerOf(id string) Danger {
	if op, ok := Operations[id]; ok {
		return op.Danger
	}
	return DangerDangerous
}

// Args are the inputs of one call. Params holds path parameters by name (pack, file, id, ...).
type Args struct {
	DB      string
	Params  map[string]string
	Query   map[string]any
	Body    any    // JSON operations: any value json.Marshal accepts
	Raw     []byte // binary and Box text operations
	Header  http.Header
	Confirm bool // required for DangerDangerous operations
}

func withParams(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// Result is a successful response.
type Result struct {
	Status int
	Header http.Header
	Body   []byte
}

// Decode unmarshals the JSON body into v.
func (r *Result) Decode(v any) error { return json.Unmarshal(r.Body, v) }

// Map is the JSON body as a map (nil if it is not a JSON object).
func (r *Result) Map() map[string]any {
	var m map[string]any
	if json.Unmarshal(r.Body, &m) != nil {
		return nil
	}
	return m
}

// Text is the body as a string (Box text responses).
func (r *Result) Text() string { return string(r.Body) }

// Error is a refused or failed call. Status 0 means the request was not answered (network, timeout) or was
// refused by the client itself (Code "confirm_required").
type Error struct {
	Status     int
	Code       string
	Message    string
	RetryAfter time.Duration
}

func (e *Error) Error() string {
	if e.Status == 0 {
		return "redx: " + e.Message
	}
	return fmt.Sprintf("redx: HTTP %d: %s", e.Status, e.Message)
}

// IsStatus reports whether err is a *Error with that HTTP status.
func IsStatus(err error, status int) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == status
}

// IsNotFound reports a 404.
func IsNotFound(err error) bool { return IsStatus(err, 404) }

var keyShape = regexp.MustCompile(`rx_live_[A-Za-z0-9]+`)

func scrub(s string) string { return keyShape.ReplaceAllString(s, "rx_live_[redacted]") }

var dbName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// Client talks to one host with one key. It is safe for concurrent use.
type Client struct {
	base string
	key  string
	db   string
	hc   *http.Client
	pin  string
}

// Option configures New.
type Option func(*Client) error

// WithDB sets the database (default: the host's default database).
func WithDB(db string) Option {
	return func(c *Client) error {
		if !dbName.MatchString(db) {
			return errors.New("redx: invalid db name")
		}
		c.db = db
		return nil
	}
}

// WithTimeout sets the per-request timeout (default 30 s). Streams are not affected.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) error { c.hc.Timeout = d; return nil }
}

// WithPin trusts exactly the TLS certificate whose SHA-256 (hex, colons allowed) is pin, for a host with a
// self-signed certificate (the fingerprint redx node status and the connect callback show).
func WithPin(pin string) Option {
	return func(c *Client) error {
		c.pin = strings.ToLower(strings.ReplaceAll(pin, ":", ""))
		if len(c.pin) != 64 {
			return errors.New("redx: pin must be a SHA-256 in hex")
		}
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = pinnedTLS(c.pin)
		c.hc.Transport = tr
		return nil
	}
}

// WithHTTPClient replaces the HTTP client (its redirect policy is overridden: redirects are never followed).
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) error { cp := *hc; c.hc = &cp; return nil }
}

func pinnedTLS(pin string) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, // replaced by the pin check
		MinVersion:         tls.VersionTLS12,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no peer certificate")
			}
			sum := sha256.Sum256(raw[0])
			if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(pin)) != 1 {
				return errors.New("peer certificate does not match the pinned fingerprint")
			}
			return nil
		},
	}
}

// New makes a client. key may be empty only for operations whose auth is "none".
func New(baseURL, key string, opts ...Option) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("redx: url must be http(s)://host[:port]")
	}
	c := &Client{base: u.Scheme + "://" + u.Host, key: key, hc: &http.Client{Timeout: 30 * time.Second}}
	for _, o := range opts {
		if err := o(c); err != nil {
			return nil, err
		}
	}
	c.hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c, nil
}

// String never shows the key.
func (c *Client) String() string { return fmt.Sprintf("redx.Client{%s db=%q}", c.base, c.db) }

// GoString never shows the key.
func (c *Client) GoString() string { return c.String() }

// WithDB is a client for another database with the same key and settings.
func (c *Client) WithDB(db string) (*Client, error) {
	if !dbName.MatchString(db) {
		return nil, errors.New("redx: invalid db name")
	}
	cp := *c
	cp.db = db
	return &cp, nil
}

// BaseURL is the host's origin.
func (c *Client) BaseURL() string { return c.base }

func (c *Client) opPath(op Operation, a *Args) (string, error) {
	p := op.Path
	if strings.Contains(p, "{db}") {
		db := a.DB
		if db == "" {
			db = c.db
		}
		if db != "" && !dbName.MatchString(db) {
			return "", errors.New("redx: invalid db name")
		}
		if db == "" && op.Shorthand != "" {
			p = op.Shorthand
		} else {
			if db == "" {
				db = "default"
			}
			p = strings.Replace(p, "{db}", db, 1)
		}
	}
	var err error
	p = paramRe.ReplaceAllStringFunc(p, func(m string) string {
		n := m[1 : len(m)-1]
		v, ok := a.Params[n]
		if !ok || v == "" {
			if n == "folder" {
				return ""
			}
			err = fmt.Errorf("redx: %s needs %s", op.ID, n)
			return ""
		}
		if segmentParams[n] {
			parts := strings.Split(v, "/")
			for i := range parts {
				parts[i] = url.PathEscape(parts[i])
			}
			return strings.Join(parts, "/")
		}
		return url.PathEscape(v)
	})
	return p, err
}

var paramRe = regexp.MustCompile(`\{[a-z][a-z0-9_]*\}`)

func queryString(q map[string]any) string {
	if len(q) == 0 {
		return ""
	}
	v := url.Values{}
	ks := make([]string, 0, len(q))
	for k := range q {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	for _, k := range ks {
		switch x := q[k].(type) {
		case nil:
		case bool:
			if x {
				v.Set(k, "1")
			} else {
				v.Set(k, "0")
			}
		default:
			v.Set(k, fmt.Sprint(x))
		}
	}
	if len(v) == 0 {
		return ""
	}
	return "?" + v.Encode()
}

// Call runs any operation by id.
func (c *Client) Call(ctx context.Context, id string, a Args) (*Result, error) {
	op, ok := Operations[id]
	if !ok {
		return nil, fmt.Errorf("redx: unknown operation %q", id)
	}
	if op.Response == "websocket" {
		return nil, fmt.Errorf("redx: %s is a stream: use Stream", id)
	}
	if op.Danger == DangerDangerous && !a.Confirm {
		return nil, &Error{Code: "confirm_required", Message: fmt.Sprintf("%s is a dangerous operation (%s) and needs Confirm", id, op.Summary)}
	}
	p, err := c.opPath(op, &a)
	if err != nil {
		return nil, err
	}
	q := map[string]any{}
	for k, v := range a.Query {
		q[k] = v
	}
	if op.HostConfirm != "" {
		v := a.Params[op.HostConfirm]
		if op.HostConfirm == "db" {
			v = a.DB
			if v == "" {
				v = c.db
			}
			if v == "" {
				v = "default"
			}
		}
		q["confirm"] = v
	}
	h := http.Header{}
	for k, vs := range a.Header {
		h[k] = vs
	}
	if a.Confirm {
		h.Set("X-RedX-Confirm", id)
	}
	var body io.Reader
	switch op.Request {
	case "json":
		b := a.Body
		if b == nil {
			b = map[string]any{}
		}
		js, err := json.Marshal(b)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(js)
		h.Set("Content-Type", "application/json")
	case "text":
		body = bytes.NewReader(a.Raw)
		h.Set("Content-Type", "text/x-redx-box")
	case "binary":
		if a.Raw == nil {
			return nil, fmt.Errorf("redx: %s needs Raw", id)
		}
		body = bytes.NewReader(a.Raw)
		if h.Get("Content-Type") == "" {
			h.Set("Content-Type", "application/octet-stream")
		}
		if h.Get("X-Redx-SHA256") == "" {
			sum := sha256.Sum256(a.Raw)
			h.Set("X-Redx-SHA256", hex.EncodeToString(sum[:]))
		}
	}
	if op.Response == "text" {
		h.Set("Accept", "text/x-redx-box")
	}
	return c.do(ctx, op.Method, p+queryString(q), body, h, op.Auth != "none")
}

func (c *Client) do(ctx context.Context, method, path string, body io.Reader, h http.Header, auth bool) (*Result, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return nil, &Error{Message: scrub(err.Error())}
	}
	for k, vs := range h {
		req.Header[k] = vs
	}
	if auth && c.key != "" {
		req.Header.Set("Authorization", "Bearer "+c.key)
	}
	res, err := c.hc.Do(req)
	if err != nil {
		return nil, &Error{Message: scrub("request failed: " + err.Error())}
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 1<<31))
	if err != nil {
		return nil, &Error{Message: scrub("reading the response: " + err.Error())}
	}
	if res.StatusCode >= 300 {
		return nil, errorFrom(res.StatusCode, res.Header, b)
	}
	return &Result{Status: res.StatusCode, Header: res.Header, Body: b}, nil
}

func errorFrom(status int, h http.Header, b []byte) *Error {
	e := &Error{Status: status, Message: http.StatusText(status)}
	var j struct{ Error, Code string }
	if json.Unmarshal(b, &j) == nil && j.Error != "" {
		e.Message, e.Code = scrub(j.Error), j.Code
	}
	if ra, err := strconv.Atoi(h.Get("Retry-After")); err == nil {
		e.RetryAfter = time.Duration(ra) * time.Second
	}
	return e
}

// ---- convenience calls (same names in every RedX SDK) ----

// WriteOptions are the TTL options of Set (seconds; zero values are not sent).
type WriteOptions struct {
	TTL        int  // expire after this many seconds
	Sliding    bool // reads extend the TTL
	Checkpoint int  // checkpoint interval in seconds
}

// Get reads the value at path, decoded from Box text into Go values (see FromBox).
func (c *Client) Get(ctx context.Context, path string) (any, error) {
	r, err := c.GetPath(ctx, path, Args{})
	if err != nil {
		return nil, err
	}
	var j struct{ Value *string }
	if err := r.Decode(&j); err != nil || j.Value == nil {
		return nil, &Error{Message: "unexpected response shape"}
	}
	return FromBox(*j.Value)
}

// GetBox reads the value at path as raw Box text.
func (c *Client) GetBox(ctx context.Context, path string) (string, error) {
	r, err := c.GetPathBox(ctx, path, Args{})
	if err != nil {
		return "", err
	}
	return r.Text(), nil
}

// Set writes a JSON-compatible value at path (maps become boxes, nil becomes NELL).
func (c *Client) Set(ctx context.Context, path string, value any, o *WriteOptions) error {
	b := map[string]any{"value": value}
	if o != nil {
		if o.TTL > 0 {
			b["ttl_seconds"] = o.TTL
		}
		if o.Sliding {
			b["sliding"] = true
		}
		if o.Checkpoint > 0 {
			b["checkpoint_seconds"] = o.Checkpoint
		}
	}
	_, err := c.SetPath(ctx, path, Args{Body: b})
	return err
}

// Delete removes the value at path.
func (c *Client) Delete(ctx context.Context, path string) error {
	_, err := c.DeletePath(ctx, path, Args{})
	return err
}

// BxResult is the result of a BoxQL command.
type BxResult struct {
	Kind     string          `json:"kind"`
	Columns  []string        `json:"columns"`
	Rows     [][]any         `json:"rows"` // one slice per row, aligned with Columns
	Count    int             `json:"count"`
	Affected int             `json:"affected"`
	Paths    []string        `json:"paths"`
	Results  []BxResult      `json:"results"`
	Raw      json.RawMessage `json:"-"`
}

// Bx runs one BoxQL command with $params (never concatenate values into the text).
func (c *Client) Bx(ctx context.Context, q string, params map[string]any) (*BxResult, error) {
	if params == nil {
		params = map[string]any{}
	}
	r, err := c.Call(ctx, "bx", Args{Body: map[string]any{"q": q, "params": params}})
	if err != nil {
		return nil, err
	}
	var out BxResult
	if err := r.Decode(&out); err != nil {
		return nil, err
	}
	out.Raw = r.Body
	return &out, nil
}

// Tx runs several BoxQL commands all-or-nothing.
func (c *Client) Tx(ctx context.Context, commands []string, params map[string]any) (*BxResult, error) {
	if len(commands) == 0 {
		return nil, errors.New("redx: Tx needs at least one command")
	}
	return c.Bx(ctx, "{Tx[]} = [\n  "+strings.Join(commands, ",\n  ")+"\n]", params)
}

// UploadFile stores data as file (a slash-separated path) in pack; the host verifies its SHA-256.
func (c *Client) UploadFile(ctx context.Context, pack, file string, data []byte) error {
	_, err := c.PackPut(ctx, pack, file, Args{Raw: data})
	return err
}

// DownloadFile reads a file of a pack. With end < 0 the whole file from start; Range is not sent for 0, -1.
func (c *Client) DownloadFile(ctx context.Context, pack, file string, start, end int64) ([]byte, error) {
	r, err := c.PackGet(ctx, pack, file, Args{Header: rangeHeader(start, end)})
	if err != nil {
		return nil, err
	}
	return r.Body, nil
}

// UploadMedia stores a media item; mediaType (e.g. image/png) is optional.
func (c *Client) UploadMedia(ctx context.Context, lib, name string, data []byte, mediaType string) error {
	a := Args{Raw: data}
	if mediaType != "" {
		a.Query = map[string]any{"type": mediaType}
	}
	_, err := c.MediaPut(ctx, lib, name, a)
	return err
}

// DownloadMedia reads a media item (same range rules as DownloadFile).
func (c *Client) DownloadMedia(ctx context.Context, lib, name string, start, end int64) ([]byte, error) {
	r, err := c.MediaGet(ctx, lib, name, Args{Header: rangeHeader(start, end)})
	if err != nil {
		return nil, err
	}
	return r.Body, nil
}

func rangeHeader(start, end int64) http.Header {
	if start == 0 && end < 0 {
		return nil
	}
	h := http.Header{}
	if end < 0 {
		h.Set("Range", fmt.Sprintf("bytes=%d-", start))
	} else {
		h.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
	}
	return h
}
