// Command cabi is the RedX C ABI: build it with -buildmode=c-shared (see include/redx.h).
package main

/*
#include <stdint.h>
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/grimvirusoffical-source/RedX/sdk/go/redx"
)

const version = "0.2.0-dev"

var (
	mu      sync.Mutex
	nextID  atomic.Int64
	clients = map[int64]*redx.Client{}
	streams = map[int64]*redx.Stream{}
	cver    = C.CString(version)
)

func out(v any) *C.char {
	b, err := json.Marshal(v)
	if err != nil {
		b = []byte(`{"ok":false,"status":0,"error":"cannot encode the result"}`)
	}
	return C.CString(string(b))
}

func fail(err error) map[string]any {
	var e *redx.Error
	if errors.As(err, &e) {
		return map[string]any{"ok": false, "status": e.Status, "code": e.Code, "error": e.Message}
	}
	return map[string]any{"ok": false, "status": 0, "code": "", "error": err.Error()}
}

func setErr(p **C.char, err error) {
	if p != nil {
		*p = out(fail(err))
	}
}

func client(h int64) (*redx.Client, error) {
	mu.Lock()
	defer mu.Unlock()
	c, ok := clients[h]
	if !ok {
		return nil, errors.New("unknown client handle")
	}
	return c, nil
}

//export redx_client_new
func redx_client_new(cfg *C.char, errOut **C.char) C.int64_t {
	var c struct {
		URL, Key, DB, Pin string
		TimeoutMS         int `json:"timeout_ms"`
	}
	if err := json.Unmarshal([]byte(C.GoString(cfg)), &c); err != nil {
		setErr(errOut, errors.New("config is not valid JSON"))
		return 0
	}
	var opts []redx.Option
	if c.DB != "" {
		opts = append(opts, redx.WithDB(c.DB))
	}
	if c.Pin != "" {
		opts = append(opts, redx.WithPin(c.Pin))
	}
	if c.TimeoutMS > 0 {
		opts = append(opts, redx.WithTimeout(time.Duration(c.TimeoutMS)*time.Millisecond))
	}
	cl, err := redx.New(c.URL, c.Key, opts...)
	if err != nil {
		setErr(errOut, err)
		return 0
	}
	id := nextID.Add(1)
	mu.Lock()
	clients[id] = cl
	mu.Unlock()
	return C.int64_t(id)
}

//export redx_client_free
func redx_client_free(h C.int64_t) {
	mu.Lock()
	delete(clients, int64(h))
	mu.Unlock()
}

type cArgs struct {
	DB        string            `json:"db"`
	Params    map[string]string `json:"params"`
	Query     map[string]any    `json:"query"`
	Body      json.RawMessage   `json:"body"`
	RawBase64 string            `json:"raw_base64"`
	Headers   map[string]string `json:"headers"`
	Confirm   bool              `json:"confirm"`
}

func parseArgs(s string) (redx.Args, error) {
	var a cArgs
	if s != "" {
		if err := json.Unmarshal([]byte(s), &a); err != nil {
			return redx.Args{}, errors.New("args are not valid JSON")
		}
	}
	ra := redx.Args{DB: a.DB, Params: a.Params, Query: a.Query, Confirm: a.Confirm}
	if len(a.Body) > 0 {
		ra.Body = a.Body
	}
	if a.RawBase64 != "" {
		b, err := base64.StdEncoding.DecodeString(a.RawBase64)
		if err != nil {
			return redx.Args{}, errors.New("raw_base64 is not base64")
		}
		ra.Raw = b
	}
	if len(a.Headers) > 0 {
		ra.Header = http.Header{}
		for k, v := range a.Headers {
			ra.Header.Set(k, v)
		}
	}
	return ra, nil
}

func result(id string, r *redx.Result) map[string]any {
	m := map[string]any{"ok": true, "status": r.Status}
	op := redx.Operations[id]
	switch op.Response {
	case "binary":
		m["body_base64"] = base64.StdEncoding.EncodeToString(r.Body)
	case "text":
		m["body"] = r.Text()
	default:
		if len(r.Body) == 0 {
			m["body"] = map[string]any{}
		} else {
			m["body"] = json.RawMessage(r.Body)
		}
	}
	return m
}

//export redx_call
func redx_call(h C.int64_t, opID *C.char, args *C.char) *C.char {
	c, err := client(int64(h))
	if err != nil {
		return out(fail(err))
	}
	a, err := parseArgs(C.GoString(args))
	if err != nil {
		return out(fail(err))
	}
	id := C.GoString(opID)
	r, err := c.Call(context.Background(), id, a)
	if err != nil {
		return out(fail(err))
	}
	return out(result(id, r))
}

//export redx_get
func redx_get(h C.int64_t, path *C.char) *C.char {
	c, err := client(int64(h))
	if err != nil {
		return out(fail(err))
	}
	v, err := c.Get(context.Background(), C.GoString(path))
	if err != nil {
		return out(fail(err))
	}
	return out(map[string]any{"ok": true, "status": 200, "body": v})
}

//export redx_set
func redx_set(h C.int64_t, path, value *C.char, ttl C.int32_t) *C.char {
	c, err := client(int64(h))
	if err != nil {
		return out(fail(err))
	}
	var v any
	if err := json.Unmarshal([]byte(C.GoString(value)), &v); err != nil {
		return out(fail(errors.New("value is not valid JSON")))
	}
	var o *redx.WriteOptions
	if ttl > 0 {
		o = &redx.WriteOptions{TTL: int(ttl)}
	}
	if err := c.Set(context.Background(), C.GoString(path), v, o); err != nil {
		return out(fail(err))
	}
	return out(map[string]any{"ok": true, "status": 200, "body": map[string]any{}})
}

//export redx_bx
func redx_bx(h C.int64_t, q, params *C.char) *C.char {
	c, err := client(int64(h))
	if err != nil {
		return out(fail(err))
	}
	p := map[string]any{}
	if s := C.GoString(params); s != "" {
		if err := json.Unmarshal([]byte(s), &p); err != nil {
			return out(fail(errors.New("params are not a JSON object")))
		}
	}
	r, err := c.Bx(context.Background(), C.GoString(q), p)
	if err != nil {
		return out(fail(err))
	}
	return out(map[string]any{"ok": true, "status": 200, "body": r.Raw})
}

//export redx_stream_open
func redx_stream_open(h C.int64_t, opID, args *C.char, reconnect C.int32_t, errOut **C.char) C.int64_t {
	c, err := client(int64(h))
	if err != nil {
		setErr(errOut, err)
		return 0
	}
	a, err := parseArgs(C.GoString(args))
	if err != nil {
		setErr(errOut, err)
		return 0
	}
	s, err := c.Stream(context.Background(), C.GoString(opID), a, &redx.StreamOptions{Reconnect: reconnect != 0})
	if err != nil {
		setErr(errOut, err)
		return 0
	}
	id := nextID.Add(1)
	mu.Lock()
	streams[id] = s
	mu.Unlock()
	return C.int64_t(id)
}

//export redx_stream_next
func redx_stream_next(h C.int64_t, timeoutMS C.int32_t) *C.char {
	mu.Lock()
	s, ok := streams[int64(h)]
	mu.Unlock()
	if !ok {
		return out(map[string]any{"ok": false, "closed": true, "error": "unknown stream handle"})
	}
	t := time.NewTimer(time.Duration(timeoutMS) * time.Millisecond)
	defer t.Stop()
	select {
	case ev, open := <-s.C:
		if !open {
			msg := "stream closed"
			if err := s.Err(); err != nil {
				msg = err.Error()
			}
			return out(map[string]any{"ok": false, "closed": true, "error": msg})
		}
		return out(map[string]any{"ok": true, "event": map[string]any{"path": ev.Path, "op": ev.Op, "value": ev.Value, "at": ev.At, "data": ev.Data}})
	case <-t.C:
		return out(map[string]any{"ok": true, "timeout": true})
	}
}

//export redx_stream_close
func redx_stream_close(h C.int64_t) {
	mu.Lock()
	s, ok := streams[int64(h)]
	delete(streams, int64(h))
	mu.Unlock()
	if ok {
		s.Close()
	}
}

//export redx_danger_level
func redx_danger_level(opID *C.char) C.int32_t { return C.int32_t(redx.DangerOf(C.GoString(opID))) }

//export redx_version
func redx_version() *C.char { return cver }

//export redx_free
func redx_free(p *C.char) { C.free(unsafe.Pointer(p)) }

func main() {}
