package redx

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Event is one change delivered by Subscribe or Watch. Value is Box text; Data its decoded form.
type Event struct {
	Path  string          `json:"path"`
	Op    string          `json:"op"`
	Value string          `json:"value"`
	At    string          `json:"at"`
	Topic string          `json:"topic,omitempty"`
	Raw   json.RawMessage `json:"-"`
	Data  any             `json:"-"`
}

// StreamOptions control a stream. With Reconnect, an unexpected close is followed by reconnects with
// exponential backoff (MinBackoff..MaxBackoff, jittered); events that happened while disconnected are not
// replayed, so re-read what you need in OnReconnect. A refusal (400/401/403/404) ends the stream.
type StreamOptions struct {
	Reconnect   bool
	MinBackoff  time.Duration // default 250 ms
	MaxBackoff  time.Duration // default 10 s
	OnReconnect func()
	OnError     func(error)
}

// Stream is an open subscription. Events arrive on C, which is closed when the stream ends.
type Stream struct {
	C      <-chan Event
	cancel context.CancelFunc
	done   chan struct{}
	mu     sync.Mutex
	err    error
}

// Close ends the stream and waits until C is closed.
func (s *Stream) Close() { s.cancel(); <-s.done }

// Err is why the stream ended (nil after Close).
func (s *Stream) Err() error { s.mu.Lock(); defer s.mu.Unlock(); return s.err }

// Subscribe streams changes matching a path pattern such as "players.red-xai.db:Player[ID=*]".
func (c *Client) Subscribe(ctx context.Context, pattern string, o *StreamOptions) (*Stream, error) {
	return c.Stream(ctx, "subscribe", Args{Query: map[string]any{"path": pattern}}, o)
}

// Watch streams the changes a BoxQL {Watch[]} command matches.
func (c *Client) Watch(ctx context.Context, q string, params map[string]any, o *StreamOptions) (*Stream, error) {
	qa := map[string]any{"q": q}
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return nil, err
		}
		qa["params"] = string(b)
	}
	return c.Stream(ctx, "bxWatch", Args{Query: qa}, o)
}

// Stream opens any WebSocket operation (subscribe, bxWatch, rulesSubscribe) by id.
func (c *Client) Stream(ctx context.Context, id string, a Args, o *StreamOptions) (*Stream, error) {
	op, ok := Operations[id]
	if !ok || op.Response != "websocket" {
		return nil, errors.New("redx: " + id + " is not a stream operation")
	}
	if o == nil {
		o = &StreamOptions{}
	}
	p, err := c.opPath(op, &a)
	if err != nil {
		return nil, err
	}
	u := "ws" + strings.TrimPrefix(c.base, "http") + p + queryString(a.Query)
	conn, err := c.dial(ctx, u)
	if err != nil {
		return nil, err
	}
	sctx, cancel := context.WithCancel(context.Background())
	ch := make(chan Event, 64)
	s := &Stream{C: ch, cancel: cancel, done: make(chan struct{})}
	go s.run(sctx, c, u, conn, ch, o)
	return s, nil
}

func (c *Client) dial(ctx context.Context, u string) (*websocket.Conn, error) {
	d := websocket.Dialer{HandshakeTimeout: 15 * time.Second, Proxy: http.ProxyFromEnvironment}
	if c.pin != "" {
		d.TLSClientConfig = pinnedTLS(c.pin)
	}
	h := http.Header{}
	if c.key != "" {
		h.Set("Authorization", "Bearer "+c.key)
	}
	conn, res, err := d.DialContext(ctx, u, h)
	if err != nil {
		if res != nil {
			b := make([]byte, 4096)
			n, _ := res.Body.Read(b)
			res.Body.Close()
			return nil, errorFrom(res.StatusCode, res.Header, b[:n])
		}
		return nil, &Error{Message: scrub("stream: " + err.Error())}
	}
	return conn, nil
}

func (s *Stream) run(ctx context.Context, c *Client, u string, conn *websocket.Conn, ch chan Event, o *StreamOptions) {
	defer close(s.done)
	defer close(ch)
	minB, maxB := o.MinBackoff, o.MaxBackoff
	if minB <= 0 {
		minB = 250 * time.Millisecond
	}
	if maxB <= 0 {
		maxB = 10 * time.Second
	}
	setErr := func(err error) {
		s.mu.Lock()
		s.err = err
		s.mu.Unlock()
		if o.OnError != nil && err != nil {
			o.OnError(err)
		}
	}
	for {
		stop := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(1000, "bye"), time.Now().Add(time.Second))
				conn.Close()
			case <-stop:
			}
		}()
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				break
			}
			var ev Event
			if json.Unmarshal(msg, &ev) != nil {
				continue
			}
			ev.Raw = append(json.RawMessage(nil), msg...)
			if ev.Op == "set" && ev.Value != "" {
				ev.Data, _ = FromBox(ev.Value)
			}
			select {
			case ch <- ev:
			case <-ctx.Done():
			}
		}
		close(stop)
		conn.Close()
		if ctx.Err() != nil {
			return
		}
		if !o.Reconnect {
			setErr(&Error{Message: "stream closed by the host"})
			return
		}
		delay := minB
		for {
			t := time.NewTimer(delay/2 + time.Duration(rand.Int63n(int64(delay/2)+1)))
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
			delay *= 2
			if delay > maxB {
				delay = maxB
			}
			nc, err := c.dial(ctx, u)
			if err != nil {
				var e *Error
				if errors.As(err, &e) && (e.Status == 400 || e.Status == 401 || e.Status == 403 || e.Status == 404) {
					setErr(err)
					return
				}
				continue
			}
			conn = nc
			if o.OnReconnect != nil {
				o.OnReconnect()
			}
			break
		}
	}
}
