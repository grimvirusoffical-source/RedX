package redx

import (
	"context"
	"encoding/base64"
	"errors"
	"github.com/grimvirusoffical-source/RedX/sdk/go/internal/rsx"
	"net/url"
)

// ConnectRequest is the app side's secret material for one connect handshake. Keep State and Verifier
// private until the exchange; only Challenge goes into the link.
type ConnectRequest struct {
	State, Verifier, Challenge string
}

// NewConnectRequest makes a fresh state (192 bits) and PKCE S256 pair.
func NewConnectRequest() (ConnectRequest, error) {
	b := make([]byte, 56)
	if err := rsx.Random(b); err != nil {
		return ConnectRequest{}, err
	}
	enc := base64.RawURLEncoding
	v := enc.EncodeToString(b[:32])
	sum := rsx.Sha256([]byte(v))
	return ConnectRequest{State: enc.EncodeToString(b[32:]), Verifier: v, Challenge: enc.EncodeToString(sum[:])}, nil
}

// LinkOptions are the optional link parameters (docs/connect.md section 2).
type LinkOptions struct {
	App, Workspace, Scope, Prefix, Label, Callback, Host, Pin, Name string
	ConsoleURL                                                      string // "" gives redx://connect?...
}

// ConnectLink is the link the owner opens to approve the app.
func ConnectLink(provider string, rq ConnectRequest, o LinkOptions) (string, error) {
	if provider == "" || rq.State == "" || rq.Challenge == "" {
		return "", errors.New("redx: ConnectLink needs provider, state and challenge")
	}
	q := url.Values{"v": {"1"}, "provider": {provider}, "state": {rq.State}, "pkce_challenge": {rq.Challenge}, "pkce_method": {"S256"}}
	for k, v := range map[string]string{"app": o.App, "workspace": o.Workspace, "scope": o.Scope, "prefix": o.Prefix, "label": o.Label,
		"callback": o.Callback, "host": o.Host, "pin": o.Pin, "name": o.Name} {
		if v != "" {
			q.Set(k, v)
		}
	}
	if o.ConsoleURL != "" {
		u, err := url.Parse(o.ConsoleURL)
		if err != nil || u.Host == "" {
			return "", errors.New("redx: bad console URL")
		}
		return u.Scheme + "://" + u.Host + "/#/connect?" + q.Encode(), nil
	}
	return "redx://connect?" + q.Encode(), nil
}

// Callback is what the console sends back to the app.
type Callback struct{ Code, State, Host, Pin string }

// ParseCallback reads the callback URL and checks its state against the expected one (constant time).
func ParseCallback(raw, expectedState string) (Callback, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Callback{}, &Error{Code: "bad_callback", Message: "bad callback URL"}
	}
	q := u.Query()
	cb := Callback{Code: q.Get("code"), State: q.Get("state"), Host: q.Get("host"), Pin: q.Get("pin")}
	if cb.Code == "" {
		return Callback{}, &Error{Code: "bad_callback", Message: "callback carries no code"}
	}
	if len(cb.State) != len(expectedState) || !rsx.CtEq([]byte(cb.State), []byte(expectedState)) {
		return Callback{}, &Error{Code: "state_mismatch", Message: "callback state does not match"}
	}
	return cb, nil
}

// ExchangeConnectCode trades the approved code plus the verifier for the app's key (returned once). The
// client may have an empty key; nothing secret of the client is sent.
func (c *Client) ExchangeConnectCode(ctx context.Context, code string, rq ConnectRequest, deviceLabel string) (map[string]any, error) {
	b := map[string]any{"code": code, "pkce_verifier": rq.Verifier, "state": rq.State}
	if deviceLabel != "" {
		b["device_label"] = deviceLabel
	}
	r, err := c.ConnectExchange(ctx, Args{Body: b})
	if err != nil {
		return nil, err
	}
	return r.Map(), nil
}
