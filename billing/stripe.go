// Package billing sells the RedX Hosted tiers with Stripe Billing: a themed Checkout Session
// (ui_mode=elements, rendered by the console's Payment Element), a signed webhook that keeps each
// Red-XAI Account's plan in step with its Stripe subscription, and the Stripe customer portal.
//
// Keys come only from the environment (STRIPE_SECRET_KEY, STRIPE_PUBLISHABLE_KEY,
// STRIPE_WEBHOOK_SECRET); they are never logged, stored or returned (except the publishable key,
// which is public by design).
package billing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// APIVersion pins the Stripe API version (same as the Rotten Apple store).
const APIVersion = "2026-09-30.endive"

// Stripe is the slice of the Stripe API billing uses. *Client implements it; tests use a fake.
type Stripe interface {
	Do(ctx context.Context, method, path string, form url.Values, idem string, out interface{}) error
}

// Client is a minimal Stripe REST client (form-encoded, pinned version).
type Client struct {
	Base string // default https://api.stripe.com
	key  string
	HTTP *http.Client
}

// NewClient returns a client for a secret key. The key is kept private to the struct.
func NewClient(secret string) *Client {
	return &Client{Base: "https://api.stripe.com", key: secret, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

// Live reports whether the key is a live-mode key.
func (c *Client) Live() bool {
	return strings.HasPrefix(c.key, "sk_live_") || strings.HasPrefix(c.key, "rk_live_")
}

// Error is a Stripe API error (no request data, never the key).
type Error struct {
	Status  int
	Type    string `json:"type"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("stripe %d %s: %s", e.Status, e.Code, redact(e.Message))
}

// keyish matches anything that looks like a Stripe key, including Stripe's own masked echo of a bad
// key ("sk_live_****…abcd"), so no part of a key ever reaches the log.
var keyish = regexp.MustCompile(`(sk|rk|pk|whsec)_[A-Za-z0-9_*$]+`)

func redact(s string) string { return keyish.ReplaceAllString(s, "$1_[redacted]") }

func (c *Client) Do(ctx context.Context, method, path string, form url.Values, idem string, out interface{}) error {
	u := c.Base + path
	var body io.Reader
	if method == "GET" && len(form) > 0 {
		u += "?" + form.Encode()
	} else if len(form) > 0 {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("Stripe-Version", APIVersion)
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if idem != "" {
		req.Header.Set("Idempotency-Key", idem)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return errors.New("stripe request failed")
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error Error `json:"error"`
		}
		_ = json.Unmarshal(b, &e)
		e.Error.Status = resp.StatusCode
		return &e.Error
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}
