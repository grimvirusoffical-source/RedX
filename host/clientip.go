package host

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
)

// clientIPKey stores the address rate limits and audit logs must use.
// It is set once, at the edge of routes, from trusted-proxy rules.
type clientIPKey struct{}

// meterKey carries the authenticated principal and request-body size so the
// response can be added to the hosted traffic counter after the handler returns.
type meterKey struct{}

type reqMeter struct {
	pr  *Principal
	req int64
}

// clientIP is the address of the caller.
// X-Forwarded-For and X-Real-IP are read only when the direct socket peer is
// listed in trusted_proxies. The client is then the rightmost untrusted hop
// in X-Forwarded-For, or X-Real-IP when that header is the only one set.
// Any other peer is the client itself: a spoofed forwarding header is ignored.
func (h *Host) clientIP(r *http.Request) string {
	peer := socketIP(r)
	if h == nil || !ipTrusted(peer, h.Cfg.TrustedProxies) {
		return peer
	}
	if ip := rightmostUntrusted(r.Header.Get("X-Forwarded-For"), h.Cfg.TrustedProxies); ip != "" {
		return ip
	}
	if ip := ipToken(r.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}
	return peer
}

func socketIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// remoteIP is the client address for audit logs and rate limits.
// Handlers reached through routes see the trusted-proxy result; anything else
// sees the socket peer.
func remoteIP(r *http.Request) string {
	if r != nil {
		if v, ok := r.Context().Value(clientIPKey{}).(string); ok && v != "" {
			return v
		}
	}
	return socketIP(r)
}

func ipTrusted(addr string, trusted []string) bool {
	ip := net.ParseIP(addr)
	if ip == nil || len(trusted) == 0 {
		return false
	}
	for _, t := range trusted {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if strings.Contains(t, "/") {
			_, n, err := net.ParseCIDR(t)
			if err == nil && n.Contains(ip) {
				return true
			}
			continue
		}
		tip := net.ParseIP(t)
		if tip != nil && tip.Equal(ip) {
			return true
		}
	}
	return false
}

// rightmostUntrusted walks X-Forwarded-For from the right and returns the
// first address that is not a trusted proxy. Trusted hops on the right are
// this proxy's own parents and are skipped. An empty result means every
// listed hop is trusted (or the header is empty).
func rightmostUntrusted(xff string, trusted []string) string {
	if strings.TrimSpace(xff) == "" {
		return ""
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := ipToken(parts[i])
		if ip == "" {
			continue
		}
		if !ipTrusted(ip, trusted) {
			return ip
		}
	}
	return ""
}

// ipToken parses one forwarding-header token into a canonical IP string.
func ipToken(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, `"`)
	if s == "" || strings.EqualFold(s, "unknown") {
		return ""
	}
	if strings.HasPrefix(s, "[") {
		if i := strings.Index(s, "]"); i > 1 {
			s = s[1:i]
		}
	} else if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	return ip.String()
}

func (h *Host) stampClient(r *http.Request, meter *reqMeter) *http.Request {
	ctx := r.Context()
	ctx = context.WithValue(ctx, clientIPKey{}, h.clientIP(r))
	if meter != nil {
		ctx = context.WithValue(ctx, meterKey{}, meter)
	}
	return r.WithContext(ctx)
}

func (h *Host) notePrincipal(r *http.Request, pr *Principal) {
	if r == nil || pr == nil {
		return
	}
	if m, ok := r.Context().Value(meterKey{}).(*reqMeter); ok && m != nil {
		m.pr = pr
	}
}

type countRC struct {
	io.ReadCloser
	m *reqMeter
}

func (c *countRC) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	if c.m != nil && n > 0 {
		c.m.req += int64(n)
	}
	return n, err
}
