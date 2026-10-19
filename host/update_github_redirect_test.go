package host

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestArtifactRedirectAllowsGitHubCDN(t *testing.T) {
	u := &updater{h: &Host{Cfg: Config{GithubRepos: []string{"acme/redx=redx"}, HostedApps: []string{"redx"}}}}
	initial := "https://github.com/acme/redx/releases/download/v1.2.3/SHA256SUMS"
	if err := u.allowArtifact(initial); err != nil {
		t.Fatal(err)
	}
	cdn := "https://release-assets.githubusercontent.com/github-production-release-asset/123?response-content-type=application%2Foctet-stream&token=abc"
	if err := u.allowArtifact(cdn); err == nil {
		t.Fatal("cdn host accepted as the initial url")
	}
	if err := u.allowArtifact(initial + "?sig=1"); err == nil {
		t.Fatal("query on the initial url")
	}
	if err := u.allowArtifactRedirect(cdn); err != nil {
		t.Fatal(err)
	}
	obj := "https://objects.githubusercontent.com/github-production-release-asset-2e65be/1?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=ab"
	if err := u.allowArtifactRedirect(obj); err != nil {
		t.Fatal(err)
	}
	refused := []string{
		"http://release-assets.githubusercontent.com/a",
		"https://release-assets.githubusercontent.com:444/a",
		"https://user:pw@release-assets.githubusercontent.com/a",
		"https://release-assets.githubusercontent.com/a#frag",
		"https://evil.example/a",
		"https://release-assets.githubusercontent.com.evil.com/a",
		"https://objects.githubusercontent.com/../secret",
		"https://objects.githubusercontent.com/foo/%2e%2e/secret",
		initial,
	}
	for _, raw := range refused {
		if err := u.allowArtifactRedirect(raw); err == nil {
			t.Fatalf("accepted redirect %s", raw)
		}
	}
	c := u.httpClient()
	next, err := http.NewRequest(http.MethodGet, cdn, nil)
	if err != nil {
		t.Fatal(err)
	}
	first, err := http.NewRequest(http.MethodGet, initial, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.CheckRedirect(next, []*http.Request{first}); err != nil {
		t.Fatal(err)
	}
	via := []*http.Request{first, first, first, first}
	if err := c.CheckRedirect(next, via); err == nil {
		t.Fatal("fourth redirect was allowed")
	}
}

func TestFetchFollowsGitHubCDNRedirect(t *testing.T) {
	const cdn = "https://release-assets.githubusercontent.com/asset/SHA256SUMS?sig=1&x=y"
	body := []byte("signed-artifact-bytes")
	var sawQuery string
	u := &updater{
		h:             &Host{Cfg: Config{GithubRepos: []string{"acme/redx=redx"}}},
		allowLoopback: true,
		artifactTransport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Host == "release-assets.githubusercontent.com" {
				sawQuery = r.URL.RawQuery
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(bytes.NewReader(body)),
					Request:    r,
				}, nil
			}
			hdr := make(http.Header)
			hdr.Set("Location", cdn)
			return &http.Response{
				StatusCode: http.StatusFound,
				Header:     hdr,
				Body:       io.NopCloser(bytes.NewReader(nil)),
				Request:    r,
			}, nil
		}),
	}
	raw := "http://127.0.0.1:9/acme/redx/releases/download/v1.2.3/SHA256SUMS"
	got, err := u.fetch(context.Background(), raw, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("body %q", got)
	}
	if !strings.Contains(sawQuery, "sig=1") {
		t.Fatalf("query %q", sawQuery)
	}
	if sha256Hex(got) == "" {
		t.Fatal("sha256")
	}

	u.artifactTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		hdr := make(http.Header)
		hdr.Set("Location", "https://evil.example/payload")
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     hdr,
			Body:       io.NopCloser(bytes.NewReader(nil)),
			Request:    r,
		}, nil
	})
	if _, err := u.fetch(context.Background(), raw, 1<<20); err == nil || !strings.Contains(err.Error(), "refused artifact url") {
		t.Fatalf("evil redirect: %v", err)
	}
}
