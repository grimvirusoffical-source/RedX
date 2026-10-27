package host_test

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"redx/host"
)

func asset(t *testing.T, name string) string {
	t.Helper()
	b, ok := host.UIAsset(name)
	if !ok {
		t.Fatalf("asset %s missing", name)
	}
	return string(b)
}

// The console is dark by default and never flashes the wrong theme: an external (CSP-friendly) classic script in <head>
// sets data-theme before the stylesheet loads, and the service worker caches it for offline use.
func TestThemeNoFlashAndDarkDefault(t *testing.T) {
	idx := asset(t, "index.html")
	if !strings.Contains(idx, `data-theme="dark"`) {
		t.Fatal("index.html must default to the dark theme")
	}
	// The original root console retains absolute /ui assets. The Hub
	// produces a separately namespaced variant without changing this order.
	si, ci := strings.Index(idx, "/ui/js/theme-init.js"), strings.Index(idx, "/ui/css/app.css")
	if si < 0 || ci < 0 || si > ci {
		t.Fatal("theme-init.js must be loaded in <head> before the stylesheet")
	}
	if regexp.MustCompile(`(?i)<script(\s[^>]*)?>\s*[^<\s]`).MatchString(idx) || strings.Contains(idx, "<style") {
		t.Fatal("inline script/style would be blocked by the CSP")
	}
	init := asset(t, "js/theme-init.js")
	for _, want := range []string{"redx.theme", "'system'", "prefers-color-scheme", "data-theme", "theme-color"} {
		if !strings.Contains(init, want) {
			t.Errorf("theme-init.js lacks %q", want)
		}
	}
	if !strings.Contains(asset(t, "sw.js"), "/ui/js/theme-init.js") {
		t.Error("service worker shell must cache theme-init.js")
	}
	if !strings.Contains(asset(t, "manifest.webmanifest"), `"theme_color": "#0f0809"`) {
		t.Error("manifest theme_color must be the dark background")
	}
	st := asset(t, "js/state.js")
	if !strings.Contains(st, "normTheme") || !strings.Contains(asset(t, "js/main.js"), "radiogroup") {
		t.Error("state.js/main.js must provide the Dark / System / Light switcher")
	}
}

func lum(hex string) float64 {
	v, _ := strconv.ParseUint(strings.TrimPrefix(hex, "#"), 16, 32)
	ch := func(c uint64) float64 {
		x := float64(c) / 255
		if x <= 0.03928 {
			return x / 12.92
		}
		return math.Pow((x+0.055)/1.055, 2.4)
	}
	return 0.2126*ch(v>>16&255) + 0.7152*ch(v>>8&255) + 0.0722*ch(v&255)
}

func ratio(a, b string) float64 {
	x, y := lum(a), lum(b)
	if x < y {
		x, y = y, x
	}
	return (x + .05) / (y + .05)
}

// Every text colour must meet WCAG AA (4.5:1) on the backgrounds it is drawn on, in both themes.
func TestThemeContrastAA(t *testing.T) {
	css := asset(t, "css/app.css")
	tok := func(block, name string) string {
		m := regexp.MustCompile(`--` + name + `:\s*(#[0-9a-fA-F]{6})`).FindStringSubmatch(block)
		if m == nil {
			t.Fatalf("token --%s not found", name)
		}
		return m[1]
	}
	li := strings.Index(css, "\n[data-theme=light] {")
	if li < 0 {
		t.Fatal("no light theme block")
	}
	blocks := map[string]string{"dark": css[:li], "light": css[li:]}
	for theme, b := range blocks {
		for _, fg := range []string{"fg", "muted", "dim", "accent", "accent2", "ok", "warn", "err", "info"} {
			for _, bg := range []string{"bg", "bg2", "panel", "panel2"} {
				if r := ratio(tok(b, fg), tok(b, bg)); r < 4.5 {
					t.Errorf("%s: --%s on --%s is %.2f:1 (< 4.5)", theme, fg, bg, r)
				}
			}
		}
		for _, m := range regexp.MustCompile(`--(tk-[a-z]+):\s*(#[0-9a-fA-F]{6})`).FindAllStringSubmatch(b, -1) {
			for _, bg := range []string{"bg", "bg2", "panel", "panel2"} {
				if r := ratio(m[2], tok(b, bg)); r < 4.5 {
					t.Errorf("%s: syntax colour --%s on --%s is %.2f:1 (< 4.5)", theme, m[1], bg, r)
				}
			}
		}
		if r := ratio("#ffffff", tok(b, "btn")); r < 4.5 {
			t.Errorf("%s: white on --btn is %.2f:1 (< 4.5)", theme, r)
		}
	}
}
