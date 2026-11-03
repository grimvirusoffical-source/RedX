package host

import (
	"bytes"
	"regexp"
	"testing"
	"testing/fstest"
)

func TestUIAssetRevisionCoversEveryEmbeddedPathAndContent(t *testing.T) {
	fixture := fstest.MapFS{
		"ui/index.html":                {Data: []byte(`<script src="/ui/js/main.js"></script>`)},
		"ui/js/main.js":                {Data: []byte(`import './pages/auth.js';`)},
		"ui/js/pages/auth.js":          {Data: []byte(`export const page = 'account';`)},
		"ui/js/website-session.js":     {Data: []byte(`export const mode = 'website';`)},
		"ui/css/app.css":               {Data: []byte(`body { color: red; }`)},
		"ui/icons/fixture.png":         {Data: []byte{0, 1, 2, 255}},
		"ui/docs/nested/fixture.txt":   {Data: []byte("embedded documentation")},
		"ui/docs/nested/empty-fixture": {Data: []byte{}},
	}
	assets, revision, err := loadUIAssets(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(revision) || len(assets) != len(fixture) {
		t.Fatalf("incomplete bundle: revision %q, files %d", revision, len(assets))
	}
	clone := func() fstest.MapFS {
		out := fstest.MapFS{}
		for name, file := range fixture {
			copy := *file
			copy.Data = bytes.Clone(file.Data)
			out[name] = &copy
		}
		return out
	}
	for name, file := range fixture {
		if got := assets[name[len("ui/"):]].data; !bytes.Equal(got, file.Data) {
			t.Fatalf("embedded bytes changed for %s", name)
		}
		t.Run(name, func(t *testing.T) {
			changed := clone()
			changed[name].Data = append(changed[name].Data, '!')
			_, next, err := loadUIAssets(changed)
			if err != nil || next == revision {
				t.Fatalf("content change did not version %s: %q, %v", name, next, err)
			}
			changed = clone()
			changed[name+".renamed"] = changed[name]
			delete(changed, name)
			_, next, err = loadUIAssets(changed)
			if err != nil || next == revision {
				t.Fatalf("path change did not version %s: %q, %v", name, next, err)
			}
			changed = clone()
			delete(changed, name)
			_, next, err = loadUIAssets(changed)
			if err != nil || next == revision {
				t.Fatalf("file removal did not version %s: %q, %v", name, next, err)
			}
		})
	}
	// Map insertion/iteration order must never become a deployment revision.
	for i := 0; i < 5; i++ {
		_, repeated, err := loadUIAssets(clone())
		if err != nil || repeated != revision {
			t.Fatalf("bundle revision is unstable: %q != %q (%v)", repeated, revision, err)
		}
	}
	_, embeddedRevision, err := loadUIAssets(uiFS)
	if err != nil || embeddedRevision != uiRevision {
		t.Fatalf("binary revision differs from its embedded files: %q != %q (%v)", embeddedRevision, uiRevision, err)
	}
}

func TestUIAssetRevisionRejectsUnreadableBundle(t *testing.T) {
	if _, _, err := loadUIAssets(fstest.MapFS{}); err == nil {
		t.Fatal("missing embedded ui tree must not silently produce a revision")
	}
}
