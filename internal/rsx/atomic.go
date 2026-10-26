package rsx

import (
	"errors"
	"os"
	"path/filepath"
)

// atomicOut writes to <final>.partial (O_EXCL, 0600) and publishes with a no-replace
// link, like librsx's AtomicOut. The final path is never replaced.
type atomicOut struct {
	f              *os.File
	final, partial string
}

func atomicOpen(final string) (*atomicOut, error) {
	if _, err := os.Lstat(final); err == nil {
		return nil, ErrExists
	}
	partial := final + ".partial"
	if fi, err := os.Lstat(partial); err == nil {
		if !fi.Mode().IsRegular() {
			return nil, ErrIO
		}
		secureRemove(partial)
	}
	f, err := os.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, ErrIO
	}
	return &atomicOut{f: f, final: final, partial: partial}, nil
}

func (a *atomicOut) Write(p []byte) (int, error) {
	n, err := a.f.Write(p)
	if err != nil {
		return n, ErrIO
	}
	return n, nil
}

func (a *atomicOut) commit() error {
	if err := a.f.Sync(); err != nil {
		a.abort()
		return ErrIO
	}
	if err := a.f.Close(); err != nil {
		os.Remove(a.partial)
		return ErrIO
	}
	if err := os.Link(a.partial, a.final); err != nil {
		os.Remove(a.partial)
		if errors.Is(err, os.ErrExist) {
			return ErrExists
		}
		return ErrIO
	}
	os.Remove(a.partial)
	syncDir(filepath.Dir(a.final))
	return nil
}

func (a *atomicOut) abort() {
	a.f.Close()
	secureRemove(a.partial)
}

// secureRemove overwrites a regular file with zeros before unlinking it (best effort).
func secureRemove(p string) {
	if f, err := os.OpenFile(p, os.O_WRONLY, 0); err == nil {
		if fi, err := f.Stat(); err == nil && fi.Mode().IsRegular() {
			z := make([]byte, 64*1024)
			for left := fi.Size(); left > 0; {
				n := int64(len(z))
				if left < n {
					n = left
				}
				f.Write(z[:n])
				left -= n
			}
			f.Sync()
		}
		f.Close()
	}
	os.Remove(p)
}

func syncDir(d string) {
	if f, err := os.Open(d); err == nil {
		f.Sync()
		f.Close()
	}
}

// atomicWrite replaces path via path.tmp -> fsync -> rename -> fsync(dir) (keymap files).
func atomicWrite(path string, data []byte) error {
	tmp := path + ".tmp"
	os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrIO
	}
	_, werr := f.Write(data)
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil || serr != nil || cerr != nil || os.Rename(tmp, path) != nil {
		os.Remove(tmp)
		return ErrIO
	}
	syncDir(filepath.Dir(path))
	return nil
}
