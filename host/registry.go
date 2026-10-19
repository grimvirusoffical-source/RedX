package host

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"
)

// ErrNoDB is returned for unknown database names.
var ErrNoDB = errors.New("database not found")

// ErrDBExists is returned when creating a database that already exists.
var ErrDBExists = errors.New("database already exists")

// Registry manages the named databases under <data>/dbs/<name>/.
type Registry struct {
	root     string
	opener   Opener
	follower func() bool
	onOpen   func(name string, b Backend)
	mu       sync.RWMutex
	open     map[string]Backend
}

// NewRegistry creates the dbs directory if needed.
// follower (may be nil) reports whether databases must open in follower mode;
// onOpen (may be nil) is called for each newly opened database.
func NewRegistry(dataDir string, op Opener, follower func() bool, onOpen func(string, Backend)) (*Registry, error) {
	r := &Registry{root: filepath.Join(dataDir, "dbs"), opener: op, follower: follower, onOpen: onOpen, open: map[string]Backend{}}
	return r, os.MkdirAll(r.root, 0o700)
}

// Root returns the dbs directory.
func (r *Registry) Root() string { return r.root }

// Exists reports whether the database directory exists.
func (r *Registry) Exists(name string) bool {
	if !ValidDBName(name) {
		return false
	}
	st, err := os.Stat(filepath.Join(r.root, name))
	return err == nil && st.IsDir()
}

// Get returns the open database, opening it lazily.
func (r *Registry) Get(name string) (Backend, error) {
	if !ValidDBName(name) {
		return nil, fmt.Errorf("%w: invalid name", ErrNoDB)
	}
	r.mu.RLock()
	b := r.open[name]
	r.mu.RUnlock()
	if b != nil {
		return b, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if b = r.open[name]; b != nil {
		return b, nil
	}
	// Checked under the write lock so a concurrent SwapRoot can neither make the
	// directory look missing mid-swap nor let us cache a handle on the old tree.
	if !r.Exists(name) {
		return nil, ErrNoDB
	}
	b, err := r.openLocked(name)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (r *Registry) openLocked(name string) (Backend, error) {
	fol := r.follower != nil && r.follower()
	b, err := r.opener(filepath.Join(r.root, name), fol)
	if err != nil {
		return nil, err
	}
	if r.onOpen != nil {
		r.onOpen(name, b)
	}
	r.open[name] = b
	return b, nil
}

// Each calls fn for every currently open database.
func (r *Registry) Each(fn func(name string, b Backend)) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for n, b := range r.open {
		fn(n, b)
	}
}

// Create makes a new database (error if it exists).
func (r *Registry) Create(name string) error {
	if !ValidDBName(name) {
		return fmt.Errorf("%w: database names are [a-z0-9][a-z0-9_-]{0,62}", ErrInvalid)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	d := filepath.Join(r.root, name)
	if _, err := os.Stat(d); err == nil {
		return ErrDBExists
	}
	if err := os.MkdirAll(d, 0o700); err != nil {
		return err
	}
	if _, err := r.openLocked(name); err != nil {
		os.RemoveAll(d)
		return err
	}
	return nil
}

// Ensure creates the database if it does not exist (idempotent; replication path).
func (r *Registry) Ensure(name string) error {
	if r.Exists(name) {
		return nil
	}
	if err := r.Create(name); err != nil && !errors.Is(err, ErrDBExists) {
		return err
	}
	return nil
}

// List returns database names.
func (r *Registry) List() []string {
	ents, _ := os.ReadDir(r.root)
	var out []string
	for _, e := range ents {
		if e.IsDir() && ValidDBName(e.Name()) {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// CloseOne closes one database and drops the cached handle so the next Get reopens it.
func (r *Registry) CloseOne(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	b := r.open[name]
	if b == nil {
		return nil
	}
	err := b.Close()
	delete(r.open, name)
	return err
}

// CloseAll closes every open database.
func (r *Registry) CloseAll() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var first error
	for n, b := range r.open {
		if err := b.Close(); err != nil && first == nil {
			first = err
		}
		delete(r.open, n)
	}
	return first
}

// SwapRoot atomically replaces the whole dbs directory with newRoot (a directory on
// the same volume, e.g. an extracted snapshot). Every open database is closed and
// the old tree is moved aside and deleted, all while holding the registry lock, so
// no concurrent Get can reopen (and cache) a database from the old tree in between.
// On failure the old tree is put back.
func (r *Registry) SwapRoot(newRoot string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for n, b := range r.open {
		// A close error is not fatal here: the handle is dropped either way, and a
		// backend that failed to close cleanly must not keep serving pre-snapshot state.
		_ = b.Close()
		delete(r.open, n)
	}
	old := r.root + ".old-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if err := os.Rename(r.root, old); err != nil {
		return fmt.Errorf("swap dbs: move old tree aside: %w", err)
	}
	if err := os.Rename(newRoot, r.root); err != nil {
		if rerr := os.Rename(old, r.root); rerr != nil {
			return fmt.Errorf("swap dbs: %v (and restoring the old tree failed: %v)", err, rerr)
		}
		return fmt.Errorf("swap dbs: install new tree: %w", err)
	}
	_ = os.RemoveAll(old)
	return nil
}

// Drop closes and permanently deletes a database directory.
func (r *Registry) Drop(name string) error {
	if !ValidDBName(name) {
		return ErrNoDB
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	d := filepath.Join(r.root, name)
	if st, err := os.Stat(d); err != nil || !st.IsDir() {
		return ErrNoDB
	}
	if b := r.open[name]; b != nil {
		if err := b.Close(); err != nil {
			return err
		}
		delete(r.open, name)
	}
	return os.RemoveAll(d)
}
