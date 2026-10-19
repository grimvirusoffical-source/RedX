package billing

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Plan is one Red-XAI Account's RedX Hosted plan as last seen from Stripe.
type Plan struct {
	Account      string    `json:"account"` // Red-XAI Account sub
	Tier         string    `json:"tier,omitempty"`
	Interval     string    `json:"interval,omitempty"` // month | year (from Stripe price lookup key)
	Status       string    `json:"status,omitempty"`   // Stripe subscription status
	PeriodEnd    time.Time `json:"periodEnd,omitempty"`
	CancelAtEnd  bool      `json:"cancelAtPeriodEnd,omitempty"`
	Customer     string    `json:"customer,omitempty"`
	Subscription string    `json:"subscription,omitempty"`
	Updated      time.Time `json:"updated"`
}

// Grace keeps a plan working this long past the paid period while Stripe retries a renewal.
const Grace = 3 * 24 * time.Hour

// Active reports whether the plan currently entitles the account to its tier.
func (p Plan) Active(now time.Time) bool {
	if p.Tier == "" {
		return false
	}
	switch p.Status {
	case "active", "trialing", "past_due":
		return p.PeriodEnd.IsZero() || now.Before(p.PeriodEnd.Add(Grace))
	}
	return false
}

// Store keeps plans in a 0600 JSON file under the data dir, plus processed webhook event ids.
type Store struct {
	mu     sync.Mutex
	path   string
	Plans  map[string]Plan      `json:"plans"`
	Events map[string]time.Time `json:"events"`
}

// OpenStore loads (or starts) the plan file. path "" keeps everything in memory.
func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, Plans: map[string]Plan{}, Events: map[string]time.Time{}}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(b, s); err != nil {
			return nil, err
		}
		if s.Plans == nil {
			s.Plans = map[string]Plan{}
		}
		if s.Events == nil {
			s.Events = map[string]time.Time{}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	cut := time.Now().Add(-30 * 24 * time.Hour)
	for id, t := range s.Events {
		if t.Before(cut) {
			delete(s.Events, id)
		}
	}
	b, err := json.MarshalIndent(s, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Get returns an account's plan.
func (s *Store) Get(account string) (Plan, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.Plans[account]
	return p, ok
}

// Put stores an account's plan.
func (s *Store) Put(p Plan) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Plans[p.Account] = p
	return s.saveLocked()
}

// seen records an event id and reports whether it was already processed.
func (s *Store) seen(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.Events[id]; ok {
		return true
	}
	s.Events[id] = time.Now()
	_ = s.saveLocked()
	return false
}

func (s *Store) forget(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.Events, id)
	_ = s.saveLocked()
}
