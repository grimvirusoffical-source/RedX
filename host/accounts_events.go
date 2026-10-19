package host

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// The moderation poller: redxd follows the Red-XAI Accounts event feed (app back-channel, client
// authentication) with a persisted cursor and ends the console sessions and WebSockets of accounts that are
// kicked, banned, terminated or deleted. The wire format lives in accounts_events_adapter.go.

type eventCursor struct {
	mu    sync.Mutex
	path  string
	Since int64 `json:"since"`
}

func loadEventCursor(dataDir string) *eventCursor {
	c := &eventCursor{path: filepath.Join(dataDir, "accounts", "events.json")}
	if b, err := os.ReadFile(c.path); err == nil {
		_ = json.Unmarshal(b, c)
	}
	return c
}

func (c *eventCursor) save() error {
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(c)
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

const eventsPageLimit = 200

// PollAccountEventsNow applies every pending Red-XAI Accounts event once (the poller calls it on a timer;
// tests call it directly). It returns how many console sessions it ended.
func (h *Host) PollAccountEventsNow(ctx context.Context) (int, error) {
	if !h.AccountsEnabled() || h.evCursor == nil {
		return 0, nil
	}
	c := h.evCursor
	c.mu.Lock()
	defer c.mu.Unlock()
	ended := 0
	for page := 0; page < 50; page++ { // catch up at most 10,000 events per round
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		st, b, err := h.oidc.backChannel(cctx, "GET", accountEventsPath(c.Since, eventsPageLimit))
		cancel()
		if err != nil {
			return ended, err
		}
		if st != 200 {
			return ended, fmt.Errorf("events feed: status %d", st)
		}
		evs, next, more, err := parseAccountEvents(b, c.Since)
		if err != nil {
			return ended, err
		}
		for _, e := range evs {
			if !e.endsSessions() {
				continue
			}
			n := h.accts.endSessionsForSub(e.Account)
			ended += n
			h.Audit.Log(AuditEvent{Event: "account.sessions_ended", KeyID: "acct:" + e.Account, Reason: e.Type,
				Detail: strconv.Itoa(n) + " console session(s) ended by Red-XAI Accounts event " + strconv.FormatInt(e.Seq, 10)})
		}
		if next != c.Since {
			c.Since = next
			if err := c.save(); err != nil {
				return ended, err
			}
		}
		if !more {
			return ended, nil
		}
	}
	return ended, nil
}

func (h *Host) accountEventsLoop(ctx context.Context) {
	defer h.wg.Done()
	t := time.NewTicker(time.Duration(h.Cfg.AccountsEventsPoll) * time.Second)
	defer t.Stop()
	failing := false
	for {
		if _, err := h.PollAccountEventsNow(ctx); err != nil {
			if !failing {
				h.Logf("accounts: event feed: %v (will keep retrying)", err)
			}
			failing = true
		} else {
			failing = false
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
