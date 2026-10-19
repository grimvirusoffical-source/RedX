package host

import (
	"encoding/json"
	"fmt"
)

// The Red-XAI Accounts cross-app event feed, as data. This adapter is the only code that knows the wire shape
// of GET /v1/apps/events (v1 contract: {events: [{seq, atMs, type, account, untilMs, reason}], next}), so a
// docs bump changes this file alone.

// acctEvent is one moderation event, in RedX's own terms.
// update.* / rollout.* / rollback.done fields are set when the Accounts feed carries a host-update event.
type acctEvent struct {
	Seq       int64
	Type      string // account.kicked | account.banned | account.unbanned | account.terminated | account.deleted | account.updated | update.* | rollout.* | rollback.done
	Account   string // the Red-XAI Account id (the OIDC sub)
	UntilMs   int64
	Reason    string
	App       string
	Version   string
	Source    string
	RolloutID string
	State     string
}

// isUpdate reports a host-update event carried on the Accounts feed. Those events do not end sessions.
func (e acctEvent) isUpdate() bool {
	switch e.Type {
	case "update.available", "update.analysed", "rollout.state", "rollout.health", "rollback.done":
		return true
	}
	return false
}

// endsSessions reports whether the event must end the account's console sessions on this host.
func (e acctEvent) endsSessions() bool {
	switch e.Type {
	case "account.banned", "account.terminated", "account.deleted", "account.kicked":
		return true
	}
	return false
}

// parseAccountEvents decodes one page. next is the cursor to store; more is the feed's hasMore (poll again now when true).
func parseAccountEvents(b []byte, since int64) (out []acctEvent, next int64, more bool, err error) {
	var page struct {
		Events []struct {
			Seq       int64  `json:"seq"`
			AtMs      int64  `json:"atMs"`
			Type      string `json:"type"`
			Account   string `json:"account"`
			UntilMs   int64  `json:"untilMs"`
			Reason    string `json:"reason"`
			App       string `json:"app"`
			Version   string `json:"version"`
			Source    string `json:"source"`
			RolloutID string `json:"rollout_id"`
			State     string `json:"state"`
		} `json:"events"`
		Next    int64 `json:"next"`
		HasMore bool  `json:"hasMore"`
	}
	if err = json.Unmarshal(b, &page); err != nil {
		return nil, since, false, fmt.Errorf("events feed: %w", err)
	}
	next = since
	out = make([]acctEvent, 0, len(page.Events))
	seen := map[int64]bool{}
	for _, e := range page.Events {
		if e.Seq <= since || seen[e.Seq] {
			continue // at-least-once: dedupe by seq
		}
		seen[e.Seq] = true
		out = append(out, acctEvent{Seq: e.Seq, Type: e.Type, Account: e.Account, UntilMs: e.UntilMs, Reason: e.Reason, App: e.App, Version: e.Version, Source: e.Source, RolloutID: e.RolloutID, State: e.State})
		if e.Seq > next {
			next = e.Seq
		}
	}
	if page.Next > next {
		next = page.Next
	}
	return out, next, page.HasMore, nil
}

// accountEventsPath is the poll request for a cursor.
func accountEventsPath(since int64, limit int) string {
	return fmt.Sprintf("/v1/apps/events?since=%d&limit=%d", since, limit)
}
