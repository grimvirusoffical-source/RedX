package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
)

func cmdUpdate(args []string) {
	var g globals
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	g.bind(fs)
	version := fs.String("version", "", "manifest version to apply")
	source := fs.String("source", "", "host or github")
	canary := fs.Int("canary", -1, "canary percent; sets the strategy to canary")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `redx update — host updates

  redx update status [APP]
  redx update check
  redx update apply APP [--version V] [--source host|github] [--canary PERCENT]
  redx update promote ID
  redx update rollback ID
  redx update snapshots APP
  redx update restore APP SNAP
  redx update source APP host|github|both

`)
		fs.PrintDefaults()
	}
	pos := parse(fs, args)
	if len(pos) == 0 {
		fs.Usage()
		os.Exit(2)
	}
	switch pos[0] {
	case "status":
		updateStatus(&g, pos[1:])
	case "check":
		updateCheck(&g)
	case "apply":
		if len(pos) < 2 {
			die("update apply needs an app")
		}
		updateApply(&g, pos[1], *version, *source, *canary)
	case "promote":
		if len(pos) != 2 {
			die("update promote needs a rollout id")
		}
		updatePromote(&g, pos[1])
	case "rollback":
		if len(pos) != 2 {
			die("update rollback needs a rollout id")
		}
		updateRollback(&g, pos[1])
	case "snapshots":
		if len(pos) != 2 {
			die("update snapshots needs an app")
		}
		updateSnapshots(&g, pos[1])
	case "restore":
		if len(pos) != 3 {
			die("update restore needs an app and a snapshot id")
		}
		updateRestore(&g, pos[1], pos[2])
	case "source":
		if len(pos) != 3 {
			die("update source needs an app and host|github|both")
		}
		updateSource(&g, pos[1], pos[2])
	default:
		fmt.Fprintf(os.Stderr, "redx: unknown update command %q\n\n", pos[0])
		fs.Usage()
		os.Exit(2)
	}
}

func updateCall(g *globals, method, path string, in, out interface{}) {
	c, cancel := ctx()
	defer cancel()
	var body []byte
	hdr := map[string]string{}
	if in != nil {
		body, _ = json.Marshal(in)
		hdr["Content-Type"] = "application/json"
	}
	if id := updateConfirm(method, path); id != "" {
		hdr["X-RedX-Confirm"] = id
	}
	st, _, b, err := g.client().Raw(c, method, path, body, hdr)
	if err != nil {
		die("%v", err)
	}
	if st < 200 || st > 299 {
		die("%s", updateErrText(st, b))
	}
	if out != nil && len(bytesTrim(b)) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			die("%v", err)
		}
	}
}

func updateConfirm(method, path string) string {
	if method != "POST" {
		return ""
	}
	switch {
	case strings.HasSuffix(path, "/apply"):
		return "updateApply"
	case strings.HasSuffix(path, "/promote"):
		return "updatePromote"
	case strings.Contains(path, "/rollouts/") && strings.HasSuffix(path, "/rollback"):
		return "updateRolloutRollback"
	case strings.HasSuffix(path, "/rollback"):
		return "updateAppRollback"
	case strings.HasSuffix(path, "/publish"):
		return "updatePublish"
	}
	return ""
}

func bytesTrim(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}

func updateErrText(st int, b []byte) string {
	var e struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(b, &e) == nil && e.Error.Code != "" {
		return fmt.Sprintf("%d %s: %s", st, e.Error.Code, e.Error.Message)
	}
	msg := strings.TrimSpace(string(b))
	if msg == "" {
		msg = "request failed"
	}
	return fmt.Sprintf("%d %s", st, msg)
}

func updatePrint(g *globals, v interface{}) {
	if g.asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(v)
		return
	}
}

type updateStatusDoc struct {
	App        string `json:"app"`
	Hosted     bool   `json:"hosted"`
	SourcePref string `json:"source_pref"`
	Installed  *struct {
		Version  string `json:"version"`
		Sequence int64  `json:"sequence"`
	} `json:"installed"`
	Latest struct {
		Host *struct {
			Version  string `json:"version"`
			Sequence int64  `json:"sequence"`
		} `json:"host"`
		GitHub *struct {
			Version  string `json:"version"`
			Sequence int64  `json:"sequence"`
		} `json:"github"`
	} `json:"latest"`
	Available []struct {
		Version string   `json:"version"`
		Channel string   `json:"channel"`
		Sources []string `json:"sources"`
		Outcome struct {
			Tags    []string `json:"tags"`
			Summary string   `json:"summary"`
		} `json:"outcome"`
	} `json:"available"`
}

func updateStatus(g *globals, pos []string) {
	if len(pos) > 1 {
		die("update status takes at most one app")
	}
	if len(pos) == 1 {
		var doc updateStatusDoc
		updateCall(g, "GET", "/v1/updates/apps/"+pos[0], nil, &doc)
		if g.asJSON {
			updatePrint(g, doc)
			return
		}
		printOneStatus(doc)
		return
	}
	var doc struct {
		Apps []updateStatusDoc `json:"apps"`
	}
	updateCall(g, "GET", "/v1/updates/apps", nil, &doc)
	if g.asJSON {
		updatePrint(g, doc)
		return
	}
	if len(doc.Apps) == 0 {
		fmt.Println("no apps")
		return
	}
	for _, a := range doc.Apps {
		printOneStatus(a)
		fmt.Println()
	}
}

func printOneStatus(doc updateStatusDoc) {
	inst := "—"
	if doc.Installed != nil && doc.Installed.Version != "" {
		inst = fmt.Sprintf("%s (sequence %d)", doc.Installed.Version, doc.Installed.Sequence)
	}
	fmt.Printf("%s  hosted=%t  source=%s  installed=%s\n", doc.App, doc.Hosted, doc.SourcePref, inst)
	if len(doc.Available) == 0 {
		fmt.Println("  no manifests")
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  VERSION\tCHANNEL\tSOURCES\tTAGS\tSUMMARY")
	for _, a := range doc.Available {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", a.Version, a.Channel, strings.Join(a.Sources, ","), strings.Join(a.Outcome.Tags, " "), a.Outcome.Summary)
	}
	tw.Flush()
}

func updateCheck(g *globals) {
	var doc struct {
		Apps []updateStatusDoc `json:"apps"`
	}
	updateCall(g, "GET", "/v1/updates/apps", nil, &doc)
	if g.asJSON {
		updatePrint(g, doc)
		return
	}
	n := 0
	for _, a := range doc.Apps {
		inst := ""
		if a.Installed != nil {
			inst = a.Installed.Version
		}
		for _, av := range a.Available {
			if av.Version == inst {
				continue
			}
			n++
			fmt.Printf("%s %s (%s) %s\n", a.App, av.Version, strings.Join(av.Sources, ","), strings.Join(av.Outcome.Tags, " "))
		}
	}
	if n == 0 {
		fmt.Println("no updates")
	}
}

func updateApply(g *globals, app, version, source string, canary int) {
	if version == "" || source == "" {
		var doc updateStatusDoc
		updateCall(g, "GET", "/v1/updates/apps/"+app, nil, &doc)
		if source == "" {
			if doc.Hosted && doc.SourcePref != "github" && doc.Latest.Host != nil {
				source = "host"
			} else if doc.Latest.GitHub != nil {
				source = "github"
			} else if doc.Latest.Host != nil {
				source = "host"
			} else {
				die("no manifest to apply")
			}
		}
		if version == "" {
			switch source {
			case "host":
				if doc.Latest.Host == nil {
					die("no host manifest")
				}
				version = doc.Latest.Host.Version
			case "github":
				if doc.Latest.GitHub == nil {
					die("no github manifest")
				}
				version = doc.Latest.GitHub.Version
			default:
				die("source must be host or github")
			}
		}
	}
	body := map[string]interface{}{"version": version, "source": source, "strategy": "direct"}
	if canary >= 0 {
		body["strategy"] = "canary"
		body["canary"] = map[string]int{"percent": canary, "min_minutes": 0}
	}
	var out struct {
		RolloutID  string `json:"rollout_id"`
		SnapshotID string `json:"snapshot_id"`
	}
	updateCall(g, "POST", "/v1/updates/apps/"+app+"/apply", body, &out)
	if g.asJSON {
		updatePrint(g, out)
		return
	}
	fmt.Printf("rollout %s\nsnapshot %s\n", out.RolloutID, out.SnapshotID)
}

func updatePromote(g *globals, id string) {
	var out map[string]interface{}
	updateCall(g, "POST", "/v1/updates/rollouts/"+id+"/promote", map[string]interface{}{}, &out)
	if g.asJSON {
		updatePrint(g, out)
		return
	}
	fmt.Printf("%s %v\n", id, out["state"])
}

func updateRollback(g *globals, id string) {
	var out map[string]interface{}
	updateCall(g, "POST", "/v1/updates/rollouts/"+id+"/rollback", map[string]string{"reason": "cli"}, &out)
	if g.asJSON {
		updatePrint(g, out)
		return
	}
	fmt.Printf("%s %v\n", id, out["state"])
}

func updateSnapshots(g *globals, app string) {
	var out struct {
		Snapshots []struct {
			ID      string `json:"id"`
			Version string `json:"version"`
			Created string `json:"created_at"`
			SHA256  string `json:"sha256"`
		} `json:"snapshots"`
	}
	updateCall(g, "GET", "/v1/updates/apps/"+app+"/snapshots", nil, &out)
	if g.asJSON {
		updatePrint(g, out)
		return
	}
	if len(out.Snapshots) == 0 {
		fmt.Println("no snapshots")
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tVERSION\tCREATED\tSHA256")
	for _, s := range out.Snapshots {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", s.ID, s.Version, s.Created, s.SHA256)
	}
	tw.Flush()
}

func updateRestore(g *globals, app, snap string) {
	var out map[string]interface{}
	updateCall(g, "POST", "/v1/updates/apps/"+app+"/rollback", map[string]string{"snapshot_id": snap}, &out)
	if g.asJSON {
		updatePrint(g, out)
		return
	}
	fmt.Printf("restored %s\n", snap)
}

func updateSource(g *globals, app, source string) {
	var out map[string]interface{}
	updateCall(g, "PUT", "/v1/updates/apps/"+app+"/source", map[string]string{"source": source}, &out)
	if g.asJSON {
		updatePrint(g, out)
		return
	}
	fmt.Printf("%s source %s\n", app, source)
}
