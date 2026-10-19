package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"redx/host"
)

// cmdPreset: redx preset ls | show NAME [--diff] | apply NAME [--dry-run] [--set k=v] [--join LINK]
func cmdPreset(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: redx preset ls | show NAME [--diff] | apply NAME [--dry-run] [--set key=value ...] [--join LINK]")
		os.Exit(2)
	}
	sub, args := args[0], args[1:]
	var g globals
	fs := flag.NewFlagSet("preset "+sub, flag.ExitOnError)
	g.bind(fs)
	diff := fs.Bool("diff", false, "show: compare with the settings of the running host")
	dry := fs.Bool("dry-run", false, "apply: show what would change, write nothing")
	join := fs.String("join", "", "apply: join link from the leader (presets that make this host a follower)")
	var sets multi
	fs.Var(&sets, "set", "apply: override a setting, key=value (repeatable)")
	pos := parse(fs, args)
	switch sub {
	case "ls", "list":
		if g.asJSON {
			json.NewEncoder(os.Stdout).Encode(host.AllPresets())
			return
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tTITLE\tFOR")
		for _, p := range host.AllPresets() {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", p.Name, p.Title, p.Audience)
		}
		tw.Flush()
		fmt.Println("\nredx preset show NAME      what it sets and why")
		fmt.Println("redxd run --preset NAME    start the host with it (or  preset = \"NAME\"  in redx.toml)")
	case "show":
		if len(pos) != 1 {
			die("usage: redx preset show NAME [--diff]")
		}
		p, err := host.GetPreset(pos[0])
		if err != nil {
			die("%v", err)
		}
		if g.asJSON {
			json.NewEncoder(os.Stdout).Encode(p)
			return
		}
		fmt.Printf("%s - %s\n%s\n\n", p.Title, p.Audience, p.Summary)
		var changes map[string]host.SettingChange
		if *diff {
			var out struct {
				Diff []host.SettingChange `json:"diff"`
			}
			c, cancel := ctx()
			defer cancel()
			if err := g.client().JSON(c, "GET", "/v1/admin/presets/"+p.Name, nil, &out); err != nil {
				die("%v", err)
			}
			changes = map[string]host.SettingChange{}
			for _, ch := range out.Diff {
				changes[ch.Key] = ch
			}
		}
		for _, k := range p.SettingKeys() {
			fmt.Printf("  %s = %v", k, p.Settings[k])
			if ch, ok := changes[k]; ok {
				if ch.Changed {
					fmt.Printf("    (now: %v)", ch.From)
				} else {
					fmt.Printf("    (unchanged)")
				}
			}
			fmt.Println()
			if w := p.Why[k]; w != "" {
				fmt.Println("      why: " + w)
			}
		}
		if len(p.Needs) > 0 {
			fmt.Println("\nneeds: " + strings.Join(p.Needs, "; "))
		}
		for _, s := range p.Guidance {
			fmt.Println("\n  * " + s)
		}
		for _, s := range p.Warnings {
			fmt.Println("\n  ! " + s)
		}
		if len(p.Files) > 0 {
			fmt.Println("\nrecommended files:")
			for _, f := range p.Files {
				fmt.Printf("  %s  %s\n", f.Name, f.Note)
			}
		}
	case "apply":
		if len(pos) != 1 {
			die("usage: redx preset apply NAME [--dry-run] [--set key=value] [--join LINK]")
		}
		over := map[string]interface{}{}
		for _, kv := range sets {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				die("--set wants key=value, got %q", kv)
			}
			over[k] = parseScalar(v)
		}
		body := map[string]interface{}{"overrides": over, "dry_run": *dry, "join": *join}
		var out struct {
			Path    string               `json:"path"`
			Backup  string               `json:"backup"`
			Changes []host.SettingChange `json:"changes"`
			Skipped []struct{ Key, Reason string }
			Env     []string `json:"env_overrides"`
		}
		c, cancel := ctx()
		defer cancel()
		if err := g.client().JSON(c, "POST", "/v1/admin/presets/"+pos[0]+"/apply", body, &out); err != nil {
			die("%v", err)
		}
		keys := make([]string, 0)
		byKey := map[string]host.SettingChange{}
		for _, ch := range out.Changes {
			keys = append(keys, ch.Key)
			byKey[ch.Key] = ch
		}
		sort.Strings(keys)
		fmt.Println("what changed:")
		for _, k := range keys {
			ch := byKey[k]
			mark := "="
			if ch.Changed {
				mark = "~"
			}
			fmt.Printf("  %s %s: %v -> %v\n", mark, k, ch.From, ch.To)
		}
		for _, s := range out.Skipped {
			fmt.Printf("  not applied: %s - %s\n", s.Key, s.Reason)
		}
		if len(out.Env) > 0 {
			fmt.Printf("note: these settings are also set by environment variables, which win over the file: %s\n", strings.Join(out.Env, ", "))
		}
		if *dry {
			fmt.Println("dry run: nothing written.")
			return
		}
		fmt.Printf("written to %s", out.Path)
		if out.Backup != "" {
			fmt.Printf(" (previous file kept as %s)", out.Backup)
		}
		fmt.Println("\nrestart redxd for it to take effect.")
	default:
		die("unknown preset command %q", sub)
	}
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

func parseScalar(s string) interface{} {
	switch s {
	case "true":
		return true
	case "false":
		return false
	}
	var f float64
	if _, err := fmt.Sscanf(s, "%g", &f); err == nil && fmt.Sprint(f) == s {
		return f
	}
	return s
}
