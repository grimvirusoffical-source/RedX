package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
)

func cmdApp(args []string) {
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		appList(rest)
	case "create":
		appCreate(rest)
	case "show":
		appShow(rest)
	case "deploy":
		appDeploy(rest)
	case "rollback":
		appRollback(rest)
	case "promote":
		appSimple(rest, "promote")
	case "start":
		appSimple(rest, "start")
	case "stop":
		appSimple(rest, "stop")
	case "delete":
		appSimple(rest, "delete")
	case "domain":
		appDomain(rest)
	case "caddy":
		appCaddy(rest)
	default:
		usage()
		os.Exit(2)
	}
}

func appClient(args []string, name string) (globals, []string) {
	var g globals
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	g.bind(fs)
	return g, parse(fs, args)
}

func appPrint(g globals, v any) {
	if g.asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(v)
		return
	}
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

func appList(args []string) {
	g, pos := appClient(args, "app list")
	if len(pos) != 0 {
		die("usage: redx app list")
	}
	c, cancel := ctx()
	defer cancel()
	var out any
	if err := g.client().JSON(c, "GET", "/v1/hosted/apps", nil, &out); err != nil {
		die("%v", err)
	}
	appPrint(g, out)
}

func appCreate(args []string) {
	var g globals
	fs := flag.NewFlagSet("app create", flag.ExitOnError)
	g.bind(fs)
	kind := fs.String("kind", "static", "static|container|process")
	db := fs.String("db", "", "logical database this app may use")
	pos := parse(fs, args)
	if len(pos) != 1 {
		die("usage: redx app create NAME [--kind static|container|process] [--db NAME]")
	}
	c, cancel := ctx()
	defer cancel()
	var out any
	body := map[string]string{"name": pos[0], "kind": *kind}
	if *db != "" {
		body["db"] = *db
	}
	if err := g.client().JSON(c, "POST", "/v1/hosted/apps", body, &out); err != nil {
		die("%v", err)
	}
	appPrint(g, out)
}

func appShow(args []string) {
	g, pos := appClient(args, "app show")
	if len(pos) != 1 {
		die("usage: redx app show ID")
	}
	c, cancel := ctx()
	defer cancel()
	var out any
	if err := g.client().JSON(c, "GET", "/v1/hosted/apps/"+url.PathEscape(pos[0]), nil, &out); err != nil {
		die("%v", err)
	}
	appPrint(g, out)
}

func appDeploy(args []string) {
	var g globals
	fs := flag.NewFlagSet("app deploy", flag.ExitOnError)
	g.bind(fs)
	archive := fs.String("archive", "", "zip, tar or tar.gz to upload")
	repo := fs.String("github", "", "owner/repo")
	ref := fs.String("ref", "", "git tag, branch or commit")
	image := fs.String("image", "", "container image")
	docker := fs.String("dockerfile", "", "owner/repo that contains a Dockerfile")
	file := fs.String("file", "Dockerfile", "Dockerfile path inside the repository")
	strategy := fs.String("strategy", "direct", "direct|canary|blue_green")
	canary := fs.Int("canary", 0, "canary percent (default 10 when strategy is canary)")
	pos := parse(fs, args)
	if len(pos) != 1 {
		die("usage: redx app deploy ID (--archive FILE | --github REPO --ref REF | --image IMG | --dockerfile REPO --ref REF)")
	}
	c, cancel := ctx()
	defer cancel()
	id := url.PathEscape(pos[0])
	var out any
	if *archive != "" {
		b, err := os.ReadFile(*archive)
		if err != nil {
			die("%v", err)
		}
		q := url.Values{}
		q.Set("strategy", *strategy)
		if *canary > 0 {
			q.Set("canaryPct", fmt.Sprint(*canary))
		}
		st, _, body, err := g.client().Raw(c, "POST", "/v1/hosted/apps/"+id+"/archive?"+q.Encode(), b, nil)
		if err != nil {
			die("%v", err)
		}
		if st < 200 || st > 299 {
			die("%d %s", st, strings.TrimSpace(string(body)))
		}
		_ = json.Unmarshal(body, &out)
		appPrint(g, out)
		return
	}
	body := map[string]any{"strategy": *strategy}
	if *canary > 0 {
		body["canaryPct"] = *canary
	}
	switch {
	case *image != "":
		body["source"] = "image"
		body["image"] = *image
	case *docker != "":
		body["source"] = "dockerfile"
		body["repo"] = *docker
		body["ref"] = *ref
		body["dockerfile"] = *file
	case *repo != "":
		body["source"] = "github"
		body["repo"] = *repo
		body["ref"] = *ref
	default:
		die("deploy needs --archive, --github, --image or --dockerfile")
	}
	if err := g.client().JSON(c, "POST", "/v1/hosted/apps/"+id+"/deploy", body, &out); err != nil {
		die("%v", err)
	}
	appPrint(g, out)
}

func appRollback(args []string) {
	var g globals
	fs := flag.NewFlagSet("app rollback", flag.ExitOnError)
	g.bind(fs)
	dep := fs.String("deploy", "", "deploy id")
	snap := fs.String("snapshot", "", "snapshot id")
	pos := parse(fs, args)
	if len(pos) != 1 || (*dep == "" && *snap == "") {
		die("usage: redx app rollback ID (--deploy ID | --snapshot ID)")
	}
	c, cancel := ctx()
	defer cancel()
	var out any
	if err := g.client().JSON(c, "POST", "/v1/hosted/apps/"+url.PathEscape(pos[0])+"/rollback", map[string]string{"deploy": *dep, "snapshot": *snap}, &out); err != nil {
		die("%v", err)
	}
	appPrint(g, out)
}

func appSimple(args []string, action string) {
	g, pos := appClient(args, "app "+action)
	if len(pos) != 1 {
		die("usage: redx app %s ID", action)
	}
	c, cancel := ctx()
	defer cancel()
	id := url.PathEscape(pos[0])
	var out any
	method, path := "POST", "/v1/hosted/apps/"+id+"/"+action
	if action == "delete" {
		method, path = "DELETE", "/v1/hosted/apps/"+id
	}
	if err := g.client().JSON(c, method, path, nil, &out); err != nil {
		die("%v", err)
	}
	appPrint(g, out)
}

func appDomain(args []string) {
	if len(args) == 0 {
		die("usage: redx app domain add|verify|rm ID NAME")
	}
	action, rest := args[0], args[1:]
	var g globals
	fs := flag.NewFlagSet("app domain", flag.ExitOnError)
	g.bind(fs)
	method := fs.String("method", "txt", "txt|cname|http")
	pos := parse(fs, rest)
	if len(pos) != 2 || (action != "add" && action != "verify" && action != "rm") {
		die("usage: redx app domain add|verify|rm ID NAME")
	}
	c, cancel := ctx()
	defer cancel()
	id := url.PathEscape(pos[0])
	name := url.PathEscape(pos[1])
	var out any
	var err error
	switch action {
	case "add":
		err = g.client().JSON(c, "POST", "/v1/hosted/apps/"+id+"/domains", map[string]string{"domain": pos[1], "method": *method}, &out)
	case "verify":
		err = g.client().JSON(c, "POST", "/v1/hosted/apps/"+id+"/domains/"+name+"/verify", nil, &out)
	default:
		err = g.client().JSON(c, "DELETE", "/v1/hosted/apps/"+id+"/domains/"+name, nil, &out)
	}
	if err != nil {
		die("%v", err)
	}
	appPrint(g, out)
}

func appEnv(args []string) {
	if len(args) == 0 {
		die("usage: redx app env show|set ID")
	}
	action, rest := args[0], args[1:]
	g, pos := appClient(rest, "app env")
	c, cancel := ctx()
	defer cancel()
	switch action {
	case "show":
		if len(pos) != 1 {
			die("usage: redx app env show ID")
		}
		var out any
		if err := g.client().JSON(c, "GET", "/v1/hosted/apps/"+url.PathEscape(pos[0])+"/env", nil, &out); err != nil {
			die("%v", err)
		}
		appPrint(g, out)
	case "set":
		if len(pos) < 2 {
			die("usage: redx app env set ID KEY=VALUE ...")
		}
		vars := map[string]string{}
		for _, p := range pos[1:] {
			k, v, ok := strings.Cut(p, "=")
			if !ok || k == "" {
				die("env %q is not KEY=VALUE", p)
			}
			vars[k] = v
		}
		var out any
		if err := g.client().JSON(c, "PUT", "/v1/hosted/apps/"+url.PathEscape(pos[0])+"/env", map[string]any{"vars": vars}, &out); err != nil {
			die("%v", err)
		}
		appPrint(g, out)
	default:
		die("usage: redx app env show|set ID")
	}
}

func appSecret(args []string) {
	if len(args) == 0 {
		die("usage: redx app secret set|rm ID NAME")
	}
	action, rest := args[0], args[1:]
	g, pos := appClient(rest, "app secret")
	if len(pos) != 2 || (action != "set" && action != "rm") {
		die("usage: redx app secret set|rm ID NAME")
	}
	c, cancel := ctx()
	defer cancel()
	path := "/v1/hosted/apps/" + url.PathEscape(pos[0]) + "/secrets/" + url.PathEscape(pos[1])
	var out any
	if action == "rm" {
		if err := g.client().JSON(c, "DELETE", path, nil, &out); err != nil {
			die("%v", err)
		}
		appPrint(g, out)
		return
	}
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		die("%v", err)
	}
	val := strings.TrimRight(string(b), "\r\n")
	if val == "" {
		die("secret value is empty (pass it on stdin)")
	}
	if err := g.client().JSON(c, "PUT", path, map[string]string{"value": val}, &out); err != nil {
		die("%v", err)
	}
	appPrint(g, out)
}

func appLogs(args []string) {
	var g globals
	fs := flag.NewFlagSet("app logs", flag.ExitOnError)
	g.bind(fs)
	kind := fs.String("kind", "runtime", "runtime|access")
	outPath := fs.String("out", "", "write the log to this file")
	pos := parse(fs, args)
	if len(pos) != 1 {
		die("usage: redx app logs ID [--kind runtime|access] [--out FILE]")
	}
	c, cancel := ctx()
	defer cancel()
	st, _, body, err := g.client().Raw(c, "GET", "/v1/hosted/apps/"+url.PathEscape(pos[0])+"/logs/download?kind="+url.QueryEscape(*kind), nil, nil)
	if err != nil {
		die("%v", err)
	}
	if st < 200 || st > 299 {
		die("%d %s", st, strings.TrimSpace(string(body)))
	}
	if *outPath != "" {
		if err := os.WriteFile(*outPath, body, 0o600); err != nil {
			die("%v", err)
		}
		fmt.Println("wrote", *outPath)
		return
	}
	os.Stdout.Write(body)
}

func appCaddy(args []string) {
	g, pos := appClient(args, "app caddy")
	if len(pos) != 0 {
		die("usage: redx app caddy")
	}
	c, cancel := ctx()
	defer cancel()
	st, _, body, err := g.client().Raw(c, "GET", "/v1/hosted/caddy", nil, nil)
	if err != nil {
		die("%v", err)
	}
	if st < 200 || st > 299 {
		die("%d %s", st, strings.TrimSpace(string(body)))
	}
	os.Stdout.Write(body)
}
