package main

import (
	"fmt"
	"runtime"
)

// inject handlers are lab-only and refuse unless SC5_ALLOW_INJECT=1.
func handleInject(cmd string, args map[string]any) string {
	if !allowInject() {
		return "error: inject disabled (set SC5_ALLOW_INJECT=1 for authorized lab only)"
	}
	tech, _ := args["technique"].(string)
	if tech == "" {
		tech = cmd
	}
	// strip inject: prefix
	if len(tech) > 7 && tech[:7] == "inject:" {
		tech = tech[7:]
	}
	pid := anyToInt(args["pid"])
	switch tech {
	case "create_remote_thread", "apc_queue":
		if runtime.GOOS != "windows" {
			return "error: windows-only technique"
		}
		// Lab stub: no real process injection in default builds.
		return fmt.Sprintf("inject:lab_stub technique=%s pid=%d os=%s (no-op safe build)", tech, pid, runtime.GOOS)
	case "process_vm_write":
		if runtime.GOOS != "linux" {
			return "error: linux-only technique"
		}
		return fmt.Sprintf("inject:lab_stub technique=%s pid=%d (no-op safe build)", tech, pid)
	default:
		return "error: unknown inject technique " + tech
	}
}
