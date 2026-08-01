package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
)

// inject handlers are lab-only and refuse unless SC5_ALLOW_INJECT=1.
func handleInject(cmd string, args map[string]any) string {
	if os.Getenv("SC5_ALLOW_INJECT") != "1" {
		return "error: inject disabled (set SC5_ALLOW_INJECT=1 for authorized lab only)"
	}
	tech, _ := args["technique"].(string)
	if tech == "" {
		tech = cmd
	}
	pid := anyToInt(args["pid"])
	switch tech {
	case "create_remote_thread", "apc_queue":
		if runtime.GOOS != "windows" {
			return "error: windows-only technique"
		}
		// Lab stub: do not perform real process injection in default builds.
		// Full implementations are gated behind lab research builds.
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

func handleBofRun(args map[string]any) string {
	if os.Getenv("SC5_ALLOW_BOF") != "1" {
		return "error: bof disabled (set SC5_ALLOW_BOF=1 for authorized lab only)"
	}
	mod, _ := args["module_id"].(string)
	entry, _ := args["entry"].(string)
	if entry == "" {
		entry = "go"
	}
	// Safe build: validate metadata only; COFF execute is research-gated.
	arch, _ := args["coff"].(map[string]any)
	msg := fmt.Sprintf("bof:lab_stub module=%s entry=%s", mod, entry)
	if arch != nil {
		msg += fmt.Sprintf(" coff_arch=%v sections=%v", arch["arch"], arch["sections"])
	}
	if sz := anyToInt(args["size"]); sz > 0 {
		msg += " size=" + strconv.Itoa(sz)
	}
	return msg + " (loader host ready; execution gated)"
}
