package main

import (
	"encoding/base64"
	"fmt"
	"runtime"
	"strings"
)

// inject handlers are lab-only and refuse unless SC5_ALLOW_INJECT=1.
// Default builds never perform real process injection.
func handleInject(cmd string, args map[string]any) string {
	if !allowInject() {
		return "error: inject disabled (set SC5_ALLOW_INJECT=1 for authorized lab only)"
	}
	tech, _ := args["technique"].(string)
	if tech == "" {
		tech = cmd
	}
	if len(tech) > 7 && tech[:7] == "inject:" {
		tech = tech[7:]
	}
	tech = strings.ToLower(strings.TrimSpace(tech))
	pid := anyToInt(args["pid"])
	hasShellcode := false
	if s, ok := args["shellcode_b64"].(string); ok && s != "" {
		if _, err := base64.StdEncoding.DecodeString(s); err == nil {
			hasShellcode = true
		}
	}

	switch tech {
	case "list":
		return injectListJSON()
	case "create_remote_thread", "crt":
		return injectStub("create_remote_thread", "windows", pid, hasShellcode)
	case "apc_queue", "apc":
		return injectStub("apc_queue", "windows", pid, hasShellcode)
	case "early_bird":
		return injectStub("early_bird", "windows", pid, hasShellcode)
	case "nt_queue_apc":
		return injectStub("nt_queue_apc", "windows", pid, hasShellcode)
	case "process_hollowing":
		return injectStub("process_hollowing", "windows", pid, hasShellcode)
	case "process_vm_write", "vm_write":
		return injectStub("process_vm_write", "linux", pid, hasShellcode)
	case "memfd_exec":
		return injectStub("memfd_exec", "linux", pid, hasShellcode)
	case "self_inject":
		return injectStub("self_inject", runtime.GOOS, 0, hasShellcode)
	default:
		return "error: unknown inject technique " + tech + " (use inject:list)"
	}
}

func injectListJSON() string {
	return `[
  {"id":"create_remote_thread","platforms":["windows"],"risk":"high"},
  {"id":"apc_queue","platforms":["windows"],"risk":"high"},
  {"id":"early_bird","platforms":["windows"],"risk":"high"},
  {"id":"nt_queue_apc","platforms":["windows"],"risk":"high"},
  {"id":"process_hollowing","platforms":["windows"],"risk":"critical"},
  {"id":"process_vm_write","platforms":["linux"],"risk":"high"},
  {"id":"memfd_exec","platforms":["linux"],"risk":"high"},
  {"id":"self_inject","platforms":["windows","linux"],"risk":"high"}
]`
}

func injectStub(tech, requiredOS string, pid int, hasSC bool) string {
	if requiredOS != "windows" && requiredOS != "linux" && requiredOS != runtime.GOOS {
		// multi-platform ok
	} else if requiredOS == "windows" && runtime.GOOS != "windows" {
		return "error: windows-only technique"
	} else if requiredOS == "linux" && runtime.GOOS != "linux" {
		return "error: linux-only technique"
	}
	// Lab stub: validate args, refuse real inject in default release builds.
	return fmt.Sprintf(
		"inject:lab_stub technique=%s pid=%d os=%s shellcode=%v exec=no-op (research build required for live inject)",
		tech, pid, runtime.GOOS, hasSC,
	)
}
