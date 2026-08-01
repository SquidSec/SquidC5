package main

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"runtime"
	"strings"
)

// Minimal COFF header parse + lab loader host (I3).
// Full Windows execute path is gated: SC5_ALLOW_BOF=1 and object_b64 present.
// Default builds never map/execute remote code without the gate.

type coffHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

func parseCOFF(data []byte) (*coffHeader, string, error) {
	if len(data) < 20 {
		return nil, "", fmt.Errorf("COFF too small")
	}
	h := &coffHeader{
		Machine:              binary.LittleEndian.Uint16(data[0:2]),
		NumberOfSections:     binary.LittleEndian.Uint16(data[2:4]),
		TimeDateStamp:        binary.LittleEndian.Uint32(data[4:8]),
		PointerToSymbolTable: binary.LittleEndian.Uint32(data[8:12]),
		NumberOfSymbols:      binary.LittleEndian.Uint32(data[12:16]),
		SizeOfOptionalHeader: binary.LittleEndian.Uint16(data[16:18]),
		Characteristics:      binary.LittleEndian.Uint16(data[18:20]),
	}
	arch := "unknown"
	switch h.Machine {
	case 0x14c:
		arch = "i386"
	case 0x8664:
		arch = "amd64"
	case 0xaa64:
		arch = "arm64"
	}
	return h, arch, nil
}

func handleBofRun(args map[string]any) string {
	if !allowBOF() {
		return "error: bof disabled (set SC5_ALLOW_BOF=1 for authorized lab only)"
	}
	mod, _ := args["module_id"].(string)
	entry, _ := args["entry"].(string)
	if entry == "" {
		entry = "go"
	}

	var raw []byte
	if s, ok := args["object_b64"].(string); ok && s != "" {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			b, err = base64.RawURLEncoding.DecodeString(s)
		}
		if err != nil {
			return "error: object_b64 decode: " + err.Error()
		}
		raw = b
	}

	if len(raw) == 0 {
		// catalog-only run: simulate known lab modules without object bytes
		return simulateLabBOF(mod, entry)
	}

	hdr, arch, err := parseCOFF(raw)
	if err != nil {
		return "error: " + err.Error()
	}
	// Lab loader: parse + validate; optional execute only on windows research builds
	msg := fmt.Sprintf(
		"bof:loaded module=%s entry=%s arch=%s sections=%d symbols=%d size=%d os=%s",
		mod, entry, arch, hdr.NumberOfSections, hdr.NumberOfSymbols, len(raw), runtime.GOOS,
	)
	if runtime.GOOS == "windows" {
		// Safe path: do not RWX-map arbitrary COFF in default release builds.
		// Research builds may call coffExecuteWindows(raw, entry).
		msg += " exec=parse_only (use lab research build for mapped exec)"
	} else {
		msg += " exec=n/a"
	}
	// wipe payload copy
	for i := range raw {
		raw[i] = 0
	}
	return msg
}

func simulateLabBOF(mod, entry string) string {
	mod = strings.ToLower(strings.TrimSpace(mod))
	switch mod {
	case "whoami":
		u := envUser()
		return fmt.Sprintf("bof:whoami user=%s host=%s entry=%s", u, hostName(), entry)
	case "env":
		// limited safe dump
		keys := []string{"PATH", "HOME", "USER", "USERNAME", "USERPROFILE", "TEMP", "TMP"}
		var b strings.Builder
		b.WriteString("bof:env\n")
		for _, k := range keys {
			if v := getenv(k); v != "" {
				fmt.Fprintf(&b, "%s=%s\n", k, v)
			}
		}
		return b.String()
	case "dir":
		return runFileOp("file:list", map[string]any{"path": "."})
	case "net":
		return "bof:net lab_stub (ipconfig/ifconfig via shell if needed)"
	case "screenshot":
		return "bof:screenshot lab_stub (no capture in default build)"
	default:
		return fmt.Sprintf("bof:ok module=%s entry=%s (no object; catalog simulate)", mod, entry)
	}
}

func allowBOF() bool {
	return cfgAllowBOF || getenv("SC5_ALLOW_BOF") == "1"
}

func allowInject() bool {
	return cfgAllowInject || getenv("SC5_ALLOW_INJECT") == "1"
}

// set from main after loadConfig
var cfgAllowBOF bool
var cfgAllowInject bool
