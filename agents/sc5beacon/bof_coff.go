package main

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"runtime"
	"strings"
)

// COFF/BOF host (I3/I7). Default builds parse + validate only.
// Mapped execute requires SC5_ALLOW_BOF=1 and research build path.

type coffHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type coffSection struct {
	Name             string
	VirtualSize      uint32
	VirtualAddress   uint32
	SizeOfRawData    uint32
	PointerToRawData uint32
	Characteristics  uint32
}

func parseCOFF(data []byte) (*coffHeader, []coffSection, string, error) {
	if len(data) < 20 {
		return nil, nil, "", fmt.Errorf("COFF too small")
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
	sections := make([]coffSection, 0, h.NumberOfSections)
	off := 20 + int(h.SizeOfOptionalHeader)
	for i := 0; i < int(h.NumberOfSections); i++ {
		if off+40 > len(data) {
			break
		}
		nameBytes := data[off : off+8]
		name := strings.TrimRight(string(nameBytes), "\x00")
		sec := coffSection{
			Name:             name,
			VirtualSize:      binary.LittleEndian.Uint32(data[off+8 : off+12]),
			VirtualAddress:   binary.LittleEndian.Uint32(data[off+12 : off+16]),
			SizeOfRawData:    binary.LittleEndian.Uint32(data[off+16 : off+20]),
			PointerToRawData: binary.LittleEndian.Uint32(data[off+20 : off+24]),
			Characteristics:  binary.LittleEndian.Uint32(data[off+36 : off+40]),
		}
		sections = append(sections, sec)
		off += 40
	}
	return h, sections, arch, nil
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
	bofArgs, _ := args["args"].(string)
	if bofArgs == "" {
		if a, ok := args["bof_args"].(string); ok {
			bofArgs = a
		}
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
		return simulateLabBOF(mod, entry)
	}

	hdr, sections, arch, err := parseCOFF(raw)
	if err != nil {
		return "error: " + err.Error()
	}
	secNames := make([]string, 0, len(sections))
	var textSize uint32
	for _, s := range sections {
		secNames = append(secNames, s.Name)
		if s.Name == ".text" || s.Name == "text" {
			textSize = s.SizeOfRawData
		}
	}
	msg := fmt.Sprintf(
		"bof:loaded module=%s entry=%s arch=%s sections=%d symbols=%d size=%d text=%d secs=[%s] args_len=%d os=%s",
		mod, entry, arch, hdr.NumberOfSections, hdr.NumberOfSymbols, len(raw), textSize,
		strings.Join(secNames, ","), len(bofArgs), runtime.GOOS,
	)
	// Research path: coffMapExecute is a no-op stub in default builds.
	if runtime.GOOS == "windows" && getenv("SC5_BOF_EXECUTE") == "1" {
		msg += " " + coffMapExecute(raw, entry, bofArgs)
	} else if runtime.GOOS == "windows" {
		msg += " exec=parse_only (set SC5_BOF_EXECUTE=1 in research build for mapped exec)"
	} else {
		msg += " exec=n/a"
	}
	for i := range raw {
		raw[i] = 0
	}
	return msg
}

// coffMapExecute: research-only hook. Default release is parse/validate only.
func coffMapExecute(raw []byte, entry, args string) string {
	// Intentionally does not RWX-map or jump — keeps default binary safe.
	// Research forks may replace this with VirtualAlloc + reloc + entry call.
	_ = raw
	_ = entry
	_ = args
	return "exec=research_stub_no_map"
}

func simulateLabBOF(mod, entry string) string {
	mod = strings.ToLower(strings.TrimSpace(mod))
	switch mod {
	case "whoami":
		return saWhoami()
	case "env":
		return saEnv(nil)
	case "dir":
		return runFileOp("file:list", map[string]any{"path": "."})
	case "net":
		return saNetIfaces()
	case "screenshot":
		return `{"module":"screenshot","status":"lab_stub","note":"no capture in default build"}`
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

var cfgAllowBOF bool
var cfgAllowInject bool
