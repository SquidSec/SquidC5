package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestSaWhoamiJSON(t *testing.T) {
	out := saWhoami()
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatal(err)
	}
	if m["hostname"] == nil || m["os"] == nil {
		t.Fatalf("missing fields: %v", m)
	}
}

func TestModuleList(t *testing.T) {
	out := moduleListJSON()
	if !strings.Contains(out, "sa:whoami") || !strings.Contains(out, "lat:tcp_probe") {
		t.Fatalf("unexpected catalog: %s", out)
	}
}

func TestCredGated(t *testing.T) {
	cfgAllowPostEx = false
	_ = os.Unsetenv("SC5_ALLOW_POSTEX")
	out := handleCred("cred:list", nil)
	if !strings.Contains(out, "disabled") {
		t.Fatalf("expected gate: %s", out)
	}
	cfgAllowPostEx = true
	out = handleCred("cred:list", nil)
	if !strings.Contains(out, "env_secrets") {
		t.Fatalf("expected list: %s", out)
	}
	cfgAllowPostEx = false
}

func TestLatTCPProbeLocal(t *testing.T) {
	cfgAllowPostEx = true
	// port 1 is usually closed — just ensure JSON shape
	out := latTCPProbe(map[string]any{"host": "127.0.0.1", "port": float64(1)})
	if !strings.Contains(out, "ok") {
		t.Fatalf("bad probe out: %s", out)
	}
	cfgAllowPostEx = false
}

func TestParseCOFFMinimal(t *testing.T) {
	// Minimal 20-byte COFF header (amd64)
	raw := make([]byte, 20)
	raw[0] = 0x64
	raw[1] = 0x86 // machine amd64
	raw[2] = 0
	raw[3] = 0 // 0 sections
	h, secs, arch, err := parseCOFF(raw)
	if err != nil {
		t.Fatal(err)
	}
	if arch != "amd64" || h.NumberOfSections != 0 || len(secs) != 0 {
		t.Fatalf("arch=%s secs=%v hdr=%+v", arch, secs, h)
	}
}

func TestHandlePostExDispatch(t *testing.T) {
	out, ok := handlePostEx("sa:env", nil)
	if !ok || out == "" {
		t.Fatal("sa:env failed")
	}
	out, ok = handlePostEx("not-a-module", nil)
	if ok {
		t.Fatalf("should not handle: %s", out)
	}
}

func TestInjectListGated(t *testing.T) {
	cfgAllowInject = false
	_ = os.Unsetenv("SC5_ALLOW_INJECT")
	out := handleInject("inject:list", nil)
	if !strings.Contains(out, "disabled") {
		t.Fatalf("expected gate: %s", out)
	}
	cfgAllowInject = true
	out = handleInject("inject:list", nil)
	if !strings.Contains(out, "create_remote_thread") {
		t.Fatalf("expected list: %s", out)
	}
	cfgAllowInject = false
}
