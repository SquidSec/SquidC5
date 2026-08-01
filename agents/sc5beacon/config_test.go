package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

func TestLoadConfigFromB64(t *testing.T) {
	cfg := AgentConfig{
		URL:     "https://c2.lab:8443/api/v1/implant/beacon",
		PSK:     "test-psk-not-secret",
		Sleep:   3,
		Jitter:  10,
		Channel: "http",
	}
	raw, _ := json.Marshal(cfg)
	os.Setenv("SC5_CONFIG_B64", base64.StdEncoding.EncodeToString(raw))
	os.Unsetenv("SC5_URL")
	os.Unsetenv("SC5_PSK")
	defer func() {
		os.Unsetenv("SC5_CONFIG_B64")
	}()
	got, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if got.URL != cfg.URL || got.PSK != cfg.PSK {
		t.Fatalf("got %+v", got)
	}
	if got.Sleep != 3 {
		t.Fatalf("sleep %v", got.Sleep)
	}
}

func TestHTTPToWS(t *testing.T) {
	u := httpToWS("https://c2:8443/api/v1/implant/beacon")
	if u != "wss://c2:8443/ws/v1/beacon" {
		t.Fatal(u)
	}
}

func TestCOFFParse(t *testing.T) {
	// amd64 header
	hdr := []byte{
		0x64, 0x86, // machine
		0x01, 0x00, // sections
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0,
		0, 0,
	}
	h, arch, err := parseCOFF(hdr)
	if err != nil {
		t.Fatal(err)
	}
	if arch != "amd64" || h.NumberOfSections != 1 {
		t.Fatalf("%s %+v", arch, h)
	}
}

func TestSimulateBOFWhoami(t *testing.T) {
	cfgAllowBOF = true
	out := handleBofRun(map[string]any{"module_id": "whoami"})
	if out == "" || out[:3] == "err" {
		t.Fatal(out)
	}
}
