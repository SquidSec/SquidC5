package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

type httpChannel struct {
	client *http.Client
	url    string
	psk    string
}

func newHTTPChannel(url, psk string) *httpChannel {
	return &httpChannel{
		client: &http.Client{Timeout: 45 * time.Second},
		url:    url,
		psk:    psk,
	}
}

func (h *httpChannel) checkin(payload map[string]any) (map[string]any, error) {
	body, err := seal(h.psk, payload)
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(body)
	resp, err := h.client.Post(h.url, "application/json", bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, errStatus(resp.StatusCode)
	}
	var env map[string]any
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, err
	}
	return openEnv(h.psk, env)
}

func (h *httpChannel) result(taskID, out, status string) error {
	done, err := seal(h.psk, map[string]any{
		"task_id": taskID,
		"result":  out,
		"status":  status,
	})
	if err != nil {
		return err
	}
	dr, _ := json.Marshal(done)
	r2, err2 := h.client.Post(h.url+"/result", "application/json", bytes.NewReader(dr))
	if err2 != nil {
		return err2
	}
	r2.Body.Close()
	return nil
}

type statusErr int

func (e statusErr) Error() string { return "http status" }
func errStatus(code int) error    { return statusErr(code) }
