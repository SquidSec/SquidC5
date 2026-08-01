package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

func b64e(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func b64d(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

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
	pt, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	aad := []byte("sc5-aead-v1")
	ct := aead.Seal(nil, nonce, pt, aad)
	return map[string]any{
		"v":   1,
		"alg": "chacha20-poly1305",
		"n":   b64e(nonce),
		"c":   b64e(ct),
	}, nil
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
	// Prefer AAD binding; fall back to legacy empty AAD for older servers
	aad := []byte("sc5-aead-v1")
	pt, err := aead.Open(nil, n, c, aad)
	if err != nil {
		pt, err = aead.Open(nil, n, c, nil)
		if err != nil {
			return nil, err
		}
	}
	var out map[string]any
	if err := json.Unmarshal(pt, &out); err != nil {
		return nil, err
	}
	return out, nil
}
