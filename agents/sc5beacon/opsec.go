package main

import (
	"crypto/rand"
	"os"
	"runtime"
	"time"
	"unsafe"
)

// I5: lightweight string/buffer OPSEC helpers.

func xorObfuscate(data []byte, key byte) {
	for i := range data {
		data[i] ^= key
	}
}

// secureWipe overwrites then random-fills then zeroes.
func secureWipe(b []byte) {
	if len(b) == 0 {
		return
	}
	for i := range b {
		b[i] = 0
	}
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = 0
	}
}

// sleepWithMask uses config sleep_mask and wipes secret buffers.
func sleepWithMask(cfg AgentConfig, secrets ...[]byte) {
	for i := range secrets {
		secureWipe(secrets[i])
	}
	// pin mask mode into env for maskedSleep if not set
	if cfg.SleepMask != "" && os.Getenv("SC5_SLEEP_MASK") == "" {
		_ = os.Setenv("SC5_SLEEP_MASK", cfg.SleepMask)
	}
	// heap pressure drop
	runtime.GC()
	maskedSleep(cfg.Sleep, cfg.Jitter)
}

// decoyJitter adds tiny extra delay (decoy timing) without changing base sleep much.
func decoyJitter() {
	n := time.Duration(time.Now().UnixNano()%50) * time.Millisecond
	time.Sleep(n)
}

// hideString stores a short string xor'd; recover with revealString.
func hideString(s string, key byte) []byte {
	b := make([]byte, len(s))
	copy(b, s)
	xorObfuscate(b, key)
	return b
}

func revealString(b []byte, key byte) string {
	tmp := make([]byte, len(b))
	copy(tmp, b)
	xorObfuscate(tmp, key)
	s := string(tmp)
	secureWipe(tmp)
	return s
}

// prevent compiler from optimizing away wipes
var sink byte

func touch(b []byte) {
	if len(b) > 0 {
		sink ^= b[0]
	}
}

// keepReference defeats some dead-store elimination on wipe paths.
func keepReference(p *[]byte) {
	if p != nil && *p != nil {
		_ = unsafe.Sizeof(*p)
	}
}
