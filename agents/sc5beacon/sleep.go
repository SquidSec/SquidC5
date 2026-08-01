package main

import (
	"crypto/rand"
	"os"
	"runtime"
	"time"
)

// maskedSleep wipes sensitive buffers then sleeps with optional timer path.
// SC5_SLEEP_MASK=jitter|timer|ekko (ekko only meaningful on windows build tags later)
func maskedSleep(base float64, jitterPct float64, secrets ...*[]byte) {
	mode := os.Getenv("SC5_SLEEP_MASK")
	if mode == "" {
		mode = "jitter"
	}
	// Wipe sensitive material before idle
	for _, p := range secrets {
		if p != nil && *p != nil {
			for i := range *p {
				(*p)[i] = 0
			}
			// fill with random then zero again (simple mask pattern)
			_, _ = rand.Read(*p)
			for i := range *p {
				(*p)[i] = 0
			}
		}
	}
	runtime.GC()

	switch mode {
	case "timer":
		// Prefer timer channel over plain Sleep
		pct := jitterPct / 100.0
		if pct < 0 {
			pct = 0
		}
		if pct > 1 {
			pct = 1
		}
		delta := base * pct
		d := base + (float64(time.Now().UnixNano()%1000)/1000.0*2-1)*delta
		if d < 0.1 {
			d = 0.1
		}
		t := time.NewTimer(time.Duration(d * float64(time.Second)))
		<-t.C
	case "ekko":
		// Portable stand-in: timer wait + buffer wipe (full ROP/timer encrypt is Win-only research)
		pct := jitterPct / 100.0
		if pct < 0 {
			pct = 0
		}
		if pct > 1 {
			pct = 1
		}
		delta := base * pct
		d := base + (float64(time.Now().UnixNano()%1000)/1000.0*2-1)*delta
		if d < 0.1 {
			d = 0.1
		}
		t := time.NewTimer(time.Duration(d * float64(time.Second)))
		<-t.C
	default:
		sleepJitter(base, jitterPct)
	}
}
