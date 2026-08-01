package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// JobManager tracks concurrent / long-running tasks (I1).
type JobManager struct {
	mu      sync.Mutex
	jobs    map[string]*Job
	cwd     string
	seq     uint64
	maxJobs int
}

type Job struct {
	ID        string
	Command   string
	Status    string // running|completed|failed|killed
	Output    string
	Started   time.Time
	Finished  time.Time
	cancel    chan struct{}
	cmd       *exec.Cmd
}

func newJobManager() *JobManager {
	cwd, _ := os.Getwd()
	return &JobManager{
		jobs:    map[string]*Job{},
		cwd:     cwd,
		maxJobs: 8,
	}
}

func (m *JobManager) list() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var b strings.Builder
	for _, j := range m.jobs {
		fmt.Fprintf(&b, "%s\t%s\t%s\t%v\n", j.ID, j.Status, truncate(j.Command, 60), j.Started.Format(time.RFC3339))
	}
	if b.Len() == 0 {
		return "(no jobs)\n"
	}
	return b.String()
}

func (m *JobManager) get(id string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	if !ok {
		return "error: job not found"
	}
	return fmt.Sprintf("id=%s status=%s cmd=%s\n%s", j.ID, j.Status, j.Command, j.Output)
}

func (m *JobManager) kill(id string) string {
	m.mu.Lock()
	j, ok := m.jobs[id]
	m.mu.Unlock()
	if !ok {
		return "error: job not found"
	}
	select {
	case <-j.cancel:
	default:
		close(j.cancel)
	}
	if j.cmd != nil && j.cmd.Process != nil {
		_ = j.cmd.Process.Kill()
	}
	m.mu.Lock()
	j.Status = "killed"
	j.Finished = time.Now()
	m.mu.Unlock()
	return "ok"
}

func (m *JobManager) start(command string) string {
	m.mu.Lock()
	running := 0
	for _, j := range m.jobs {
		if j.Status == "running" {
			running++
		}
	}
	if running >= m.maxJobs {
		m.mu.Unlock()
		return "error: max concurrent jobs"
	}
	id := fmt.Sprintf("job_%d", atomic.AddUint64(&m.seq, 1))
	j := &Job{
		ID:      id,
		Command: command,
		Status:  "running",
		Started: time.Now(),
		cancel:  make(chan struct{}),
	}
	m.jobs[id] = j
	cwd := m.cwd
	m.mu.Unlock()

	go func() {
		var c *exec.Cmd
		if runtime.GOOS == "windows" {
			c = exec.Command("cmd", "/C", command)
		} else {
			c = exec.Command("sh", "-c", command)
		}
		c.Dir = cwd
		j.cmd = c
		done := make(chan struct{})
		var out []byte
		var err error
		go func() {
			out, err = c.CombinedOutput()
			close(done)
		}()
		select {
		case <-j.cancel:
			if c.Process != nil {
				_ = c.Process.Kill()
			}
			<-done
			m.mu.Lock()
			j.Status = "killed"
			j.Output = string(out)
			j.Finished = time.Now()
			m.mu.Unlock()
		case <-done:
			m.mu.Lock()
			if err != nil {
				j.Status = "failed"
				j.Output = string(out) + "\n" + err.Error()
			} else {
				j.Status = "completed"
				j.Output = string(out)
			}
			j.Finished = time.Now()
			m.mu.Unlock()
		}
	}()
	return id
}

func (m *JobManager) setCwd(path string) string {
	if path == "" {
		return "error: path required"
	}
	if err := os.Chdir(path); err != nil {
		return err.Error()
	}
	cwd, _ := os.Getwd()
	m.mu.Lock()
	m.cwd = cwd
	m.mu.Unlock()
	return cwd
}

func (m *JobManager) getCwd() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cwd
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func listProcesses() string {
	var c *exec.Cmd
	if runtime.GOOS == "windows" {
		c = exec.Command("cmd", "/C", "tasklist")
	} else {
		c = exec.Command("sh", "-c", "ps aux 2>/dev/null || ps -ef")
	}
	out, err := c.CombinedOutput()
	if err != nil {
		return string(out) + "\n" + err.Error()
	}
	return string(out)
}

func killPID(pid int) string {
	if pid <= 0 {
		return "error: invalid pid"
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err.Error()
	}
	if err := proc.Kill(); err != nil {
		return err.Error()
	}
	return "ok"
}
