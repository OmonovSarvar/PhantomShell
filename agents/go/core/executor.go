package core

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"sync"
	"time"
)

const defaultCmdTimeout = 30 * time.Second

// Executor runs shell commands with working directory tracking and timeouts.
type Executor struct {
	mu  sync.Mutex
	cwd string
}

func NewExecutor() *Executor {
	return &Executor{cwd: "."}
}

// SetCwd updates the working directory for subsequent commands.
func (e *Executor) SetCwd(dir string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cwd = dir
}

// Cwd returns the current working directory.
func (e *Executor) Cwd() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cwd
}

// Run executes a shell command and returns stdout, stderr, and exit code.
func (e *Executor) Run(command string, timeout time.Duration) (stdout, stderr string, exitCode int) {
	if timeout == 0 {
		timeout = defaultCmdTimeout
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/c", command)
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", command)
	}

	e.mu.Lock()
	cmd.Dir = e.cwd
	e.mu.Unlock()

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()
	stdout = outBuf.String()
	stderr = errBuf.String()

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			stderr = fmt.Sprintf("command timed out after %s\n%s", timeout, stderr)
			exitCode = -1
			return
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
			stderr = fmt.Sprintf("%s\n%s", err.Error(), stderr)
		}
		return
	}
	exitCode = 0
	return
}
