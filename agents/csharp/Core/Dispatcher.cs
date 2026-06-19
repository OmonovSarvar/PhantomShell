using System.Text.Json;

namespace PhantomAgent.Core;

public class Dispatcher
{
    private readonly Dictionary<string, CommandEntry> _commands = new();
    private readonly List<string> _modules = new();

    public List<string> Modules => _modules;

    public void RegisterModule(string moduleName, Dictionary<string, Func<Dictionary<string, JsonElement>?, object>> handlers)
    {
        foreach (var (cmdName, handler) in handlers)
        {
            _commands[cmdName] = new CommandEntry
            {
                Handler = handler,
                Module = moduleName,
            };
        }
        if (!_modules.Contains(moduleName))
            _modules.Add(moduleName);
    }

    public bool HasCommand(string command) => _commands.ContainsKey(command);

    public Dictionary<string, object> Dispatch(string command, Dictionary<string, JsonElement>? args)
    {
        if (!_commands.TryGetValue(command, out var entry))
            return Error(1, $"Unknown command: {command}");

        try
        {
            object result = entry.Handler(args);
            if (result is Dictionary<string, object> dict)
                return new Dictionary<string, object> { ["status"] = "ok", ["data"] = dict };
            return new Dictionary<string, object> { ["status"] = "ok", ["output"] = result?.ToString() ?? "" };
        }
        catch (ArgumentException ex)
        {
            return Error(2, $"Invalid arguments: {ex.Message}");
        }
        catch (UnauthorizedAccessException ex)
        {
            return Error(3, $"Permission denied: {ex.Message}");
        }
        catch (TimeoutException ex)
        {
            return Error(4, $"Timeout: {ex.Message}");
        }
        catch (Exception ex)
        {
            return Error(5, $"Execution failed: {ex.Message}");
        }
    }

    public Dictionary<string, string> ListCommands()
    {
        var result = new Dictionary<string, string>();
        foreach (var (name, entry) in _commands)
            result[name] = entry.Module;
        return result;
    }

    private static Dictionary<string, object> Error(int code, string message)
    {
        return new Dictionary<string, object>
        {
            ["status"] = "error",
            ["error_code"] = code,
            ["output"] = message,
        };
    }

    private class CommandEntry
    {
        public required Func<Dictionary<string, JsonElement>?, object> Handler;
        public required string Module;
    }
}
