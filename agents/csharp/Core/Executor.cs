using System.Diagnostics;

namespace PhantomAgent.Core;

public class Executor
{
    public string Cwd { get; private set; }

    public Executor()
    {
        Cwd = Directory.GetCurrentDirectory();
    }

    public (string stdout, string stderr, int exitCode) Execute(string command, int timeout = 30, bool usePowerShell = false)
    {
        try
        {
            string fileName;
            string arguments;
            if (usePowerShell)
            {
                fileName = "powershell.exe";
                arguments = $"-NoProfile -NonInteractive -Command \"{command.Replace("\"", "\\\"")}\"";
            }
            else
            {
                fileName = "cmd.exe";
                arguments = $"/c {command}";
            }

            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                WorkingDirectory = Cwd,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };

            using var proc = Process.Start(psi);
            if (proc == null)
                return ("", "Failed to start process", -1);

            // Read both streams to avoid deadlocks
            var stdoutTask = proc.StandardOutput.ReadToEndAsync();
            var stderrTask = proc.StandardError.ReadToEndAsync();

            if (!proc.WaitForExit(timeout * 1000))
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                return ("", "Command timed out", -1);
            }

            return (stdoutTask.GetAwaiter().GetResult(),
                    stderrTask.GetAwaiter().GetResult(),
                    proc.ExitCode);
        }
        catch (Exception ex)
        {
            return ("", ex.Message, -1);
        }
    }

    public (string path, bool ok) Cd(string path)
    {
        string target = Path.IsPathRooted(path) ? path : Path.Combine(Cwd, path);
        target = Path.GetFullPath(target);
        if (Directory.Exists(target))
        {
            Cwd = target;
            return (target, true);
        }
        return ($"Directory not found: {path}", false);
    }
}
