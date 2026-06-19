using System.Globalization;

namespace PhantomAgent.Core;

public class Scheduler
{
    public double SleepTime { get; private set; }
    public double JitterPercent { get; private set; }
    private DateTime? _killDate;

    private static readonly string[] DateFormats =
    {
        "yyyy-MM-ddTHH:mm:ss",
        "yyyy-MM-dd HH:mm:ss",
        "yyyy-MM-dd",
    };

    public Scheduler(double sleepTime = 5.0, double jitterPercent = 20.0, string? killDate = null)
    {
        SleepTime = sleepTime;
        JitterPercent = jitterPercent;
        _killDate = ParseDate(killDate);
    }

    public void Wait()
    {
        double jitter = SleepTime * (JitterPercent / 100.0);
        double actual = SleepTime + (Random.Shared.NextDouble() * 2 - 1) * jitter;
        actual = Math.Max(0.1, actual);
        Thread.Sleep((int)(actual * 1000));
    }

    public bool CheckKillDate()
    {
        if (_killDate == null) return false;
        return DateTime.UtcNow >= _killDate.Value;
    }

    public void UpdateConfig(double? sleep = null, double? jitter = null, string? killDate = null)
    {
        if (sleep.HasValue)
            SleepTime = Math.Max(0.1, sleep.Value);
        if (jitter.HasValue)
            JitterPercent = Math.Clamp(jitter.Value, 0.0, 100.0);
        if (killDate != null)
            _killDate = ParseDate(killDate);
    }

    private static DateTime? ParseDate(string? dateStr)
    {
        if (string.IsNullOrEmpty(dateStr)) return null;
        if (DateTime.TryParseExact(dateStr, DateFormats, CultureInfo.InvariantCulture,
                                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                                    out var dt))
            return dt;
        return null;
    }
}
