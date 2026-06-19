using System.Net.Sockets;

namespace PhantomAgent.Transport;

public class TcpTransport : ITransport
{
    private readonly string _host;
    private readonly int _port;
    private readonly int _retryCount;
    private readonly double _retryDelay;
    private readonly int _timeout;
    private TcpClient? _client;
    private NetworkStream? _stream;
    private const int MaxMessageSize = 10 * 1024 * 1024; // 10MB

    public bool Connected { get; private set; }

    public TcpTransport(string host, int port, int retryCount = -1,
                        double retryDelay = 10.0, int timeout = 30)
    {
        _host = host;
        _port = port;
        _retryCount = retryCount;
        _retryDelay = retryDelay;
        _timeout = timeout * 1000;
    }

    public bool Connect()
    {
        int attempts = 0;
        while (_retryCount == -1 || attempts < _retryCount)
        {
            try
            {
                _client = new TcpClient();
                _client.ReceiveTimeout = _timeout;
                _client.SendTimeout = _timeout;
                _client.Connect(_host, _port);
                _stream = _client.GetStream();
                Connected = true;
                return true;
            }
            catch (SocketException)
            {
                attempts++;
                Cleanup();
                if (_retryCount != -1 && attempts >= _retryCount)
                    return false;
                Thread.Sleep((int)(_retryDelay * 1000));
            }
        }
        return false;
    }

    public bool Send(byte[] data)
    {
        if (!Connected || _stream == null) return false;
        try
        {
            // 4-byte big-endian length prefix, identical to Python struct.pack(">I", len)
            byte[] lengthPrefix = BitConverter.GetBytes((uint)data.Length);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(lengthPrefix);
            _stream.Write(lengthPrefix, 0, 4);
            _stream.Write(data, 0, data.Length);
            _stream.Flush();
            return true;
        }
        catch (Exception)
        {
            Connected = false;
            return false;
        }
    }

    public byte[]? Recv()
    {
        if (!Connected || _stream == null) return null;
        try
        {
            byte[]? lengthBuf = RecvExact(4);
            if (lengthBuf == null) return null;

            if (BitConverter.IsLittleEndian)
                Array.Reverse(lengthBuf);
            uint length = BitConverter.ToUInt32(lengthBuf, 0);

            if (length > MaxMessageSize)
                return null;

            return RecvExact((int)length);
        }
        catch (Exception)
        {
            Connected = false;
            return null;
        }
    }

    private byte[]? RecvExact(int n)
    {
        byte[] buf = new byte[n];
        int offset = 0;
        while (offset < n)
        {
            int read = _stream!.Read(buf, offset, n - offset);
            if (read == 0)
            {
                Connected = false;
                return null;
            }
            offset += read;
        }
        return buf;
    }

    public void Disconnect()
    {
        Cleanup();
    }

    private void Cleanup()
    {
        Connected = false;
        try { _stream?.Close(); } catch { }
        try { _client?.Close(); } catch { }
        _stream = null;
        _client = null;
    }
}
