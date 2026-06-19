namespace PhantomAgent.Transport;

public interface ITransport
{
    bool Connected { get; }
    bool Connect();
    bool Send(byte[] data);
    byte[]? Recv();
    void Disconnect();
}
