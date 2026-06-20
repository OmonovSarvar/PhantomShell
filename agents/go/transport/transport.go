package transport

// Transport defines the interface for C2 communication channels.
type Transport interface {
	Connect() error
	Send(data []byte) error
	Recv() ([]byte, error)
	Disconnect()
	Connected() bool
}
