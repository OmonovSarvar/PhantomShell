package transport

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	maxMessageSize  = 10 * 1024 * 1024 // 10MB
	connectTimeout  = 10 * time.Second
	defaultRetries  = 3
	defaultRetryDel = 5 * time.Second
)

// TCPTransport implements length-prefixed TCP communication.
type TCPTransport struct {
	host       string
	port       int
	conn       net.Conn
	mu         sync.Mutex
	retries    int
	retryDelay time.Duration
	connected  bool
}

func NewTCPTransport(host string, port int) *TCPTransport {
	return &TCPTransport{
		host:       host,
		port:       port,
		retries:    defaultRetries,
		retryDelay: defaultRetryDel,
	}
}

func (t *TCPTransport) Connect() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	addr := fmt.Sprintf("%s:%d", t.host, t.port)
	dialer := net.Dialer{Timeout: connectTimeout}

	var lastErr error
	for i := 0; i <= t.retries; i++ {
		conn, err := dialer.Dial("tcp", addr)
		if err == nil {
			t.conn = conn
			t.connected = true
			return nil
		}
		lastErr = err
		if i < t.retries {
			time.Sleep(t.retryDelay)
		}
	}
	return fmt.Errorf("tcp connect failed after %d retries: %w", t.retries, lastErr)
}

// Send writes a 4-byte big-endian length prefix followed by the payload.
func (t *TCPTransport) Send(data []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.connected || t.conn == nil {
		return fmt.Errorf("not connected")
	}

	if len(data) > maxMessageSize {
		return fmt.Errorf("message too large: %d > %d", len(data), maxMessageSize)
	}

	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(data)))

	if _, err := t.conn.Write(header); err != nil {
		t.connected = false
		return fmt.Errorf("send header: %w", err)
	}
	if _, err := t.conn.Write(data); err != nil {
		t.connected = false
		return fmt.Errorf("send payload: %w", err)
	}
	return nil
}

// Recv reads a 4-byte big-endian length prefix then reads that many bytes.
func (t *TCPTransport) Recv() ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.connected || t.conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(t.conn, header); err != nil {
		t.connected = false
		return nil, fmt.Errorf("recv header: %w", err)
	}

	length := binary.BigEndian.Uint32(header)
	if length > maxMessageSize {
		t.connected = false
		return nil, fmt.Errorf("message too large: %d", length)
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(t.conn, buf); err != nil {
		t.connected = false
		return nil, fmt.Errorf("recv payload: %w", err)
	}
	return buf, nil
}

func (t *TCPTransport) Disconnect() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn != nil {
		t.conn.Close()
		t.conn = nil
	}
	t.connected = false
}

func (t *TCPTransport) Connected() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.connected
}
