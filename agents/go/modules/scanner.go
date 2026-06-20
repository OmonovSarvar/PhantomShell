package modules

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OmonovSarvar/PhantomShell/agents/go/core"
)

const (
	defaultScanConcurrency = 500
	defaultScanTimeout     = 2 * time.Second
	bannerReadSize         = 1024
)

func RegisterScanner(d *core.Dispatcher) {
	d.Register("portscan", handlePortScan)
	d.Register("subnetscan", handleSubnetScan)
}

type scanResult struct {
	Port    int    `json:"port"`
	State   string `json:"state"`
	Banner  string `json:"banner,omitempty"`
	Service string `json:"service,omitempty"`
}

func handlePortScan(args map[string]interface{}) map[string]interface{} {
	host := getString(args, "host")
	portsStr := getString(args, "ports")
	if host == "" {
		return map[string]interface{}{"status": "error", "error": "host required"}
	}
	if portsStr == "" {
		portsStr = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080,8443"
	}

	concurrency := getInt(args, "concurrency", defaultScanConcurrency)
	timeout := time.Duration(getInt(args, "timeout", 2000)) * time.Millisecond
	grabBanner := false
	if v, ok := args["banner"]; ok {
		if b, ok := v.(bool); ok {
			grabBanner = b
		}
	}

	ports, err := parsePorts(portsStr)
	if err != nil {
		return map[string]interface{}{"status": "error", "error": err.Error()}
	}

	results := scanPorts(host, ports, concurrency, timeout, grabBanner)

	sort.Slice(results, func(i, j int) bool {
		return results[i]["port"].(int) < results[j]["port"].(int)
	})

	return map[string]interface{}{
		"status": "success",
		"host":   host,
		"open":   len(results),
		"data":   results,
	}
}

func handleSubnetScan(args map[string]interface{}) map[string]interface{} {
	cidr := getString(args, "cidr")
	portsStr := getString(args, "ports")
	if cidr == "" {
		return map[string]interface{}{"status": "error", "error": "cidr required"}
	}
	if portsStr == "" {
		portsStr = "22,80,443,445,3389"
	}

	concurrency := getInt(args, "concurrency", defaultScanConcurrency)
	timeout := time.Duration(getInt(args, "timeout", 1000)) * time.Millisecond

	hosts, err := expandCIDR(cidr)
	if err != nil {
		return map[string]interface{}{"status": "error", "error": err.Error()}
	}

	ports, err := parsePorts(portsStr)
	if err != nil {
		return map[string]interface{}{"status": "error", "error": err.Error()}
	}

	var allResults []map[string]interface{}
	for _, host := range hosts {
		results := scanPorts(host, ports, concurrency, timeout, false)
		if len(results) > 0 {
			allResults = append(allResults, map[string]interface{}{
				"host":  host,
				"ports": results,
			})
		}
	}

	return map[string]interface{}{
		"status":    "success",
		"cidr":      cidr,
		"alive":     len(allResults),
		"total":     len(hosts),
		"data":      allResults,
	}
}

func scanPorts(host string, ports []int, concurrency int, timeout time.Duration, grabBanner bool) []map[string]interface{} {
	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var results []map[string]interface{}
	var wg sync.WaitGroup

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			addr := fmt.Sprintf("%s:%d", host, p)
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err != nil {
				return
			}
			defer conn.Close()

			result := map[string]interface{}{
				"port":  p,
				"state": "open",
			}

			if grabBanner {
				conn.SetReadDeadline(time.Now().Add(timeout))
				buf := make([]byte, bannerReadSize)
				n, _ := conn.Read(buf)
				if n > 0 {
					result["banner"] = strings.TrimSpace(string(buf[:n]))
				}
			}

			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(port)
	}
	wg.Wait()
	return results
}

// parsePorts handles "22,80,443", "1-1024", and mixed "22,80,100-200"
func parsePorts(s string) ([]int, error) {
	var ports []int
	parts := strings.Split(s, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.SplitN(part, "-", 2)
			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid port range start: %s", rangeParts[0])
			}
			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid port range end: %s", rangeParts[1])
			}
			if start > end || start < 1 || end > 65535 {
				return nil, fmt.Errorf("invalid port range: %d-%d", start, end)
			}
			for p := start; p <= end; p++ {
				ports = append(ports, p)
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("port out of range: %d", p)
			}
			ports = append(ports, p)
		}
	}
	return ports, nil
}

// expandCIDR returns all host addresses in a CIDR block.
func expandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	var hosts []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		hosts = append(hosts, ip.String())
	}

	// Remove network and broadcast for /24 and larger
	if len(hosts) > 2 {
		hosts = hosts[1 : len(hosts)-1]
	}
	return hosts, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
