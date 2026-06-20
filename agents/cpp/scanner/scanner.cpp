/*
 * PhantomScan v5.2 — Port Scanner
 * Part of PhantomShell v5.2 Agent Framework
 *
 * AUTHORIZED USE ONLY. This tool is provided for legitimate penetration
 * testing and security assessments with explicit written authorization.
 * Unauthorized scanning of networks or systems you do not own or have
 * permission to test is illegal and unethical. The authors assume no
 * liability for misuse of this software.
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <queue>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <chrono>

#pragma comment(lib, "ws2_32")

#include "../common/utils.h"

// ---------------------------------------------------------------------------
// Structures
// ---------------------------------------------------------------------------

struct ScanConfig {
    std::string host;
    std::vector<uint16_t> ports;
    int concurrency = 500;
    int timeoutMs   = 1000;
    bool bannerGrab = false;
    std::string outputFile; // empty = stdout only
};

struct ScanResult {
    std::string host;
    uint16_t    port;
    bool        open;
    std::string banner;
    std::string timestamp;
    int         responseTimeMs;
};

// ---------------------------------------------------------------------------
// Port parsing — supports "22,80,100-200,443,8000-8100"
// ---------------------------------------------------------------------------

std::vector<uint16_t> ParsePorts(const std::string& portSpec) {
    std::vector<uint16_t> ports;
    std::stringstream ss(portSpec);
    std::string token;

    while (std::getline(ss, token, ',')) {
        // Trim whitespace
        token.erase(0, token.find_first_not_of(' '));
        token.erase(token.find_last_not_of(' ') + 1);

        auto dash = token.find('-');
        if (dash != std::string::npos) {
            // Range: "100-200"
            int start = std::stoi(token.substr(0, dash));
            int end   = std::stoi(token.substr(dash + 1));
            if (start < 1)     start = 1;
            if (end   > 65535) end   = 65535;
            if (start > end)   std::swap(start, end);
            for (int p = start; p <= end; ++p)
                ports.push_back(static_cast<uint16_t>(p));
        } else {
            // Single port
            int p = std::stoi(token);
            if (p >= 1 && p <= 65535)
                ports.push_back(static_cast<uint16_t>(p));
        }
    }

    // Remove duplicates
    std::sort(ports.begin(), ports.end());
    ports.erase(std::unique(ports.begin(), ports.end()), ports.end());
    return ports;
}

// ---------------------------------------------------------------------------
// Get current timestamp as ISO-ish string
// ---------------------------------------------------------------------------

static std::string GetCurrentTimestamp() {
#ifdef PHANTOMSHELL_UTILS
    return PhantomUtils::GetTimestamp();
#else
    auto now = std::chrono::system_clock::now();
    auto tt  = std::chrono::system_clock::to_time_t(now);
    struct tm tmBuf;
    gmtime_s(&tmBuf, &tt);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tmBuf);
    return std::string(buf);
#endif
}

// ---------------------------------------------------------------------------
// Banner grabbing — read up to 1024 bytes, strip non-printables
// ---------------------------------------------------------------------------

std::string GrabBanner(SOCKET sock, int timeoutMs) {
    // Set receive timeout
    DWORD tv = static_cast<DWORD>(timeoutMs);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&tv), sizeof(tv));

    char buf[1024] = {};
    int n = recv(sock, buf, sizeof(buf) - 1, 0);
    if (n <= 0)
        return "";

    buf[n] = '\0';

    // Replace non-printable characters with '.'
    std::string banner(buf, n);
    for (auto& ch : banner) {
        if (ch < 0x20 || ch > 0x7E)
            ch = '.';
    }
    return banner;
}

// ---------------------------------------------------------------------------
// Scan a single port (non-blocking connect + select)
// ---------------------------------------------------------------------------

ScanResult ScanPort(const std::string& host, uint16_t port,
                    int timeoutMs, bool bannerGrab) {
    ScanResult result;
    result.host           = host;
    result.port           = port;
    result.open           = false;
    result.responseTimeMs = 0;
    result.timestamp      = GetCurrentTimestamp();

    // Resolve host
    struct addrinfo hints = {}, *addrResult = nullptr;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    std::string portStr = std::to_string(port);
    if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &addrResult) != 0)
        return result;

    SOCKET sock = socket(addrResult->ai_family, addrResult->ai_socktype,
                         addrResult->ai_protocol);
    if (sock == INVALID_SOCKET) {
        freeaddrinfo(addrResult);
        return result;
    }

    // Set non-blocking mode
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);

    auto t0 = std::chrono::high_resolution_clock::now();

    // Initiate connection (returns SOCKET_ERROR with WSAEWOULDBLOCK)
    int cr = connect(sock, addrResult->ai_addr,
                     static_cast<int>(addrResult->ai_addrlen));

    if (cr == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {
        closesocket(sock);
        freeaddrinfo(addrResult);
        return result;
    }

    // Wait for connection via select()
    fd_set writeSet, exceptSet;
    FD_ZERO(&writeSet);
    FD_ZERO(&exceptSet);
    FD_SET(sock, &writeSet);
    FD_SET(sock, &exceptSet);

    struct timeval tv;
    tv.tv_sec  = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;

    int sel = select(0, nullptr, &writeSet, &exceptSet, &tv);

    auto t1 = std::chrono::high_resolution_clock::now();
    result.responseTimeMs = static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());

    if (sel > 0 && FD_ISSET(sock, &writeSet) && !FD_ISSET(sock, &exceptSet)) {
        // Verify the connection actually succeeded
        int optVal = 0;
        int optLen = sizeof(optVal);
        getsockopt(sock, SOL_SOCKET, SO_ERROR,
                   reinterpret_cast<char*>(&optVal), &optLen);

        if (optVal == 0) {
            result.open = true;

            // Switch back to blocking for banner grab
            if (bannerGrab) {
                u_long blocking = 0;
                ioctlsocket(sock, FIONBIO, &blocking);
                result.banner = GrabBanner(sock, timeoutMs);
            }
        }
    }

    closesocket(sock);
    freeaddrinfo(addrResult);
    return result;
}

// ---------------------------------------------------------------------------
// Thread pool scanner
// ---------------------------------------------------------------------------

std::vector<ScanResult> RunScan(const ScanConfig& config) {
    // Build thread-safe port queue
    std::queue<uint16_t> portQueue;
    std::mutex queueMtx;
    for (auto p : config.ports)
        portQueue.push(p);

    std::vector<ScanResult> results;
    std::mutex resultsMtx;

    int threadCount = std::min(config.concurrency,
                               static_cast<int>(config.ports.size()));

    auto workerFn = [&]() {
        while (true) {
            uint16_t port;
            {
                std::lock_guard<std::mutex> lk(queueMtx);
                if (portQueue.empty())
                    return;
                port = portQueue.front();
                portQueue.pop();
            }

            ScanResult r = ScanPort(config.host, port,
                                    config.timeoutMs, config.bannerGrab);
            {
                std::lock_guard<std::mutex> lk(resultsMtx);
                results.push_back(std::move(r));
            }
        }
    };

    // Spawn worker threads
    std::vector<std::thread> threads;
    threads.reserve(threadCount);
    for (int i = 0; i < threadCount; ++i)
        threads.emplace_back(workerFn);

    // Wait for completion
    for (auto& t : threads)
        t.join();

    // Sort results by port number
    std::sort(results.begin(), results.end(),
              [](const ScanResult& a, const ScanResult& b) {
                  return a.port < b.port;
              });

    return results;
}

// ---------------------------------------------------------------------------
// JSON output — manual build, no external library
// ---------------------------------------------------------------------------

static std::string EscapeJson(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:   out += c;      break;
        }
    }
    return out;
}

std::string ResultsToJson(const std::vector<ScanResult>& results,
                           const ScanConfig& config) {
    int openCount = 0;
    for (auto& r : results)
        if (r.open) ++openCount;

    std::ostringstream js;
    js << "{\n";
    js << "  \"scan\": {\n";
    js << "    \"host\": \"" << EscapeJson(config.host) << "\",\n";
    js << "    \"timestamp\": \"" << GetCurrentTimestamp() << "\",\n";
    js << "    \"total_ports\": " << results.size() << ",\n";
    js << "    \"open_ports\": " << openCount << "\n";
    js << "  },\n";
    js << "  \"results\": [\n";

    bool first = true;
    for (auto& r : results) {
        if (!r.open) continue;
        if (!first) js << ",\n";
        first = false;
        js << "    {\n";
        js << "      \"port\": " << r.port << ",\n";
        js << "      \"state\": \"open\",\n";
        js << "      \"banner\": \"" << EscapeJson(r.banner) << "\",\n";
        js << "      \"response_time_ms\": " << r.responseTimeMs << ",\n";
        js << "      \"timestamp\": \"" << EscapeJson(r.timestamp) << "\"\n";
        js << "    }";
    }

    js << "\n  ]\n";
    js << "}\n";
    return js.str();
}

// ---------------------------------------------------------------------------
// Print results to console
// ---------------------------------------------------------------------------

void PrintResults(const std::vector<ScanResult>& results) {
    int openCount = 0;

    printf("\n%-10s %-10s %-40s %s\n",
           "PORT", "STATE", "BANNER", "RESPONSE TIME");
    printf("%-10s %-10s %-40s %s\n",
           "----", "-----", "------", "-------------");

    for (auto& r : results) {
        if (!r.open) continue;
        ++openCount;
        printf("%-10d %-10s %-40s %d ms\n",
               r.port, "open",
               r.banner.empty() ? "-" : r.banner.substr(0, 40).c_str(),
               r.responseTimeMs);
    }

    printf("\n[*] %zu ports scanned, %d open\n",
           results.size(), openCount);
}

// ---------------------------------------------------------------------------
// Usage
// ---------------------------------------------------------------------------

static void PrintUsage(const char* prog) {
    printf("Usage: %s -h <host> -p <ports> [options]\n\n", prog);
    printf("Options:\n");
    printf("  -h <host>        Target IP or hostname (required)\n");
    printf("  -p <ports>       Port spec: 22,80,443 or 1-1024 (required)\n");
    printf("  -c <concurrency> Max concurrent threads (default: 500)\n");
    printf("  -t <timeout_ms>  Connection timeout in ms (default: 1000)\n");
    printf("  -b               Enable banner grabbing\n");
    printf("  -o <file.json>   Write JSON results to file\n");
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

int main(int argc, char* argv[]) {
    ScanConfig config;
    bool hasHost  = false;
    bool hasPorts = false;
    std::string portSpec;

    // Parse command-line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" && i + 1 < argc) {
            config.host = argv[++i];
            hasHost = true;
        } else if (arg == "-p" && i + 1 < argc) {
            portSpec = argv[++i];
            hasPorts = true;
        } else if (arg == "-c" && i + 1 < argc) {
            config.concurrency = std::stoi(argv[++i]);
        } else if (arg == "-t" && i + 1 < argc) {
            config.timeoutMs = std::stoi(argv[++i]);
        } else if (arg == "-b") {
            config.bannerGrab = true;
        } else if (arg == "-o" && i + 1 < argc) {
            config.outputFile = argv[++i];
        } else {
            PrintUsage(argv[0]);
            return 1;
        }
    }

    if (!hasHost || !hasPorts) {
        PrintUsage(argv[0]);
        return 1;
    }

    printf("[*] PhantomScan v5.2 — Port Scanner\n");
    printf("[*] ================================\n\n");

    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "[!] WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }

    // Parse ports
    config.ports = ParsePorts(portSpec);
    if (config.ports.empty()) {
        fprintf(stderr, "[!] No valid ports specified\n");
        WSACleanup();
        return 1;
    }

    // Validate host — quick DNS check
    struct addrinfo hints = {}, *res = nullptr;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(config.host.c_str(), nullptr, &hints, &res) != 0) {
        fprintf(stderr, "[!] Cannot resolve host: %s\n", config.host.c_str());
        WSACleanup();
        return 1;
    }
    freeaddrinfo(res);

    // Print scan parameters
    printf("[*] Target       : %s\n", config.host.c_str());
    printf("[*] Ports        : %zu\n", config.ports.size());
    printf("[*] Concurrency  : %d threads\n", config.concurrency);
    printf("[*] Timeout      : %d ms\n", config.timeoutMs);
    printf("[*] Banner grab  : %s\n", config.bannerGrab ? "enabled" : "disabled");
    if (!config.outputFile.empty())
        printf("[*] Output file  : %s\n", config.outputFile.c_str());
    printf("\n[*] Scan started at %s\n", GetCurrentTimestamp().c_str());

    // Run scan
    auto startTime = std::chrono::high_resolution_clock::now();
    std::vector<ScanResult> results = RunScan(config);
    auto endTime = std::chrono::high_resolution_clock::now();

    double elapsed = std::chrono::duration<double>(endTime - startTime).count();
    printf("[*] Scan completed in %.2f seconds\n", elapsed);

    // Print results table
    PrintResults(results);

    // Write JSON output if requested
    if (!config.outputFile.empty()) {
        std::string json = ResultsToJson(results, config);
        std::ofstream ofs(config.outputFile);
        if (ofs.is_open()) {
            ofs << json;
            ofs.close();
            printf("[*] Results written to %s\n", config.outputFile.c_str());
        } else {
            fprintf(stderr, "[!] Failed to open output file: %s\n",
                    config.outputFile.c_str());
        }
    }

    WSACleanup();
    return 0;
}
