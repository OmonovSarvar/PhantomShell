/*
 * PhantomSocks v5.2 — SOCKS5 Proxy Module
 * Part of PhantomShell Agent Framework
 *
 * AUTHORIZED USE ONLY. This software is provided for use in sanctioned
 * penetration testing, red team operations, and security research under
 * explicit written authorization. Unauthorized use of this tool against
 * systems you do not own or have permission to test is illegal and
 * unethical. The authors assume no liability for misuse.
 *
 * Implements RFC 1928 (SOCKS5) and RFC 1929 (Username/Password Auth).
 * Compile: cl /EHsc /std:c++17 socks5.cpp /Fe:socks5.exe
 */

#define _WINSOCK_DEPRECATED_NO_WARNINGS

// winsock2.h must precede windows.h to avoid redefinition conflicts
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <stdio.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <cstdarg>
#include <cstring>
#include <ctime>

#pragma comment(lib, "ws2_32")

// ---------------------------------------------------------------------------
// Configuration globals
// ---------------------------------------------------------------------------
std::string  g_username;                   // Auth username (empty = no auth)
std::string  g_password;                   // Auth password
bool         g_requireAuth = false;        // Enforce username/password auth
std::atomic<bool> g_running{true};         // Shutdown flag (Ctrl+C handler)
std::mutex   g_logMutex;                   // Guards console output

// ---------------------------------------------------------------------------
// Thread-safe logging with [HH:MM:SS] timestamp prefix
// ---------------------------------------------------------------------------
void Log(const char* fmt, ...) {
    std::lock_guard<std::mutex> lock(g_logMutex);

    // Timestamp
    time_t now = time(nullptr);
    struct tm t;
    localtime_s(&t, &now);
    printf("[%02d:%02d:%02d] ", t.tm_hour, t.tm_min, t.tm_sec);

    // Message
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);

    printf("\n");
    fflush(stdout);
}

// ---------------------------------------------------------------------------
// RFC 1928 SOCKS5 Constants
// ---------------------------------------------------------------------------

// Protocol version
constexpr uint8_t SOCKS_VERSION        = 0x05;

// Authentication methods
constexpr uint8_t AUTH_NO_AUTH         = 0x00;
constexpr uint8_t AUTH_USER_PASS      = 0x02;
constexpr uint8_t AUTH_NO_ACCEPTABLE  = 0xFF;

// Commands
constexpr uint8_t CMD_CONNECT         = 0x01;
constexpr uint8_t CMD_BIND            = 0x02;

// Address types
constexpr uint8_t ATYP_IPV4           = 0x01;
constexpr uint8_t ATYP_DOMAIN        = 0x03;
constexpr uint8_t ATYP_IPV6          = 0x04;

// Reply codes
constexpr uint8_t REP_SUCCEEDED           = 0x00;
constexpr uint8_t REP_GENERAL_FAILURE     = 0x01;
constexpr uint8_t REP_NOT_ALLOWED         = 0x02;
constexpr uint8_t REP_NETWORK_UNREACHABLE = 0x03;
constexpr uint8_t REP_HOST_UNREACHABLE    = 0x04;
constexpr uint8_t REP_CONNECTION_REFUSED  = 0x05;
constexpr uint8_t REP_COMMAND_NOT_SUPPORTED = 0x07;
constexpr uint8_t REP_ADDR_NOT_SUPPORTED = 0x08;

// Relay buffer size
constexpr int RELAY_BUFFER_SIZE = 8192;

// Forward declarations
void RelayData(SOCKET clientSock, SOCKET remoteSock);

// ---------------------------------------------------------------------------
// Helper: send an exact number of bytes
// ---------------------------------------------------------------------------
static bool SendAll(SOCKET s, const void* data, int len) {
    const char* ptr = static_cast<const char*>(data);
    while (len > 0) {
        int sent = send(s, ptr, len, 0);
        if (sent == SOCKET_ERROR || sent == 0) return false;
        ptr += sent;
        len -= sent;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Helper: receive an exact number of bytes
// ---------------------------------------------------------------------------
static bool RecvAll(SOCKET s, void* data, int len) {
    char* ptr = static_cast<char*>(data);
    while (len > 0) {
        int received = recv(s, ptr, len, 0);
        if (received <= 0) return false;
        ptr += received;
        len -= received;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Helper: send a SOCKS5 error reply (CONNECT-style, with zeroed bind addr)
// ---------------------------------------------------------------------------
static void SendErrorReply(SOCKET clientSock, uint8_t repCode) {
    uint8_t reply[10] = {
        SOCKS_VERSION, repCode, 0x00, ATYP_IPV4,
        0, 0, 0, 0,   // 4-byte zeroed address
        0, 0           // 2-byte zeroed port
    };
    SendAll(clientSock, reply, sizeof(reply));
}

// ---------------------------------------------------------------------------
// NegotiateAuth — RFC 1928 section 3 (+ RFC 1929 subnegotiation)
// ---------------------------------------------------------------------------
bool NegotiateAuth(SOCKET clientSock) {
    // Read client greeting: VER(1) + NMETHODS(1)
    uint8_t header[2];
    if (!RecvAll(clientSock, header, 2)) {
        Log("Auth: failed to read greeting header");
        return false;
    }

    if (header[0] != SOCKS_VERSION) {
        Log("Auth: unsupported SOCKS version 0x%02X", header[0]);
        return false;
    }

    uint8_t nmethods = header[1];
    if (nmethods == 0) {
        Log("Auth: client offered zero methods");
        return false;
    }

    // Read offered methods
    std::vector<uint8_t> methods(nmethods);
    if (!RecvAll(clientSock, methods.data(), nmethods)) {
        Log("Auth: failed to read methods list");
        return false;
    }

    if (g_requireAuth) {
        // Check if client supports USERNAME/PASSWORD (0x02)
        bool supportsUserPass = false;
        for (auto m : methods) {
            if (m == AUTH_USER_PASS) { supportsUserPass = true; break; }
        }

        if (!supportsUserPass) {
            uint8_t resp[2] = { SOCKS_VERSION, AUTH_NO_ACCEPTABLE };
            SendAll(clientSock, resp, 2);
            Log("Auth: client does not support username/password auth");
            return false;
        }

        // Select USERNAME/PASSWORD
        uint8_t resp[2] = { SOCKS_VERSION, AUTH_USER_PASS };
        if (!SendAll(clientSock, resp, 2)) return false;

        // RFC 1929 subnegotiation: VER(1) + ULEN(1) + UNAME(ULEN) + PLEN(1) + PASSWD(PLEN)
        uint8_t authVer;
        if (!RecvAll(clientSock, &authVer, 1)) return false;
        // Auth subneg version should be 0x01
        if (authVer != 0x01) {
            Log("Auth: bad subnegotiation version 0x%02X", authVer);
            return false;
        }

        uint8_t ulen;
        if (!RecvAll(clientSock, &ulen, 1)) return false;
        std::string username(ulen, '\0');
        if (ulen > 0 && !RecvAll(clientSock, &username[0], ulen)) return false;

        uint8_t plen;
        if (!RecvAll(clientSock, &plen, 1)) return false;
        std::string password(plen, '\0');
        if (plen > 0 && !RecvAll(clientSock, &password[0], plen)) return false;

        if (username == g_username && password == g_password) {
            uint8_t success[2] = { 0x01, 0x00 }; // STATUS 0x00 = success
            SendAll(clientSock, success, 2);
            Log("Auth: user '%s' authenticated", username.c_str());
        } else {
            uint8_t failure[2] = { 0x01, 0x01 }; // STATUS 0x01 = failure
            SendAll(clientSock, failure, 2);
            Log("Auth: invalid credentials for user '%s'", username.c_str());
            return false;
        }
    } else {
        // No authentication required
        uint8_t resp[2] = { SOCKS_VERSION, AUTH_NO_AUTH };
        if (!SendAll(clientSock, resp, 2)) return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// HandleConnect — RFC 1928 CONNECT command
// ---------------------------------------------------------------------------
bool HandleConnect(SOCKET clientSock, SOCKET& remoteSock) {
    // Request header already partially consumed by HandleRequest;
    // we receive: RSV(1) + ATYP(1)
    uint8_t rsv, atyp;
    if (!RecvAll(clientSock, &rsv, 1)) return false;
    if (!RecvAll(clientSock, &atyp, 1)) return false;

    sockaddr_in  destAddrV4{};
    sockaddr_in6 destAddrV6{};
    sockaddr*    destAddr = nullptr;
    int          destLen  = 0;

    if (atyp == ATYP_IPV4) {
        // 4-byte IPv4 + 2-byte port (network order)
        uint8_t ipBytes[4];
        uint16_t port;
        if (!RecvAll(clientSock, ipBytes, 4)) return false;
        if (!RecvAll(clientSock, &port, 2)) return false;

        destAddrV4.sin_family = AF_INET;
        memcpy(&destAddrV4.sin_addr, ipBytes, 4);
        destAddrV4.sin_port = port; // already in network order
        destAddr = reinterpret_cast<sockaddr*>(&destAddrV4);
        destLen  = sizeof(destAddrV4);

        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &destAddrV4.sin_addr, ipStr, sizeof(ipStr));
        Log("CONNECT to %s:%d", ipStr, ntohs(port));

    } else if (atyp == ATYP_DOMAIN) {
        // LEN(1) + DOMAIN(LEN) + PORT(2)
        uint8_t domLen;
        if (!RecvAll(clientSock, &domLen, 1)) return false;

        std::string domain(domLen, '\0');
        if (!RecvAll(clientSock, &domain[0], domLen)) return false;

        uint16_t port;
        if (!RecvAll(clientSock, &port, 2)) return false;

        Log("CONNECT to %s:%d (domain)", domain.c_str(), ntohs(port));

        // Resolve domain via getaddrinfo
        addrinfo hints{}, *result = nullptr;
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        char portStr[8];
        snprintf(portStr, sizeof(portStr), "%d", ntohs(port));

        int res = getaddrinfo(domain.c_str(), portStr, &hints, &result);
        if (res != 0 || !result) {
            Log("CONNECT: DNS resolution failed for %s", domain.c_str());
            SendErrorReply(clientSock, REP_HOST_UNREACHABLE);
            return false;
        }

        // Use first resolved address
        if (result->ai_family == AF_INET) {
            memcpy(&destAddrV4, result->ai_addr, result->ai_addrlen);
            destAddr = reinterpret_cast<sockaddr*>(&destAddrV4);
            destLen  = static_cast<int>(result->ai_addrlen);
        } else if (result->ai_family == AF_INET6) {
            memcpy(&destAddrV6, result->ai_addr, result->ai_addrlen);
            destAddr = reinterpret_cast<sockaddr*>(&destAddrV6);
            destLen  = static_cast<int>(result->ai_addrlen);
        } else {
            freeaddrinfo(result);
            SendErrorReply(clientSock, REP_ADDR_NOT_SUPPORTED);
            return false;
        }
        freeaddrinfo(result);

    } else if (atyp == ATYP_IPV6) {
        // 16-byte IPv6 + 2-byte port
        uint8_t ipBytes[16];
        uint16_t port;
        if (!RecvAll(clientSock, ipBytes, 16)) return false;
        if (!RecvAll(clientSock, &port, 2)) return false;

        destAddrV6.sin6_family = AF_INET6;
        memcpy(&destAddrV6.sin6_addr, ipBytes, 16);
        destAddrV6.sin6_port = port;
        destAddr = reinterpret_cast<sockaddr*>(&destAddrV6);
        destLen  = sizeof(destAddrV6);

        char ipStr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &destAddrV6.sin6_addr, ipStr, sizeof(ipStr));
        Log("CONNECT to [%s]:%d", ipStr, ntohs(port));

    } else {
        Log("CONNECT: unsupported address type 0x%02X", atyp);
        SendErrorReply(clientSock, REP_ADDR_NOT_SUPPORTED);
        return false;
    }

    // Create remote socket
    int family = (destAddr->sa_family == AF_INET6) ? AF_INET6 : AF_INET;
    remoteSock = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (remoteSock == INVALID_SOCKET) {
        Log("CONNECT: socket creation failed (%d)", WSAGetLastError());
        SendErrorReply(clientSock, REP_GENERAL_FAILURE);
        return false;
    }

    // Connect to target
    if (connect(remoteSock, destAddr, destLen) == SOCKET_ERROR) {
        int err = WSAGetLastError();
        Log("CONNECT: connection failed (%d)", err);
        uint8_t rep = REP_GENERAL_FAILURE;
        if (err == WSAECONNREFUSED)  rep = REP_CONNECTION_REFUSED;
        if (err == WSAENETUNREACH)   rep = REP_NETWORK_UNREACHABLE;
        if (err == WSAEHOSTUNREACH)  rep = REP_HOST_UNREACHABLE;
        SendErrorReply(clientSock, rep);
        closesocket(remoteSock);
        remoteSock = INVALID_SOCKET;
        return false;
    }

    // Get bound address for the reply
    sockaddr_in boundAddr{};
    int boundLen = sizeof(boundAddr);
    getsockname(remoteSock, reinterpret_cast<sockaddr*>(&boundAddr), &boundLen);

    // Send success reply: VER(1) + REP(1) + RSV(1) + ATYP(1) + BND.ADDR(4) + BND.PORT(2)
    uint8_t reply[10] = {
        SOCKS_VERSION, REP_SUCCEEDED, 0x00, ATYP_IPV4
    };
    memcpy(reply + 4, &boundAddr.sin_addr, 4);
    memcpy(reply + 8, &boundAddr.sin_port, 2);

    if (!SendAll(clientSock, reply, sizeof(reply))) {
        closesocket(remoteSock);
        remoteSock = INVALID_SOCKET;
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// HandleBind — Simplified RFC 1928 BIND command
// ---------------------------------------------------------------------------
bool HandleBind(SOCKET clientSock) {
    // Consume RSV + ATYP + DST.ADDR + DST.PORT (we don't use them for bind)
    uint8_t rsv, atyp;
    if (!RecvAll(clientSock, &rsv, 1)) return false;
    if (!RecvAll(clientSock, &atyp, 1)) return false;

    // Skip the address and port fields based on atyp
    if (atyp == ATYP_IPV4) {
        uint8_t skip[6]; RecvAll(clientSock, skip, 6);
    } else if (atyp == ATYP_DOMAIN) {
        uint8_t dlen; RecvAll(clientSock, &dlen, 1);
        std::vector<uint8_t> skip(dlen + 2); RecvAll(clientSock, skip.data(), dlen + 2);
    } else if (atyp == ATYP_IPV6) {
        uint8_t skip[18]; RecvAll(clientSock, skip, 18);
    }

    // Create a listening socket bound to 0.0.0.0:0 (random port)
    SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSock == INVALID_SOCKET) {
        SendErrorReply(clientSock, REP_GENERAL_FAILURE);
        return false;
    }

    sockaddr_in bindAddr{};
    bindAddr.sin_family      = AF_INET;
    bindAddr.sin_addr.s_addr = INADDR_ANY;
    bindAddr.sin_port        = 0; // OS assigns a random port

    if (bind(listenSock, reinterpret_cast<sockaddr*>(&bindAddr), sizeof(bindAddr)) == SOCKET_ERROR) {
        Log("BIND: bind failed (%d)", WSAGetLastError());
        SendErrorReply(clientSock, REP_GENERAL_FAILURE);
        closesocket(listenSock);
        return false;
    }

    if (listen(listenSock, 1) == SOCKET_ERROR) {
        Log("BIND: listen failed (%d)", WSAGetLastError());
        SendErrorReply(clientSock, REP_GENERAL_FAILURE);
        closesocket(listenSock);
        return false;
    }

    // Get the bound address/port
    sockaddr_in actualAddr{};
    int addrLen = sizeof(actualAddr);
    getsockname(listenSock, reinterpret_cast<sockaddr*>(&actualAddr), &addrLen);

    Log("BIND: listening on port %d", ntohs(actualAddr.sin_port));

    // First reply: tell client the bind address/port
    uint8_t reply1[10] = { SOCKS_VERSION, REP_SUCCEEDED, 0x00, ATYP_IPV4 };
    memcpy(reply1 + 4, &actualAddr.sin_addr, 4);
    memcpy(reply1 + 8, &actualAddr.sin_port, 2);
    if (!SendAll(clientSock, reply1, sizeof(reply1))) {
        closesocket(listenSock);
        return false;
    }

    // Accept one incoming connection
    sockaddr_in peerAddr{};
    int peerLen = sizeof(peerAddr);
    SOCKET peerSock = accept(listenSock, reinterpret_cast<sockaddr*>(&peerAddr), &peerLen);
    closesocket(listenSock); // No longer needed

    if (peerSock == INVALID_SOCKET) {
        Log("BIND: accept failed (%d)", WSAGetLastError());
        SendErrorReply(clientSock, REP_GENERAL_FAILURE);
        return false;
    }

    char peerIp[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &peerAddr.sin_addr, peerIp, sizeof(peerIp));
    Log("BIND: accepted connection from %s:%d", peerIp, ntohs(peerAddr.sin_port));

    // Second reply: tell client who connected
    uint8_t reply2[10] = { SOCKS_VERSION, REP_SUCCEEDED, 0x00, ATYP_IPV4 };
    memcpy(reply2 + 4, &peerAddr.sin_addr, 4);
    memcpy(reply2 + 8, &peerAddr.sin_port, 2);
    if (!SendAll(clientSock, reply2, sizeof(reply2))) {
        closesocket(peerSock);
        return false;
    }

    // Relay data between original client and the accepted peer
    RelayData(clientSock, peerSock);
    closesocket(peerSock);
    return true;
}

// ---------------------------------------------------------------------------
// RelayData — bidirectional data relay using select()
// ---------------------------------------------------------------------------
void RelayData(SOCKET clientSock, SOCKET remoteSock) {
    char buffer[RELAY_BUFFER_SIZE];

    while (g_running) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(clientSock, &readfds);
        FD_SET(remoteSock, &readfds);

        // 1-second timeout so we can check g_running periodically
        timeval tv;
        tv.tv_sec  = 1;
        tv.tv_usec = 0;

        // On Windows, the first param to select() is ignored but required
        int maxfd = 0;
        int ret = select(maxfd, &readfds, nullptr, nullptr, &tv);

        if (ret == SOCKET_ERROR) {
            Log("Relay: select() error (%d)", WSAGetLastError());
            break;
        }
        if (ret == 0) continue; // Timeout, check g_running

        // Client -> Remote
        if (FD_ISSET(clientSock, &readfds)) {
            int n = recv(clientSock, buffer, RELAY_BUFFER_SIZE, 0);
            if (n <= 0) {
                if (n == 0) Log("Relay: client closed connection");
                else        Log("Relay: client recv error (%d)", WSAGetLastError());
                break;
            }
            if (!SendAll(remoteSock, buffer, n)) {
                Log("Relay: failed to send to remote");
                break;
            }
        }

        // Remote -> Client
        if (FD_ISSET(remoteSock, &readfds)) {
            int n = recv(remoteSock, buffer, RELAY_BUFFER_SIZE, 0);
            if (n <= 0) {
                if (n == 0) Log("Relay: remote closed connection");
                else        Log("Relay: remote recv error (%d)", WSAGetLastError());
                break;
            }
            if (!SendAll(clientSock, buffer, n)) {
                Log("Relay: failed to send to client");
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// HandleClient — per-connection thread entry point
// ---------------------------------------------------------------------------
void HandleClient(SOCKET clientSock, sockaddr_in clientAddr) {
    char clientIp[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &clientAddr.sin_addr, clientIp, sizeof(clientIp));
    int clientPort = ntohs(clientAddr.sin_port);

    Log("Connection from %s:%d", clientIp, clientPort);

    // Phase 1: Authentication negotiation
    if (!NegotiateAuth(clientSock)) {
        Log("Auth failed for %s:%d", clientIp, clientPort);
        closesocket(clientSock);
        return;
    }

    // Phase 2: Read command — VER(1) + CMD(1), then dispatch
    uint8_t verCmd[2];
    if (!RecvAll(clientSock, verCmd, 2)) {
        Log("Failed to read request from %s:%d", clientIp, clientPort);
        closesocket(clientSock);
        return;
    }

    if (verCmd[0] != SOCKS_VERSION) {
        Log("Bad version in request: 0x%02X", verCmd[0]);
        closesocket(clientSock);
        return;
    }

    uint8_t cmd = verCmd[1];

    if (cmd == CMD_CONNECT) {
        SOCKET remoteSock = INVALID_SOCKET;
        if (HandleConnect(clientSock, remoteSock)) {
            RelayData(clientSock, remoteSock);
            if (remoteSock != INVALID_SOCKET) closesocket(remoteSock);
        }
    } else if (cmd == CMD_BIND) {
        HandleBind(clientSock);
    } else {
        Log("Unsupported command 0x%02X from %s:%d", cmd, clientIp, clientPort);
        // Consume RSV + ATYP to stay in sync, then send error
        uint8_t discard[2];
        RecvAll(clientSock, discard, 2);
        SendErrorReply(clientSock, REP_COMMAND_NOT_SUPPORTED);
    }

    closesocket(clientSock);
    Log("Disconnected %s:%d", clientIp, clientPort);
}

// ---------------------------------------------------------------------------
// Ctrl+C handler — signals graceful shutdown
// ---------------------------------------------------------------------------
BOOL WINAPI CtrlHandler(DWORD ctrlType) {
    if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_CLOSE_EVENT) {
        Log("Shutdown signal received");
        g_running = false;
        return TRUE;
    }
    return FALSE;
}

// ---------------------------------------------------------------------------
// Usage banner
// ---------------------------------------------------------------------------
void PrintUsage(const char* prog) {
    printf("Usage: %s -l <port> [-u <username>] [-p <password>] [--no-auth]\n", prog);
    printf("\n");
    printf("  -l <port>      Listening port (required)\n");
    printf("  -u <username>  Authentication username\n");
    printf("  -p <password>  Authentication password\n");
    printf("  --no-auth      Disable auth even if -u/-p are set\n");
}

// ---------------------------------------------------------------------------
// main — parse args, start listener, accept loop
// ---------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    int listenPort = 0;
    bool noAuthFlag = false;

    // Parse command-line arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-l" && i + 1 < argc) {
            listenPort = atoi(argv[++i]);
        } else if (arg == "-u" && i + 1 < argc) {
            g_username = argv[++i];
        } else if (arg == "-p" && i + 1 < argc) {
            g_password = argv[++i];
        } else if (arg == "--no-auth") {
            noAuthFlag = true;
        } else {
            PrintUsage(argv[0]);
            return 1;
        }
    }

    if (listenPort <= 0 || listenPort > 65535) {
        PrintUsage(argv[0]);
        return 1;
    }

    // Determine auth mode
    if (!noAuthFlag && !g_username.empty() && !g_password.empty()) {
        g_requireAuth = true;
    }

    // Banner
    printf("[*] PhantomSocks v5.2 -- SOCKS5 Proxy\n");
    printf("[*] Auth: %s\n", g_requireAuth ? "username/password" : "none");

    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        Log("WSAStartup failed (%d)", WSAGetLastError());
        return 1;
    }

    // Register Ctrl+C handler
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    // Create listening socket
    SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSock == INVALID_SOCKET) {
        Log("Failed to create listening socket (%d)", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    // Allow address reuse
    int optval = 1;
    setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&optval), sizeof(optval));

    // Bind to 0.0.0.0:<port>
    sockaddr_in serverAddr{};
    serverAddr.sin_family      = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port        = htons(static_cast<uint16_t>(listenPort));

    if (bind(listenSock, reinterpret_cast<sockaddr*>(&serverAddr),
             sizeof(serverAddr)) == SOCKET_ERROR) {
        Log("Bind failed on port %d (%d)", listenPort, WSAGetLastError());
        closesocket(listenSock);
        WSACleanup();
        return 1;
    }

    if (listen(listenSock, SOMAXCONN) == SOCKET_ERROR) {
        Log("Listen failed (%d)", WSAGetLastError());
        closesocket(listenSock);
        WSACleanup();
        return 1;
    }

    Log("Listening on 0.0.0.0:%d", listenPort);

    // Accept loop
    while (g_running) {
        // Use select() with timeout so we can check g_running
        fd_set acceptSet;
        FD_ZERO(&acceptSet);
        FD_SET(listenSock, &acceptSet);

        timeval tv;
        tv.tv_sec  = 1;
        tv.tv_usec = 0;

        int sel = select(0, &acceptSet, nullptr, nullptr, &tv);
        if (sel == SOCKET_ERROR) {
            if (g_running) Log("Accept select error (%d)", WSAGetLastError());
            break;
        }
        if (sel == 0) continue; // Timeout

        sockaddr_in clientAddr{};
        int clientAddrLen = sizeof(clientAddr);
        SOCKET clientSock = accept(listenSock,
                                   reinterpret_cast<sockaddr*>(&clientAddr),
                                   &clientAddrLen);

        if (clientSock == INVALID_SOCKET) {
            if (g_running) Log("Accept failed (%d)", WSAGetLastError());
            continue;
        }

        // Spawn a detached thread for each client
        std::thread(HandleClient, clientSock, clientAddr).detach();
    }

    // Cleanup
    Log("Shutting down...");
    closesocket(listenSock);
    WSACleanup();

    return 0;
}
