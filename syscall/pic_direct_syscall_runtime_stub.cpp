#include "..\common\bkaes_sample.h"

static bool BkaesPicScanStubForSsn(const BYTE* stub, size_t stubBytes, DWORD* ssn)
{
    if (stub == nullptr || ssn == nullptr || stubBytes < 12)
    {
        return false;
    }

    for (size_t i = 0; i + 6 < stubBytes; ++i)
    {
        if (stub[i] != 0xB8)
        {
            continue;
        }

        DWORD value = 0;
        memcpy(&value, &stub[i + 1], sizeof(value));
        for (size_t j = i + 5; j + 1 < stubBytes && j < i + 32; ++j)
        {
            if (stub[j] == 0x0F && stub[j + 1] == 0x05)
            {
                *ssn = value;
                return true;
            }
        }
    }

    return false;
}

static const BYTE* BkaesPicResolveJumpTarget(const BYTE* stub)
{
    if (stub == nullptr)
    {
        return nullptr;
    }
    if (stub[0] == 0xE9)
    {
        int32_t rel32 = 0;
        memcpy(&rel32, &stub[1], sizeof(rel32));
        return stub + 5 + rel32;
    }
    if (stub[0] == 0xEB)
    {
        return stub + 2 + (int8_t)stub[1];
    }
    if (stub[0] == 0xFF && stub[1] == 0x25)
    {
        int32_t disp32 = 0;
        const BYTE* target = nullptr;
        memcpy(&disp32, &stub[2], sizeof(disp32));
        memcpy(&target, stub + 6 + disp32, sizeof(target));
        return target;
    }

    return nullptr;
}

static bool BkaesPicExtractSsn(const BYTE* stub, DWORD* ssn)
{
    const BYTE* candidate = stub;
    for (int depth = 0; depth < 3 && candidate != nullptr; ++depth)
    {
        if (BkaesPicScanStubForSsn(candidate, 96, ssn))
        {
            return true;
        }
        candidate = BkaesPicResolveJumpTarget(candidate);
    }
    return false;
}

static BYTE* BkaesPicCreateSyscallStub(DWORD ssn)
{
    BYTE* stub = (BYTE*)VirtualAlloc(nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (stub == nullptr)
    {
        return nullptr;
    }

    BYTE bytes[] = {
        0x4C, 0x8B, 0xD1,             // mov r10, rcx
        0xB8, 0,    0,    0,    0,    // mov eax, ssn
        0x0F, 0x05,                   // syscall
        0xC3                          // ret
    };
    memcpy(&bytes[4], &ssn, sizeof(ssn));
    memcpy(stub, bytes, sizeof(bytes));

    DWORD oldProtect = 0;
    if (!VirtualProtect(stub, 0x1000, PAGE_EXECUTE_READ, &oldProtect))
    {
        VirtualFree(stub, 0, MEM_RELEASE);
        return nullptr;
    }
    FlushInstructionCache(GetCurrentProcess(), stub, sizeof(bytes));
    return stub;
}

int RunPicDirectSyscallRuntimeStub()
{
#if !defined(_M_X64)
    BkaesPrint("[SKIP] x64-only sample\n");
    return 2;
#else
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto ntQuerySystemInformation =
        ntdll != nullptr ? (NtQuerySystemInformationFn)GetProcAddress(ntdll, "NtQuerySystemInformation") : nullptr;
    DWORD ssn = 0;
    BYTE* stub = nullptr;
    BYTE output[512] = {};
    ULONG returnLength = 0;

    if (ntQuerySystemInformation == nullptr ||
        !BkaesPicExtractSsn(reinterpret_cast<const BYTE*>(ntQuerySystemInformation), &ssn))
    {
        BkaesPrint("[FAIL] PIC sample could not resolve NtQuerySystemInformation syscall number\n");
        return 1;
    }

    stub = BkaesPicCreateSyscallStub(ssn);
    if (stub == nullptr)
    {
        BkaesPrint("[FAIL] PIC sample could not allocate private syscall stub\n");
        return 1;
    }

    auto directNtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformationFn>(stub);
    for (int i = 0; i < 384; ++i)
    {
        (void)directNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0, output, sizeof(output), &returnLength);
        if ((i % 64) == 0)
        {
            Sleep(15);
        }
    }

    char status[256];
    (void)StringCchPrintfA(status, ARRAYSIZE(status),
                           "sample=pic_direct_syscall_runtime_stub syscall=NtQuerySystemInformation ssn=0x%08lX "
                           "stub=%p calls=384 returnLength=%lu",
                           ssn, stub, returnLength);
    BkaesWriteAuditText(L"pic_direct_syscall_runtime_stub.status.txt", status);
    BkaesPrint("[OK] %s\n", status);
    BkaesSettleTelemetry(7000);
    VirtualFree(stub, 0, MEM_RELEASE);
    return 0;
#endif
}
