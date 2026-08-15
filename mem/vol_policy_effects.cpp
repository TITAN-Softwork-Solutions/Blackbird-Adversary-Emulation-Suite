#include "..\common\bkaes_sample.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace
{
    constexpr uintptr_t kVolBaseAddress = 0x000002BB5A500000ull;
    constexpr SIZE_T kPageSize = 0x1000;
    constexpr SIZE_T kRegionSize = kPageSize * 4;
    constexpr char kOriginalRead[17] = "ORIGINAL-READ-00";
    constexpr char kOverlayRead[17] = "VOL-READ-OVERLAY";
    constexpr char kOriginalWrite[17] = "ORIGINAL-WRITE00";
    constexpr char kAttemptedWrite[17] = "ATTEMPTED-WRITE!";
    constexpr char kNearWrite[17] = "NEAR-MISS-WRITE!";
    // Keep this path neutral: Blackbird intentionally conceals its own product
    // artifacts from instrumented targets, which would invalidate the no-policy
    // baseline.
    constexpr wchar_t kRegistryPath[] = L"Software\\Contoso\\VolEffects";

    void RecordFailure(std::string &failures, const char *message)
    {
        failures += "[BKAES_ASSERT_FAIL] ";
        failures += message;
        failures += "\n";
        BkaesPrint("[FAIL] %s\n", message);
    }

    bool QueryDword(HKEY key, const wchar_t *valueName, DWORD *value, LSTATUS *queryStatus)
    {
        DWORD type = 0;
        DWORD size = sizeof(*value);
        *value = 0;
        *queryStatus = RegQueryValueExW(key, valueName, nullptr, &type, reinterpret_cast<BYTE *>(value), &size);
        return *queryStatus == ERROR_SUCCESS && type == REG_DWORD && size == sizeof(*value);
    }
} // namespace

int RunVolPolicyEffects()
{
    const bool expectVol = BkaesEnvFlagEnabled(L"BKAES_EXPECT_VOL");
    std::string failures;
    BYTE *region = static_cast<BYTE *>(
        VirtualAlloc(reinterpret_cast<void *>(kVolBaseAddress), kRegionSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    HANDLE process = nullptr;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto ntRead = ntdll != nullptr
                      ? reinterpret_cast<NtReadVirtualMemoryFn>(GetProcAddress(ntdll, "NtReadVirtualMemory"))
                      : nullptr;
    auto ntWrite = ntdll != nullptr
                       ? reinterpret_cast<NtWriteVirtualMemoryFn>(GetProcAddress(ntdll, "NtWriteVirtualMemory"))
                       : nullptr;
    auto ntProtect = ntdll != nullptr
                         ? reinterpret_cast<NtProtectVirtualMemoryFn>(GetProcAddress(ntdll, "NtProtectVirtualMemory"))
                         : nullptr;
    NTSTATUS readStatus = static_cast<NTSTATUS>(0xC0000001u);
    NTSTATUS writeStatus = static_cast<NTSTATUS>(0xC0000001u);
    NTSTATUS nearWriteStatus = static_cast<NTSTATUS>(0xC0000001u);
    NTSTATUS protectStatus = static_cast<NTSTATUS>(0xC0000001u);
    NTSTATUS nearProtectStatus = static_cast<NTSTATUS>(0xC0000001u);
    SIZE_T readBytes = 0;
    SIZE_T writeBytes = 0;
    SIZE_T nearWriteBytes = 0;
    char readBack[sizeof(kOriginalRead)] = {};
    LSTATUS hiddenQueryStatus = ERROR_INVALID_FUNCTION;
    LSTATUS replacedQueryStatus = ERROR_INVALID_FUNCTION;
    LSTATUS controlQueryStatus = ERROR_INVALID_FUNCTION;
    DWORD replacedValue = 0;
    DWORD controlValue = 0;

    if (region == nullptr || reinterpret_cast<uintptr_t>(region) != kVolBaseAddress)
    {
        RecordFailure(failures, "fixed VOL test allocation was unavailable");
    }
    if (ntdll == nullptr || ntRead == nullptr || ntWrite == nullptr || ntProtect == nullptr)
    {
        RecordFailure(failures, "required ntdll memory APIs were unavailable");
    }

    if (region != nullptr)
    {
        memcpy(region, kOriginalRead, sizeof(kOriginalRead) - 1);
        memcpy(region + kPageSize, kOriginalWrite, sizeof(kOriginalWrite) - 1);
        memset(region + (kPageSize * 2), 0x43, kPageSize);
        memset(region + (kPageSize * 3), 0x44, kPageSize);
    }

    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
                          FALSE, GetCurrentProcessId());
    if (process == nullptr)
    {
        RecordFailure(failures, "real self-process handle could not be opened");
    }

    if (region != nullptr && process != nullptr && ntRead != nullptr)
    {
        readStatus = ntRead(process, region, readBack, sizeof(kOriginalRead) - 1, &readBytes);
        const char *expectedRead = expectVol ? kOverlayRead : kOriginalRead;
        if (!NT_SUCCESS(readStatus) || readBytes != sizeof(kOriginalRead) - 1 ||
            memcmp(readBack, expectedRead, sizeof(kOriginalRead) - 1) != 0)
        {
            RecordFailure(failures, expectVol ? "memory read overlay was not observed"
                                              : "baseline memory read was unexpectedly modified");
        }
        if (memcmp(region, kOriginalRead, sizeof(kOriginalRead) - 1) != 0)
        {
            RecordFailure(failures, "memory read overlay changed the underlying allocation");
        }
    }

    if (region != nullptr && process != nullptr && ntWrite != nullptr)
    {
        writeStatus = ntWrite(process, region + kPageSize, kAttemptedWrite, sizeof(kAttemptedWrite) - 1, &writeBytes);
        if (!NT_SUCCESS(writeStatus) || writeBytes != sizeof(kAttemptedWrite) - 1)
        {
            RecordFailure(failures, "targeted NtWriteVirtualMemory did not report a complete write");
        }
        const char *expectedWrite = expectVol ? kOriginalWrite : kAttemptedWrite;
        if (memcmp(region + kPageSize, expectedWrite, sizeof(kOriginalWrite) - 1) != 0)
        {
            RecordFailure(failures, expectVol ? "memory write cloak did not preserve original bytes"
                                              : "baseline memory write was unexpectedly cloaked");
        }

        BYTE *nearAddress = region + kPageSize + 0x100;
        nearWriteStatus = ntWrite(process, nearAddress, kNearWrite, sizeof(kNearWrite) - 1, &nearWriteBytes);
        if (!NT_SUCCESS(nearWriteStatus) || nearWriteBytes != sizeof(kNearWrite) - 1 ||
            memcmp(nearAddress, kNearWrite, sizeof(kNearWrite) - 1) != 0)
        {
            RecordFailure(failures, "near-miss memory write was incorrectly modified or blocked");
        }
    }

    if (region != nullptr && process != nullptr && ntProtect != nullptr)
    {
        PVOID protectedBase = region + (kPageSize * 2);
        SIZE_T protectedSize = kPageSize;
        ULONG oldProtect = 0;
        protectStatus = ntProtect(process, &protectedBase, &protectedSize, PAGE_EXECUTE_READWRITE, &oldProtect);
        if (expectVol)
        {
            MEMORY_BASIC_INFORMATION info = {};
            if (protectStatus != static_cast<NTSTATUS>(0xC0000022u) ||
                VirtualQuery(region + (kPageSize * 2), &info, sizeof(info)) != sizeof(info) ||
                (info.Protect & 0xFFu) != PAGE_READWRITE)
            {
                RecordFailure(failures, "memory protection denial was not observed");
            }
        }
        else if (!NT_SUCCESS(protectStatus))
        {
            RecordFailure(failures, "baseline memory protection change was unexpectedly denied");
        }
        if (NT_SUCCESS(protectStatus))
        {
            DWORD ignored = 0;
            VirtualProtect(region + (kPageSize * 2), kPageSize, oldProtect, &ignored);
        }

        PVOID nearBase = region + (kPageSize * 3);
        SIZE_T nearSize = kPageSize;
        ULONG nearOldProtect = 0;
        nearProtectStatus = ntProtect(process, &nearBase, &nearSize, PAGE_READONLY, &nearOldProtect);
        if (!NT_SUCCESS(nearProtectStatus))
        {
            RecordFailure(failures, "near-miss memory protection change was incorrectly denied");
        }
        else
        {
            DWORD ignored = 0;
            VirtualProtect(region + (kPageSize * 3), kPageSize, nearOldProtect, &ignored);
        }
    }

    RegDeleteTreeW(HKEY_CURRENT_USER, kRegistryPath);
    HKEY key = nullptr;
    DWORD disposition = 0;
    LSTATUS registryStatus = RegCreateKeyExW(HKEY_CURRENT_USER, kRegistryPath, 0, nullptr, 0,
                                             KEY_QUERY_VALUE | KEY_SET_VALUE, nullptr, &key, &disposition);
    if (registryStatus != ERROR_SUCCESS)
    {
        RecordFailure(failures, "VOL registry test key could not be created");
    }
    else
    {
        const DWORD hiddenOriginal = 0xA1B2C3D4u;
        const DWORD replacedOriginal = 0x11223344u;
        const DWORD controlOriginal = 0x55667788u;
        if (RegSetValueExW(key, L"Hidden", 0, REG_DWORD, reinterpret_cast<const BYTE *>(&hiddenOriginal),
                           sizeof(hiddenOriginal)) != ERROR_SUCCESS ||
            RegSetValueExW(key, L"Replaced", 0, REG_DWORD, reinterpret_cast<const BYTE *>(&replacedOriginal),
                           sizeof(replacedOriginal)) != ERROR_SUCCESS ||
            RegSetValueExW(key, L"Control", 0, REG_DWORD, reinterpret_cast<const BYTE *>(&controlOriginal),
                           sizeof(controlOriginal)) != ERROR_SUCCESS)
        {
            RecordFailure(failures, "VOL registry test values could not be initialized");
        }
        else
        {
            DWORD value = 0;
            bool hiddenRead = QueryDword(key, L"Hidden", &value, &hiddenQueryStatus);
            if (expectVol)
            {
                if (hiddenRead ||
                    (hiddenQueryStatus != ERROR_FILE_NOT_FOUND && hiddenQueryStatus != ERROR_PATH_NOT_FOUND))
                {
                    RecordFailure(failures, "registry query-not-found modification was not observed");
                }
            }
            else if (!hiddenRead || value != hiddenOriginal)
            {
                RecordFailure(failures, "baseline registry query was unexpectedly hidden");
            }

            bool replacedRead = QueryDword(key, L"Replaced", &value, &replacedQueryStatus);
            replacedValue = value;
            const DWORD expectedReplacement = expectVol ? 0x12345678u : replacedOriginal;
            if (!replacedRead || value != expectedReplacement)
            {
                RecordFailure(failures, expectVol ? "registry value replacement was not observed"
                                                  : "baseline registry value was unexpectedly replaced");
            }

            bool controlRead = QueryDword(key, L"Control", &value, &controlQueryStatus);
            controlValue = value;
            if (!controlRead || value != controlOriginal)
            {
                RecordFailure(failures, "near-miss registry value was incorrectly modified");
            }
        }
        RegCloseKey(key);
    }
    RegDeleteTreeW(HKEY_CURRENT_USER, kRegistryPath);

    char outcome[768] = {};
    StringCchPrintfA(outcome, ARRAYSIZE(outcome),
                     "[BKAES_OUTCOME] vol_policy_effects=%s expectVol=%u readStatus=0x%08lX "
                     "writeStatus=0x%08lX protectStatus=0x%08lX nearWriteStatus=0x%08lX "
                     "nearProtectStatus=0x%08lX hiddenQueryStatus=%ld replacedQueryStatus=%ld "
                     "replacedValue=0x%08lX controlQueryStatus=%ld controlValue=0x%08lX\n",
                     failures.empty() ? "passed" : "failed", expectVol ? 1u : 0u, static_cast<ULONG>(readStatus),
                     static_cast<ULONG>(writeStatus), static_cast<ULONG>(protectStatus),
                     static_cast<ULONG>(nearWriteStatus), static_cast<ULONG>(nearProtectStatus), hiddenQueryStatus,
                     replacedQueryStatus, replacedValue, controlQueryStatus, controlValue);
    BkaesWriteAuditText(L"bkaes-protection-outcome.txt", outcome);
    if (!failures.empty())
    {
        BkaesWriteAuditText(L"bkaes-assertions.txt", failures.c_str());
    }
    BkaesPrint("%s", outcome);
    BkaesSettleTelemetry(1000);

    if (process != nullptr)
    {
        CloseHandle(process);
    }
    if (region != nullptr)
    {
        VirtualFree(region, 0, MEM_RELEASE);
    }
    return failures.empty() ? 0 : 41;
}
