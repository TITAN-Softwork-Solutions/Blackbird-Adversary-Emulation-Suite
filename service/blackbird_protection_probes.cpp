#include "..\common\bkaes_sample.h"

static constexpr NTSTATUS BkaesStatusNotImplemented = (NTSTATUS)0xC0000002L;
static constexpr NTSTATUS BkaesStatusAccessDenied = (NTSTATUS)0xC0000022L;
static constexpr NTSTATUS BkaesStatusNotFound = (NTSTATUS)0xC0000225L;

static std::wstring ExpandProbePath(const wchar_t* path)
{
    DWORD needed = ExpandEnvironmentStringsW(path, nullptr, 0);
    if (needed == 0)
    {
        return path;
    }

    std::wstring expanded(needed, L'\0');
    DWORD written = ExpandEnvironmentStringsW(path, expanded.data(), needed);
    if (written == 0 || written > needed)
    {
        return path;
    }
    while (!expanded.empty() && expanded.back() == L'\0')
    {
        expanded.pop_back();
    }
    return expanded;
}

static bool WideNameEqualsAny(const wchar_t* name, const wchar_t* const* candidates, size_t count)
{
    if (name == nullptr)
    {
        return false;
    }
    for (size_t i = 0; i < count; ++i)
    {
        if (_wcsicmp(name, candidates[i]) == 0)
        {
            return true;
        }
    }
    return false;
}

static void ProbeServiceNames(const wchar_t* const* names, size_t count, const char* label, int* openedCount)
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    if (scm == nullptr)
    {
        BkaesPrint("[INFO] service probe label=%s scm-open failed err=%lu\n", label, GetLastError());
        return;
    }

    int opened = 0;
    for (size_t i = 0; i < count; ++i)
    {
        SC_HANDLE service = OpenServiceW(scm, names[i], SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
        DWORD err = GetLastError();
        if (service != nullptr)
        {
            SERVICE_STATUS_PROCESS status = {};
            DWORD bytesNeeded = 0;
            QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status),
                                 &bytesNeeded);
            ++opened;
            CloseServiceHandle(service);
        }
        BkaesPrint("[INFO] service probe label=%s name=%ls opened=%u err=%lu\n", label, names[i],
                   service != nullptr ? 1u : 0u, service != nullptr ? 0u : err);
    }

    if (openedCount != nullptr)
    {
        *openedCount += opened;
    }
    CloseServiceHandle(scm);
}

static void ProbeFileArtifacts(const wchar_t* const* paths, size_t count, const char* label, int* visibleCount)
{
    int visible = 0;
    for (size_t i = 0; i < count; ++i)
    {
        std::wstring path = ExpandProbePath(paths[i]);
        DWORD attrs = GetFileAttributesW(path.c_str());
        HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                  nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        DWORD err = file == INVALID_HANDLE_VALUE ? GetLastError() : 0;
        if (attrs != INVALID_FILE_ATTRIBUTES || file != INVALID_HANDLE_VALUE)
        {
            ++visible;
        }
        if (file != INVALID_HANDLE_VALUE)
        {
            CloseHandle(file);
        }
        BkaesPrint("[INFO] file artifact probe label=%s path=%ls attrs=0x%08lX opened=%u err=%lu\n", label,
                   path.c_str(), attrs, file != INVALID_HANDLE_VALUE ? 1u : 0u, err);
    }

    if (visibleCount != nullptr)
    {
        *visibleCount += visible;
    }
}

struct ServiceArtifactProbeResult
{
    int vmOpened;
    int blackbirdOpened;
};

struct FileArtifactProbeResult
{
    int vmVisible;
    int blackbirdVisible;
    int blackbirdLocalVisible;
};

struct ProcessModuleProbeResult
{
    int matchedProcesses;
    int openedProcesses;
    int matchedModules;
    bool sr71Loaded;
    bool j58Loaded;
};

struct ThreadProbeResult
{
    int openedThreads;
    int queriedThreadStarts;
    int ntGetNextCount;
};

struct MemoryStubProbeResult
{
    int queried;
    int readBack;
    int patchedLooking;
    int sr71Queried;
    int sr71ReadBack;
    bool sr71ProtectDenied;
    bool sr71WriteDenied;
    NTSTATUS sr71QueryStatus;
    NTSTATUS sr71ReadStatus;
    NTSTATUS protectStatus;
    NTSTATUS writeStatus;
    SIZE_T written;
};

static ServiceArtifactProbeResult ProbeVmAndBlackbirdServices()
{
    const wchar_t* vmServices[] = {
        L"VBoxService", L"VBoxGuest",    L"VMTools", L"vmtools",    L"vmicheartbeat",
        L"vmicvss",     L"vmicshutdown", L"qemu-ga", L"xenservice",
    };
    const wchar_t* blackbirdServices[] = {
        L"BlackbirdController",
        L"BlackbirdNetSvc",
        L"Blackbird",
    };
    ServiceArtifactProbeResult result = {};
    ProbeServiceNames(vmServices, ARRAYSIZE(vmServices), "vm", &result.vmOpened);
    ProbeServiceNames(blackbirdServices, ARRAYSIZE(blackbirdServices), "blackbird", &result.blackbirdOpened);

    for (const wchar_t* name : vmServices)
    {
        std::wstring subkey = L"SYSTEM\\CurrentControlSet\\Services\\";
        subkey += name;
        BkaesQueryKeyValue(HKEY_LOCAL_MACHINE, subkey.c_str(), L"ImagePath");
    }
    for (const wchar_t* name : blackbirdServices)
    {
        std::wstring subkey = L"SYSTEM\\CurrentControlSet\\Services\\";
        subkey += name;
        BkaesQueryKeyValue(HKEY_LOCAL_MACHINE, subkey.c_str(), L"ImagePath");
    }

    BkaesPrint("[OK] service artifact probes completed vmOpened=%d blackbirdOpened=%d total=%d\n", result.vmOpened,
               result.blackbirdOpened, result.vmOpened + result.blackbirdOpened);
    return result;
}

static FileArtifactProbeResult ProbeVmAndBlackbirdFiles()
{
    const wchar_t* vmPaths[] = {
        L"%SystemRoot%\\System32\\drivers\\vmmouse.sys",   L"%SystemRoot%\\System32\\drivers\\vmhgfs.sys",
        L"%SystemRoot%\\System32\\drivers\\VBoxGuest.sys", L"%SystemRoot%\\System32\\drivers\\VBoxMouse.sys",
        L"%SystemRoot%\\System32\\drivers\\qemufwcfg.sys", L"%ProgramFiles%\\VMware\\VMware Tools\\vmtoolsd.exe",
    };
    const wchar_t* blackbirdPaths[] = {
        L"%ProgramData%\\Blackbird",
        L"%ProgramData%\\Blackbird\\Node",
        L"%ProgramData%\\Blackbird\\Node\\SR71.dll",
        L"%ProgramData%\\Blackbird\\Node\\J58.dll",
        L"%ProgramData%\\Blackbird\\Node\\BlackbirdController.exe",
        L"%ProgramData%\\Blackbird\\Node\\logs",
        L"%SystemRoot%\\System32\\drivers\\Blackbird.sys",
    };

    FileArtifactProbeResult result = {};
    ProbeFileArtifacts(vmPaths, ARRAYSIZE(vmPaths), "vm", &result.vmVisible);
    ProbeFileArtifacts(blackbirdPaths, ARRAYSIZE(blackbirdPaths), "blackbird", &result.blackbirdVisible);

    std::wstring selfDir = BkaesSelfDirectory();
    const std::wstring localSr71 = selfDir + L"\\SR71.dll";
    const std::wstring localJ58 = selfDir + L"\\J58.dll";
    const wchar_t* localPaths[] = {localSr71.c_str(), localJ58.c_str()};
    ProbeFileArtifacts(localPaths, ARRAYSIZE(localPaths), "blackbird-local", &result.blackbirdLocalVisible);

    BkaesPrint(
        "[OK] file artifact probes completed vmVisible=%d blackbirdVisible=%d blackbirdLocalVisible=%d total=%d\n",
        result.vmVisible, result.blackbirdVisible, result.blackbirdLocalVisible,
        result.vmVisible + result.blackbirdVisible + result.blackbirdLocalVisible);
    return result;
}

static ProcessModuleProbeResult ProbeBlackbirdProcessAndModuleVisibility()
{
    const wchar_t* processNames[] = {
        L"BlackbirdController.exe",
        L"BlackbirdInterface.exe",
        L"BlackbirdRunner.exe",
        L"BlackbirdNetSvc.exe",
    };
    const wchar_t* moduleNames[] = {
        L"SR71.dll",
        L"J58.dll",
        L"BKDC.dll",
    };

    ProcessModuleProbeResult result = {};
    HANDLE processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (processSnapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W entry = {};
        entry.dwSize = sizeof(entry);
        if (Process32FirstW(processSnapshot, &entry))
        {
            do
            {
                if (!WideNameEqualsAny(entry.szExeFile, processNames, ARRAYSIZE(processNames)))
                {
                    continue;
                }

                ++result.matchedProcesses;
                HANDLE process =
                    OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, entry.th32ProcessID);
                if (process != nullptr)
                {
                    wchar_t image[MAX_PATH] = {};
                    DWORD chars = ARRAYSIZE(image);
                    QueryFullProcessImageNameW(process, 0, image, &chars);
                    ++result.openedProcesses;
                    CloseHandle(process);
                }
            } while (Process32NextW(processSnapshot, &entry));
        }
        CloseHandle(processSnapshot);
    }

    HANDLE moduleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (moduleSnapshot != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32W module = {};
        module.dwSize = sizeof(module);
        if (Module32FirstW(moduleSnapshot, &module))
        {
            do
            {
                if (WideNameEqualsAny(module.szModule, moduleNames, ARRAYSIZE(moduleNames)))
                {
                    ++result.matchedModules;
                }
            } while (Module32NextW(moduleSnapshot, &module));
        }
        CloseHandle(moduleSnapshot);
    }

    HMODULE sr71 = GetModuleHandleW(L"SR71.dll");
    HMODULE j58 = GetModuleHandleW(L"J58.dll");
    result.sr71Loaded = sr71 != nullptr;
    result.j58Loaded = j58 != nullptr;
    BkaesPrint("[OK] process/module visibility probe processes=%d opened=%d modules=%d sr71=%p j58=%p\n",
               result.matchedProcesses, result.openedProcesses, result.matchedModules, sr71, j58);
    return result;
}

static void ProbeSystemInformationLists()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto ntQuerySystemInformation = (NtQuerySystemInformationFn)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (ntQuerySystemInformation == nullptr)
    {
        return;
    }

    const ULONG classes[] = {5u, 11u, 16u, 35u, 76u};
    for (ULONG infoClass : classes)
    {
        ULONG returnLength = 0;
        std::vector<BYTE> buffer(1u << 20);
        NTSTATUS status = ntQuerySystemInformation((SYSTEM_INFORMATION_CLASS)infoClass, buffer.data(),
                                                   (ULONG)buffer.size(), &returnLength);
        BkaesPrint("[INFO] system-information probe class=%lu status=0x%08lX returnLength=%lu\n", infoClass,
                   (ULONG)status, returnLength);
    }
}

static ThreadProbeResult ProbeSr71Threads()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto ntQueryInformationThread = (NtQueryInformationThreadFn)GetProcAddress(ntdll, "NtQueryInformationThread");
    auto ntGetNextThread = (NtGetNextThreadFn)GetProcAddress(ntdll, "NtGetNextThread");

    DWORD selfPid = GetCurrentProcessId();
    ThreadProbeResult result = {};

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot != INVALID_HANDLE_VALUE)
    {
        THREADENTRY32 entry = {};
        entry.dwSize = sizeof(entry);
        if (Thread32First(snapshot, &entry))
        {
            do
            {
                if (entry.th32OwnerProcessID != selfPid)
                {
                    continue;
                }

                HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT, FALSE, entry.th32ThreadID);
                if (thread == nullptr)
                {
                    thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ThreadID);
                }
                if (thread != nullptr)
                {
                    ++result.openedThreads;
                    if (ntQueryInformationThread != nullptr)
                    {
                        PVOID startAddress = nullptr;
                        ULONG ret = 0;
                        NTSTATUS status =
                            ntQueryInformationThread(thread, 9, &startAddress, sizeof(startAddress), &ret);
                        if (status >= 0)
                        {
                            ++result.queriedThreadStarts;
                        }
                    }
                    CloseHandle(thread);
                }
            } while (Thread32Next(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }

    if (ntGetNextThread != nullptr)
    {
        HANDLE cursor = nullptr;
        for (int i = 0; i < 64; ++i)
        {
            HANDLE next = nullptr;
            NTSTATUS status = ntGetNextThread(GetCurrentProcess(), cursor, THREAD_QUERY_INFORMATION, 0, 0, &next);
            if (cursor != nullptr)
            {
                CloseHandle(cursor);
                cursor = nullptr;
            }
            if (status < 0 || next == nullptr)
            {
                break;
            }
            cursor = next;
            ++result.ntGetNextCount;
        }
        if (cursor != nullptr)
        {
            CloseHandle(cursor);
        }
    }

    BkaesPrint("[OK] SR71 thread visibility probe opened=%d queriedStarts=%d ntGetNext=%d\n", result.openedThreads,
               result.queriedThreadStarts, result.ntGetNextCount);
    return result;
}

static bool StubBytesLookPatched(const BYTE* bytes, size_t size)
{
    if (bytes == nullptr || size < 2)
    {
        return false;
    }

    return bytes[0] == 0xE9 || bytes[0] == 0xCC || bytes[0] == 0xC3 || (bytes[0] == 0xEB) ||
           (bytes[0] == 0xFF && bytes[1] == 0x25) || (bytes[0] == 0x48 && bytes[1] == 0xB8);
}

static MemoryStubProbeResult ProbeProtectedMemoryAndNtStubs()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto ntQueryVirtualMemory = (NtQueryVirtualMemoryFn)GetProcAddress(ntdll, "NtQueryVirtualMemory");
    auto ntReadVirtualMemory = (NtReadVirtualMemoryFn)GetProcAddress(ntdll, "NtReadVirtualMemory");
    auto ntProtectVirtualMemory = (NtProtectVirtualMemoryFn)GetProcAddress(ntdll, "NtProtectVirtualMemory");
    auto ntWriteVirtualMemory = (NtWriteVirtualMemoryFn)GetProcAddress(ntdll, "NtWriteVirtualMemory");

    const char* exports[] = {
        "NtOpenProcess",        "NtWriteVirtualMemory",     "NtProtectVirtualMemory", "NtCreateThreadEx",
        "NtQueryVirtualMemory", "NtQueryInformationThread", "NtGetNextThread",
    };

    MemoryStubProbeResult result = {};
    result.sr71QueryStatus = BkaesStatusNotFound;
    result.sr71ReadStatus = BkaesStatusNotFound;
    result.protectStatus = BkaesStatusNotImplemented;
    result.writeStatus = BkaesStatusNotImplemented;
    void* firstExport = nullptr;
    BYTE firstByte = 0;
    for (const char* name : exports)
    {
        void* address = reinterpret_cast<void*>(GetProcAddress(ntdll, name));
        if (address == nullptr)
        {
            continue;
        }
        if (firstExport == nullptr)
        {
            firstExport = address;
            memcpy(&firstByte, address, sizeof(firstByte));
        }

        BYTE directBytes[16] = {};
        BYTE readBytes[16] = {};
        memcpy(directBytes, address, sizeof(directBytes));
        if (StubBytesLookPatched(directBytes, sizeof(directBytes)))
        {
            ++result.patchedLooking;
        }

        if (ntQueryVirtualMemory != nullptr)
        {
            MEMORY_BASIC_INFORMATION mbi = {};
            SIZE_T ret = 0;
            NTSTATUS status = ntQueryVirtualMemory(GetCurrentProcess(), address, 0, &mbi, sizeof(mbi), &ret);
            if (status >= 0)
            {
                ++result.queried;
            }
        }

        if (ntReadVirtualMemory != nullptr)
        {
            SIZE_T bytesRead = 0;
            NTSTATUS status =
                ntReadVirtualMemory(GetCurrentProcess(), address, readBytes, sizeof(readBytes), &bytesRead);
            if (status >= 0 && bytesRead != 0)
            {
                ++result.readBack;
            }
        }
    }

    HMODULE sr71 = GetModuleHandleW(L"SR71.dll");
    void* protectedProbe = sr71 != nullptr ? reinterpret_cast<void*>(sr71) : firstExport;
    if (sr71 != nullptr && ntQueryVirtualMemory != nullptr)
    {
        MEMORY_BASIC_INFORMATION mbi = {};
        SIZE_T ret = 0;
        result.sr71QueryStatus =
            ntQueryVirtualMemory(GetCurrentProcess(), sr71, 0, &mbi, sizeof(mbi), &ret);
        if (result.sr71QueryStatus >= 0)
        {
            ++result.sr71Queried;
        }
    }
    if (sr71 != nullptr && ntReadVirtualMemory != nullptr)
    {
        BYTE sr71Bytes[32] = {};
        SIZE_T bytesRead = 0;
        result.sr71ReadStatus =
            ntReadVirtualMemory(GetCurrentProcess(), sr71, sr71Bytes, sizeof(sr71Bytes), &bytesRead);
        if (result.sr71ReadStatus >= 0 && bytesRead != 0)
        {
            ++result.sr71ReadBack;
        }
    }
    if (protectedProbe != nullptr && ntProtectVirtualMemory != nullptr)
    {
        PVOID base = protectedProbe;
        SIZE_T size = 16;
        ULONG oldProtect = 0;
        result.protectStatus =
            ntProtectVirtualMemory(GetCurrentProcess(), &base, &size, PAGE_EXECUTE_READWRITE, &oldProtect);
        result.sr71ProtectDenied = sr71 != nullptr && result.protectStatus == BkaesStatusAccessDenied;
        if (result.protectStatus >= 0 && oldProtect != 0)
        {
            ULONG ignored = 0;
            ntProtectVirtualMemory(GetCurrentProcess(), &base, &size, oldProtect, &ignored);
        }
    }
    if (protectedProbe != nullptr && ntWriteVirtualMemory != nullptr)
    {
        result.writeStatus =
            ntWriteVirtualMemory(GetCurrentProcess(), protectedProbe, &firstByte, sizeof(firstByte), &result.written);
        result.sr71WriteDenied = sr71 != nullptr && result.writeStatus == BkaesStatusAccessDenied;
    }

    BkaesPrint("[OK] protected memory and NT stub probe queried=%d read=%d patchedLooking=%d protectStatus=0x%08lX "
               "writeStatus=0x%08lX written=%llu sr71=%p sr71Queried=%d sr71Read=%d sr71QueryStatus=0x%08lX "
               "sr71ReadStatus=0x%08lX sr71ProtectDenied=%u sr71WriteDenied=%u\n",
               result.queried, result.readBack, result.patchedLooking, (ULONG)result.protectStatus,
               (ULONG)result.writeStatus, (unsigned long long)result.written, sr71, result.sr71Queried,
               result.sr71ReadBack, (ULONG)result.sr71QueryStatus, (ULONG)result.sr71ReadStatus,
               result.sr71ProtectDenied ? 1u : 0u, result.sr71WriteDenied ? 1u : 0u);
    return result;
}

int RunBlackbirdProtectionProbes()
{
    ServiceArtifactProbeResult services = ProbeVmAndBlackbirdServices();
    FileArtifactProbeResult files = ProbeVmAndBlackbirdFiles();
    ProcessModuleProbeResult processModules = ProbeBlackbirdProcessAndModuleVisibility();
    ProbeSystemInformationLists();
    ThreadProbeResult threads = ProbeSr71Threads();
    MemoryStubProbeResult memory = ProbeProtectedMemoryAndNtStubs();

    int blackbirdVisible = services.blackbirdOpened + files.blackbirdVisible + files.blackbirdLocalVisible +
                           processModules.matchedProcesses + processModules.matchedModules +
                           (processModules.sr71Loaded ? 1 : 0) + (processModules.j58Loaded ? 1 : 0);
    int vmVisible = services.vmOpened + files.vmVisible;
    bool concealmentFailed = blackbirdVisible > 0 || vmVisible > 0;
    bool assertConcealment = BkaesEnvFlagEnabled(L"BKAES_ASSERT_CONCEALMENT");

    char outcome[2048];
    HRESULT outcomeStatus = StringCchPrintfA(
        outcome, ARRAYSIZE(outcome),
        "[BKAES_OUTCOME] blackbird_protection_concealment=%s assert=%u blackbirdVisible=%d vmVisible=%d "
        "blackbirdServicesOpened=%d blackbirdFilesVisible=%d blackbirdLocalFilesVisible=%d "
        "blackbirdProcesses=%d blackbirdProcessesOpened=%d blackbirdModules=%d sr71Loaded=%u j58Loaded=%u "
        "vmServicesOpened=%d vmFilesVisible=%d sr71ThreadsOpened=%d sr71ThreadStartsQueried=%d ntGetNext=%d "
        "ntStubsQueried=%d ntStubsRead=%d patchedLooking=%d sr71Queried=%d sr71Read=%d "
        "sr71ProtectDenied=%u sr71WriteDenied=%u sr71QueryStatus=0x%08lX sr71ReadStatus=0x%08lX "
        "protectStatus=0x%08lX writeStatus=0x%08lX written=%llu\n",
        concealmentFailed ? "failed" : "passed", assertConcealment ? 1u : 0u, blackbirdVisible, vmVisible,
        services.blackbirdOpened, files.blackbirdVisible, files.blackbirdLocalVisible, processModules.matchedProcesses,
        processModules.openedProcesses, processModules.matchedModules, processModules.sr71Loaded ? 1u : 0u,
        processModules.j58Loaded ? 1u : 0u, services.vmOpened, files.vmVisible, threads.openedThreads,
        threads.queriedThreadStarts, threads.ntGetNextCount, memory.queried, memory.readBack, memory.patchedLooking,
        memory.sr71Queried, memory.sr71ReadBack, memory.sr71ProtectDenied ? 1u : 0u,
        memory.sr71WriteDenied ? 1u : 0u, (ULONG)memory.sr71QueryStatus, (ULONG)memory.sr71ReadStatus,
        (ULONG)memory.protectStatus, (ULONG)memory.writeStatus, (unsigned long long)memory.written);
    if (FAILED(outcomeStatus))
    {
        StringCchCopyA(outcome, ARRAYSIZE(outcome),
                       "[BKAES_OUTCOME] blackbird_protection_concealment=failed reason=outcome-format-error\n");
    }
    BkaesPrint("%s", outcome);
    BkaesWriteAuditText(L"bkaes-protection-outcome.txt", outcome);

    if (concealmentFailed)
    {
        char assertion[768];
        StringCchPrintfA(assertion, ARRAYSIZE(assertion),
                         "[BKAES_ASSERT_FAIL] blackbird_protection_concealment failed: "
                         "blackbirdVisible=%d vmVisible=%d blackbirdServicesOpened=%d blackbirdFilesVisible=%d "
                         "blackbirdProcesses=%d vmServicesOpened=%d vmFilesVisible=%d\n",
                         blackbirdVisible, vmVisible, services.blackbirdOpened, files.blackbirdVisible,
                         processModules.matchedProcesses, services.vmOpened, files.vmVisible);
        if (assertConcealment)
        {
            BkaesPrint("%s", assertion);
            BkaesWriteAuditText(L"bkaes-assertions.txt", assertion);
            return 31;
        }
        BkaesPrint("[WARN] blackbird_protection_concealment failed: "
                   "blackbirdVisible=%d vmVisible=%d blackbirdServicesOpened=%d blackbirdFilesVisible=%d "
                   "blackbirdProcesses=%d vmServicesOpened=%d vmFilesVisible=%d\n",
                   blackbirdVisible, vmVisible, services.blackbirdOpened, files.blackbirdVisible,
                   processModules.matchedProcesses, services.vmOpened, files.vmVisible);
    }

    BkaesPrint("[OK] Blackbird protection probe suite completed\n");
    return 0;
}
