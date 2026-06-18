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
    int sr71DescriptorCandidates;
    DWORD sr71DescriptorHoldMs;
    bool sr71ProtectDenied;
    bool sr71WriteDenied;
    bool sr71DescriptorTampered;
    bool sr71DescriptorRestored;
    void* sr71DescriptorAddress;
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

struct AddressRange
{
    uintptr_t start;
    uintptr_t end;
};

static bool AddressInRange(uintptr_t address, const AddressRange& range)
{
    return range.start != 0 && address >= range.start && address < range.end;
}

static bool TryGetImageLayout(HMODULE module, IMAGE_NT_HEADERS** ntHeaders)
{
    if (module == nullptr || ntHeaders == nullptr)
    {
        return false;
    }

    __try
    {
        auto* base = reinterpret_cast<BYTE*>(module);
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
        {
            return false;
        }

        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.SizeOfImage == 0)
        {
            return false;
        }

        *ntHeaders = nt;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static bool QueryModuleRange(HMODULE module, AddressRange* range)
{
    if (range == nullptr)
    {
        return false;
    }
    *range = {};

    IMAGE_NT_HEADERS* nt = nullptr;
    if (!TryGetImageLayout(module, &nt))
    {
        return false;
    }

    uintptr_t start = reinterpret_cast<uintptr_t>(module);
    range->start = start;
    range->end = start + nt->OptionalHeader.SizeOfImage;
    return range->end > range->start;
}

static bool MemoryProtectReadable(DWORD protect)
{
    if ((protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0)
    {
        return false;
    }

    DWORD baseProtect = protect & 0xFFu;
    return baseProtect == PAGE_READONLY || baseProtect == PAGE_READWRITE || baseProtect == PAGE_WRITECOPY ||
           baseProtect == PAGE_EXECUTE_READ || baseProtect == PAGE_EXECUTE_READWRITE ||
           baseProtect == PAGE_EXECUTE_WRITECOPY;
}

static bool MemoryProtectWritable(DWORD protect)
{
    if ((protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0)
    {
        return false;
    }

    DWORD baseProtect = protect & 0xFFu;
    return baseProtect == PAGE_READWRITE || baseProtect == PAGE_WRITECOPY ||
           baseProtect == PAGE_EXECUTE_READWRITE || baseProtect == PAGE_EXECUTE_WRITECOPY;
}

static bool RegionOverlapsAddressWindow(uintptr_t regionStart, uintptr_t regionEnd, uintptr_t address, uintptr_t window)
{
    uintptr_t windowStart = address > window ? address - window : 0;
    uintptr_t windowEnd = address + window;
    if (windowEnd < address)
    {
        windowEnd = UINTPTR_MAX;
    }
    return regionStart < windowEnd && regionEnd > windowStart;
}

static void* FindSr71AsciiString(HMODULE sr71, const char* value)
{
    IMAGE_NT_HEADERS* nt = nullptr;
    if (!TryGetImageLayout(sr71, &nt) || value == nullptr)
    {
        return nullptr;
    }

    auto* base = reinterpret_cast<BYTE*>(sr71);
    const size_t needleLength = strlen(value) + 1;
    auto* section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
    {
        if ((section->Characteristics & IMAGE_SCN_MEM_READ) == 0 || section->Misc.VirtualSize < needleLength)
        {
            continue;
        }

        BYTE* start = base + section->VirtualAddress;
        BYTE* end = start + section->Misc.VirtualSize - needleLength;
        __try
        {
            for (BYTE* p = start; p <= end; ++p)
            {
                if (memcmp(p, value, needleLength) == 0)
                {
                    return p;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }
    return nullptr;
}

static bool LooksLikeNtHookDescriptor(BYTE* candidate, void* expectedName)
{
    if (candidate == nullptr || expectedName == nullptr)
    {
        return false;
    }

    uintptr_t name = 0;
    DWORD operation = 0;
    DWORD syscallIndex = 0;
    BYTE installed = 0;
    memcpy(&name, candidate, sizeof(name));
    memcpy(&operation, candidate + 8, sizeof(operation));
    memcpy(&syscallIndex, candidate + 32, sizeof(syscallIndex));
    memcpy(&installed, candidate + 68, sizeof(installed));

    return name == reinterpret_cast<uintptr_t>(expectedName) && operation < 128 && syscallIndex < 0x2000 &&
           installed <= 1;
}

static void* FindSr71NtHookDescriptor(HMODULE sr71, void* value, int* candidateCount)
{
    IMAGE_NT_HEADERS* nt = nullptr;
    if (!TryGetImageLayout(sr71, &nt) || value == nullptr)
    {
        return nullptr;
    }

    auto* base = reinterpret_cast<BYTE*>(sr71);
    const uintptr_t needle = reinterpret_cast<uintptr_t>(value);
    void* fallback = nullptr;
    int candidates = 0;
    auto* section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
    {
        if ((section->Characteristics & IMAGE_SCN_MEM_WRITE) == 0 ||
            section->Misc.VirtualSize < 72)
        {
            continue;
        }

        BYTE* start = base + section->VirtualAddress;
        BYTE* end = start + section->Misc.VirtualSize - 72;
        __try
        {
            for (BYTE* p = start; p <= end; p += sizeof(void*))
            {
                uintptr_t candidate = 0;
                memcpy(&candidate, p, sizeof(candidate));
                if (candidate == needle)
                {
                    ++candidates;
                    if (fallback == nullptr)
                    {
                        fallback = p;
                    }
                    if (LooksLikeNtHookDescriptor(p, value))
                    {
                        if (candidateCount != nullptr)
                        {
                            *candidateCount = candidates;
                        }
                        return p;
                    }
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }
    if (candidateCount != nullptr)
    {
        *candidateCount = candidates;
    }
    return fallback;
}

static void CollectRawAsciiStringHits(const char* value, const AddressRange& skipRange, std::vector<void*>* hits)
{
    if (value == nullptr || hits == nullptr)
    {
        return;
    }

    SYSTEM_INFO info = {};
    GetSystemInfo(&info);
    const size_t needleLength = strlen(value) + 1;
    uintptr_t current = reinterpret_cast<uintptr_t>(info.lpMinimumApplicationAddress);
    const uintptr_t maximum = reinterpret_cast<uintptr_t>(info.lpMaximumApplicationAddress);

    while (current < maximum && hits->size() < 64)
    {
        MEMORY_BASIC_INFORMATION mbi = {};
        SIZE_T queried = VirtualQuery(reinterpret_cast<void*>(current), &mbi, sizeof(mbi));
        if (queried == 0)
        {
            current += 0x10000;
            continue;
        }

        uintptr_t next = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= current)
        {
            break;
        }

        uintptr_t startAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        if ((mbi.State & MEM_COMMIT) != 0 && mbi.Type == MEM_IMAGE && MemoryProtectReadable(mbi.Protect) &&
            !AddressInRange(startAddress, skipRange) && mbi.RegionSize >= needleLength)
        {
            BYTE* start = static_cast<BYTE*>(mbi.BaseAddress);
            BYTE* end = start + mbi.RegionSize - needleLength;
            __try
            {
                for (BYTE* p = start; p <= end && hits->size() < 64; ++p)
                {
                    if (memcmp(p, value, needleLength) == 0)
                    {
                        hits->push_back(p);
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
            }
        }

        current = next;
    }
}

static void* FindNtHookDescriptorInReadableImageMemory(void* value, const AddressRange& skipRange, int* candidateCount)
{
    if (value == nullptr)
    {
        return nullptr;
    }

    SYSTEM_INFO info = {};
    GetSystemInfo(&info);
    uintptr_t current = reinterpret_cast<uintptr_t>(info.lpMinimumApplicationAddress);
    const uintptr_t maximum = reinterpret_cast<uintptr_t>(info.lpMaximumApplicationAddress);
    const uintptr_t needle = reinterpret_cast<uintptr_t>(value);
    void* fallback = nullptr;
    int candidates = 0;

    while (current < maximum)
    {
        MEMORY_BASIC_INFORMATION mbi = {};
        SIZE_T queried = VirtualQuery(reinterpret_cast<void*>(current), &mbi, sizeof(mbi));
        if (queried == 0)
        {
            current += 0x10000;
            continue;
        }

        uintptr_t next = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= current)
        {
            break;
        }

        uintptr_t startAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        constexpr uintptr_t kDescriptorSearchWindow = 16ull * 1024ull * 1024ull;
        const bool candidateType = mbi.Type == MEM_IMAGE || mbi.Type == MEM_PRIVATE;
        if ((mbi.State & MEM_COMMIT) != 0 && candidateType && MemoryProtectReadable(mbi.Protect) &&
            RegionOverlapsAddressWindow(startAddress, next, needle, kDescriptorSearchWindow) &&
            !AddressInRange(startAddress, skipRange) && mbi.RegionSize >= 72)
        {
            BYTE* start = static_cast<BYTE*>(mbi.BaseAddress);
            BYTE* end = start + mbi.RegionSize - 72;
            __try
            {
                for (BYTE* p = start; p <= end; p += sizeof(void*))
                {
                    uintptr_t candidate = 0;
                    memcpy(&candidate, p, sizeof(candidate));
                    if (candidate == needle)
                    {
                        ++candidates;
                        if (fallback == nullptr)
                        {
                            fallback = p;
                        }
                        if (LooksLikeNtHookDescriptor(p, value))
                        {
                            if (candidateCount != nullptr)
                            {
                                *candidateCount = candidates;
                            }
                            return p;
                        }
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
            }
        }

        current = next;
    }

    if (candidateCount != nullptr)
    {
        *candidateCount = candidates;
    }
    return fallback;
}

static void* FindSr71NtHookDescriptorByRawScan(int* candidateCount)
{
    AddressRange selfRange{};
    (void)QueryModuleRange(GetModuleHandleW(nullptr), &selfRange);

    std::vector<void*> nameHits;
    CollectRawAsciiStringHits("NtCreateThread", selfRange, &nameHits);

    int totalCandidates = 0;
    for (void* nameHit : nameHits)
    {
        int localCandidates = 0;
        void* descriptor = FindNtHookDescriptorInReadableImageMemory(nameHit, selfRange, &localCandidates);
        totalCandidates += localCandidates;
        if (descriptor != nullptr)
        {
            if (candidateCount != nullptr)
            {
                *candidateCount = totalCandidates;
            }
            return descriptor;
        }
    }

    if (candidateCount != nullptr)
    {
        *candidateCount = totalCandidates;
    }
    return nullptr;
}

static void ExerciseSr71WhileDescriptorIsDirty(void* probeAddress, DWORD holdMs)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto ntQueryVirtualMemory = (NtQueryVirtualMemoryFn)GetProcAddress(ntdll, "NtQueryVirtualMemory");
    auto ntReadVirtualMemory = (NtReadVirtualMemoryFn)GetProcAddress(ntdll, "NtReadVirtualMemory");

    ULONGLONG stop = GetTickCount64() + holdMs;
    while (GetTickCount64() < stop)
    {
        if (ntQueryVirtualMemory != nullptr)
        {
            MEMORY_BASIC_INFORMATION mbi = {};
            SIZE_T ret = 0;
            (void)ntQueryVirtualMemory(GetCurrentProcess(), probeAddress, 0, &mbi, sizeof(mbi), &ret);
        }
        if (ntReadVirtualMemory != nullptr)
        {
            BYTE bytes[16] = {};
            SIZE_T bytesRead = 0;
            (void)ntReadVirtualMemory(GetCurrentProcess(), probeAddress, bytes, sizeof(bytes), &bytesRead);
        }
        Sleep(250);
    }
}

static bool ProbeSr71DescriptorTamper(HMODULE sr71, void** descriptorAddress, bool* restored, int* candidateCount,
                                      DWORD* holdMs)
{
    constexpr DWORD kDescriptorTamperHoldMs = 8500;
    if (descriptorAddress != nullptr)
    {
        *descriptorAddress = nullptr;
    }
    if (restored != nullptr)
    {
        *restored = false;
    }
    void* descriptor = nullptr;
    if (sr71 != nullptr)
    {
        void* ntCreateThreadName = FindSr71AsciiString(sr71, "NtCreateThread");
        descriptor = FindSr71NtHookDescriptor(sr71, ntCreateThreadName, candidateCount);
    }
    if (descriptor == nullptr)
    {
        descriptor = FindSr71NtHookDescriptorByRawScan(candidateCount);
    }
    if (descriptor == nullptr)
    {
        return false;
    }
    if (holdMs != nullptr)
    {
        *holdMs = kDescriptorTamperHoldMs;
    }

    // NtTargetHook layout: Name ptr, Operation, padding, target token, stub token, SyscallIndex.
    auto* syscallIndex = reinterpret_cast<DWORD*>(static_cast<BYTE*>(descriptor) + 32);
    DWORD original = 0;
    DWORD oldProtect = 0;
    DWORD ignoredProtect = 0;
    bool protectionChanged = false;
    bool tampered = false;
    __try
    {
        protectionChanged =
            VirtualProtect(descriptor, 72, PAGE_READWRITE, &oldProtect) || oldProtect != 0;
        original = *syscallIndex;
        *syscallIndex = original ^ 0x00010000u;
        tampered = (*syscallIndex != original);
        if (protectionChanged)
        {
            (void)VirtualProtect(descriptor, 72, oldProtect, &ignoredProtect);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        tampered = false;
    }

    if (descriptorAddress != nullptr)
    {
        *descriptorAddress = descriptor;
    }

    if (!tampered)
    {
        return false;
    }

    ExerciseSr71WhileDescriptorIsDirty(descriptor, kDescriptorTamperHoldMs);

    __try
    {
        oldProtect = 0;
        ignoredProtect = 0;
        protectionChanged =
            VirtualProtect(descriptor, 72, PAGE_READWRITE, &oldProtect) || oldProtect != 0;
        *syscallIndex = original;
        if (restored != nullptr)
        {
            *restored = (*syscallIndex == original);
        }
        if (protectionChanged)
        {
            (void)VirtualProtect(descriptor, 72, oldProtect, &ignoredProtect);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }

    return true;
}

static bool SeenModuleBase(const std::vector<void*>& seen, void* base)
{
    return std::find(seen.begin(), seen.end(), base) != seen.end();
}

static HMODULE ResolveSr71ForProtectedProbe()
{
    HMODULE sr71 = GetModuleHandleW(L"SR71.dll");
    if (sr71 != nullptr)
    {
        return sr71;
    }
    HMODULE self = GetModuleHandleW(nullptr);

    SYSTEM_INFO info = {};
    GetSystemInfo(&info);

    uintptr_t current = reinterpret_cast<uintptr_t>(info.lpMinimumApplicationAddress);
    const uintptr_t maximum = reinterpret_cast<uintptr_t>(info.lpMaximumApplicationAddress);
    std::vector<void*> seenBases;
    while (current < maximum)
    {
        MEMORY_BASIC_INFORMATION mbi = {};
        SIZE_T queried = VirtualQuery(reinterpret_cast<void*>(current), &mbi, sizeof(mbi));
        if (queried == 0)
        {
            current += 0x10000;
            continue;
        }

        uintptr_t next = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= current)
        {
            break;
        }

        void* allocationBase = mbi.AllocationBase;
        const bool readable =
            (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0 && (mbi.State & MEM_COMMIT) != 0;
        if (allocationBase != nullptr && readable && !SeenModuleBase(seenBases, allocationBase))
        {
            seenBases.push_back(allocationBase);
            auto candidate = reinterpret_cast<HMODULE>(allocationBase);
            if (candidate == self)
            {
                current = next;
                continue;
            }

            IMAGE_NT_HEADERS* nt = nullptr;
            if (TryGetImageLayout(candidate, &nt) && FindSr71AsciiString(candidate, "NtCreateThread") != nullptr &&
                (FindSr71AsciiString(candidate, "rt.nt.desc") != nullptr ||
                 FindSr71AsciiString(candidate, "Sr71DescriptorIntegrity") != nullptr ||
                 FindSr71AsciiString(candidate, "Sr71SelfMap") != nullptr) &&
                (FindSr71AsciiString(candidate, "BK_SR71_ENABLE_PIC") != nullptr ||
                 FindSr71AsciiString(candidate, "BkRuntimeEventLoopThreadProc") != nullptr ||
                 FindSr71AsciiString(candidate, "EnsureRuntimeInitializedForLaunch") != nullptr))
            {
                BkaesPrint("[INFO] resolved SR71 by memory scan base=%p type=0x%08lX protect=0x%08lX\n",
                           candidate, mbi.Type, mbi.Protect);
                return candidate;
            }
        }

        current = next;
    }

    return nullptr;
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

    HMODULE sr71 = ResolveSr71ForProtectedProbe();
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
    result.sr71DescriptorTampered =
        ProbeSr71DescriptorTamper(sr71, &result.sr71DescriptorAddress, &result.sr71DescriptorRestored,
                                  &result.sr71DescriptorCandidates, &result.sr71DescriptorHoldMs);

    BkaesPrint("[OK] protected memory and NT stub probe queried=%d read=%d patchedLooking=%d protectStatus=0x%08lX "
               "writeStatus=0x%08lX written=%llu sr71=%p sr71Queried=%d sr71Read=%d sr71QueryStatus=0x%08lX "
               "sr71ReadStatus=0x%08lX sr71ProtectDenied=%u sr71WriteDenied=%u sr71DescriptorTampered=%u "
               "sr71DescriptorRestored=%u sr71Descriptor=%p sr71DescriptorCandidates=%d sr71DescriptorHoldMs=%lu\n",
               result.queried, result.readBack, result.patchedLooking, (ULONG)result.protectStatus,
               (ULONG)result.writeStatus, (unsigned long long)result.written, sr71, result.sr71Queried,
               result.sr71ReadBack, (ULONG)result.sr71QueryStatus, (ULONG)result.sr71ReadStatus,
               result.sr71ProtectDenied ? 1u : 0u, result.sr71WriteDenied ? 1u : 0u,
               result.sr71DescriptorTampered ? 1u : 0u, result.sr71DescriptorRestored ? 1u : 0u,
               result.sr71DescriptorAddress, result.sr71DescriptorCandidates, result.sr71DescriptorHoldMs);
    return result;
}

int RunBlackbirdProtectionProbes()
{
    SetEnvironmentVariableA("BK_SR71_TEST_DESCRIPTOR_TAMPER", "1");
    SetEnvironmentVariableW(L"BK_SR71_TEST_DESCRIPTOR_TAMPER", L"1");

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
        "sr71ProtectDenied=%u sr71WriteDenied=%u sr71DescriptorTampered=%u sr71DescriptorRestored=%u "
        "sr71Descriptor=0x%p sr71DescriptorCandidates=%d sr71DescriptorHoldMs=%lu "
        "sr71QueryStatus=0x%08lX sr71ReadStatus=0x%08lX protectStatus=0x%08lX "
        "writeStatus=0x%08lX written=%llu\n",
        concealmentFailed ? "failed" : "passed", assertConcealment ? 1u : 0u, blackbirdVisible, vmVisible,
        services.blackbirdOpened, files.blackbirdVisible, files.blackbirdLocalVisible, processModules.matchedProcesses,
        processModules.openedProcesses, processModules.matchedModules, processModules.sr71Loaded ? 1u : 0u,
        processModules.j58Loaded ? 1u : 0u, services.vmOpened, files.vmVisible, threads.openedThreads,
        threads.queriedThreadStarts, threads.ntGetNextCount, memory.queried, memory.readBack, memory.patchedLooking,
        memory.sr71Queried, memory.sr71ReadBack, memory.sr71ProtectDenied ? 1u : 0u,
        memory.sr71WriteDenied ? 1u : 0u, memory.sr71DescriptorTampered ? 1u : 0u,
        memory.sr71DescriptorRestored ? 1u : 0u, memory.sr71DescriptorAddress, memory.sr71DescriptorCandidates,
        memory.sr71DescriptorHoldMs, (ULONG)memory.sr71QueryStatus, (ULONG)memory.sr71ReadStatus,
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
