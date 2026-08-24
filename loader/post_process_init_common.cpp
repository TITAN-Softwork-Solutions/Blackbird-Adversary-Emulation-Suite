#include "post_process_init_common.h"

#include <cstddef>
#include <limits>
#include <utility>

namespace {
#if defined(_WIN64)
static_assert(offsetof(PEB, Reserved3) + sizeof(PVOID) == 0x10);
static_assert(offsetof(PEB, PostProcessInitRoutine) == 0x230);
#endif

bool IsExecutableProtection(DWORD protection) {
  protection &= ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);
  return protection == PAGE_EXECUTE || protection == PAGE_EXECUTE_READ ||
         protection == PAGE_EXECUTE_READWRITE ||
         protection == PAGE_EXECUTE_WRITECOPY;
}

bool PatchRelativeDisplacement(std::array<BYTE, 50> *routine,
                               size_t displacementOffset,
                               ULONGLONG instructionEnd, ULONGLONG target) {
  if (routine == nullptr ||
      displacementOffset + sizeof(LONG) > routine->size()) {
    return false;
  }

  const LONGLONG delta =
      static_cast<LONGLONG>(target) - static_cast<LONGLONG>(instructionEnd);
  if (delta < (std::numeric_limits<LONG>::min)() ||
      delta > (std::numeric_limits<LONG>::max)()) {
    return false;
  }

  const LONG displacement = static_cast<LONG>(delta);
  std::memcpy(routine->data() + displacementOffset, &displacement,
              sizeof(displacement));
  return true;
}

bool ReadRemoteLong(HANDLE process, ULONGLONG address, LONG *value) {
  SIZE_T transferred = 0;
  return value != nullptr &&
         ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address), value,
                           sizeof(*value), &transferred) &&
         transferred == sizeof(*value);
}

bool WriteRemoteLong(HANDLE process, ULONGLONG address, LONG value) {
  SIZE_T transferred = 0;
  return WriteProcessMemory(process, reinterpret_cast<LPVOID>(address), &value,
                            sizeof(value), &transferred) &&
         transferred == sizeof(value);
}

bool WaitForRemoteLong(HANDLE process, ULONGLONG address, LONG expected,
                       DWORD timeoutMs, LONG *observed) {
  const ULONGLONG deadline = GetTickCount64() + timeoutMs;
  LONG value = 0;
  do {
    if (!ReadRemoteLong(process, address, &value)) {
      return false;
    }
    if (value == expected) {
      if (observed != nullptr) {
        *observed = value;
      }
      return true;
    }
    if (value == kBkaesPpirTimedOut) {
      break;
    }
    Sleep(5);
  } while (GetTickCount64() < deadline);

  if (observed != nullptr) {
    *observed = value;
  }
  return false;
}

bool ReadPreResumeHold(DWORD *holdMs) {
  if (holdMs == nullptr) {
    return false;
  }
  *holdMs = 0;
  const std::wstring value =
      BkaesGetEnvString(L"BKAES_PPIR_PRE_RESUME_HOLD_MS");
  if (value.empty()) {
    return true;
  }

  wchar_t *end = nullptr;
  const unsigned long parsed = std::wcstoul(value.c_str(), &end, 10);
  if (end == value.c_str() || *end != L'\0' || parsed == 0 || parsed > 30000) {
    BkaesPrint("[FAIL] BKAES_PPIR_PRE_RESUME_HOLD_MS must be 1..30000\n");
    return false;
  }
  *holdMs = static_cast<DWORD>(parsed);
  return true;
}

} // namespace

bool BkaesPpirLaunchSuspended(const wchar_t *childMode,
                              BkaesPpirRemoteTarget *target) {
#if !defined(_WIN64)
  UNREFERENCED_PARAMETER(childMode);
  UNREFERENCED_PARAMETER(target);
  BkaesPrint("[FAIL] PostProcessInitRoutine fixtures require x64\n");
  return false;
#else
  if (childMode == nullptr || target == nullptr) {
    return false;
  }

  std::wstring commandLine = L"\"" + BkaesSelfPath() + L"\" ";
  commandLine += childMode;
  std::vector<wchar_t> mutableCommand = BkaesMutableCommandLine(commandLine);
  STARTUPINFOW startup = {};
  startup.cb = sizeof(startup);

  if (!CreateProcessW(nullptr, mutableCommand.data(), nullptr, nullptr, FALSE,
                      CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, nullptr,
                      &startup, &target->ProcessInfo)) {
    BkaesPrint("[FAIL] CreateProcessW suspended failed error=%lu\n",
               GetLastError());
    return false;
  }

  auto ntQueryInformationProcess =
      reinterpret_cast<NtQueryInformationProcessFn>(GetProcAddress(
          GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
  PROCESS_BASIC_INFORMATION basic = {};
  if (ntQueryInformationProcess == nullptr ||
      ntQueryInformationProcess(target->ProcessInfo.hProcess,
                                ProcessBasicInformation, &basic, sizeof(basic),
                                nullptr) < 0) {
    BkaesPrint("[FAIL] NtQueryInformationProcess failed\n");
    BkaesPpirCleanup(target);
    return false;
  }

  target->PebAddress = basic.PebBaseAddress;
  const ULONGLONG imageBaseAddress =
      reinterpret_cast<ULONGLONG>(target->PebAddress) +
      offsetof(PEB, Reserved3) + sizeof(PVOID);
  SIZE_T transferred = 0;
  if (!ReadProcessMemory(target->ProcessInfo.hProcess,
                         reinterpret_cast<LPCVOID>(imageBaseAddress),
                         &target->ImageBase, sizeof(target->ImageBase),
                         &transferred) ||
      transferred != sizeof(target->ImageBase) || target->ImageBase == 0) {
    BkaesPrint("[FAIL] reading target image base from PEB failed error=%lu\n",
               GetLastError());
    BkaesPpirCleanup(target);
    return false;
  }

  return true;
#endif
}

bool BkaesPpirFindImageSection(const char *name, PVOID *base, SIZE_T *size,
                               DWORD *characteristics) {
  if (name == nullptr || base == nullptr || size == nullptr ||
      std::strlen(name) > IMAGE_SIZEOF_SHORT_NAME) {
    return false;
  }

  auto imageBase = reinterpret_cast<BYTE *>(GetModuleHandleW(nullptr));
  auto dos = reinterpret_cast<IMAGE_DOS_HEADER *>(imageBase);
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
    return false;
  }
  auto nt = reinterpret_cast<IMAGE_NT_HEADERS64 *>(imageBase + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE ||
      nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    return false;
  }

  auto section = IMAGE_FIRST_SECTION(nt);
  for (WORD index = 0; index < nt->FileHeader.NumberOfSections;
       ++index, ++section) {
    char sectionName[IMAGE_SIZEOF_SHORT_NAME + 1] = {};
    std::memcpy(sectionName, section->Name, IMAGE_SIZEOF_SHORT_NAME);
    if (std::strcmp(sectionName, name) == 0) {
      *base = imageBase + section->VirtualAddress;
      *size =
          std::max<SIZE_T>(section->Misc.VirtualSize, section->SizeOfRawData);
      if (characteristics != nullptr) {
        *characteristics = section->Characteristics;
      }
      return true;
    }
  }
  return false;
}

ULONGLONG BkaesPpirRemoteAddress(const volatile void *localAddress,
                                 ULONGLONG remoteImageBase) {
  const ULONGLONG localImageBase =
      reinterpret_cast<ULONGLONG>(GetModuleHandleW(nullptr));
  const ULONGLONG local = reinterpret_cast<ULONGLONG>(localAddress);
  if (local < localImageBase) {
    return 0;
  }
  return remoteImageBase + (local - localImageBase);
}

bool BkaesPpirBuildRoutine(ULONGLONG remoteRoutine, ULONGLONG remoteState,
                           ULONGLONG remoteRelease,
                           std::array<BYTE, 50> *routine) {
  if (routine == nullptr) {
    return false;
  }

  std::array<BYTE, 50> code = {
      0xC7, 0x05, 0,    0,    0, 0, 0x45, 0x4E, 0x54, 0x52, 0xB9, 0x80, 0x96,
      0x98, 0x00, 0x83, 0x3D, 0, 0, 0,    0,    0x00, 0x75, 0x0F, 0xF3, 0x90,
      0xE2, 0xF3, 0xC7, 0x05, 0, 0, 0,    0,    0x54, 0x4F, 0x55, 0x54, 0xC3,
      0xC7, 0x05, 0,    0,    0, 0, 0x44, 0x4F, 0x4E, 0x45, 0xC3};

  if (!PatchRelativeDisplacement(&code, 2, remoteRoutine + 10, remoteState) ||
      !PatchRelativeDisplacement(&code, 17, remoteRoutine + 22,
                                 remoteRelease) ||
      !PatchRelativeDisplacement(&code, 30, remoteRoutine + 38, remoteState) ||
      !PatchRelativeDisplacement(&code, 41, remoteRoutine + 49, remoteState)) {
    BkaesPrint("[FAIL] callback data is outside x64 RIP-relative range\n");
    return false;
  }

  *routine = std::move(code);
  return true;
}

bool BkaesPpirPatchImageRoutine(BkaesPpirRemoteTarget *target,
                                ULONGLONG remoteRoutine,
                                const std::array<BYTE, 50> &routine,
                                DWORD *originalProtection) {
  if (target == nullptr || target->ProcessInfo.hProcess == nullptr) {
    return false;
  }

  DWORD oldProtection = 0;
  if (!VirtualProtectEx(target->ProcessInfo.hProcess,
                        reinterpret_cast<LPVOID>(remoteRoutine), routine.size(),
                        PAGE_EXECUTE_READWRITE, &oldProtection)) {
    BkaesPrint("[FAIL] VirtualProtectEx code cave failed error=%lu\n",
               GetLastError());
    return false;
  }

  SIZE_T transferred = 0;
  const bool written =
      WriteProcessMemory(target->ProcessInfo.hProcess,
                         reinterpret_cast<LPVOID>(remoteRoutine),
                         routine.data(), routine.size(), &transferred) &&
      transferred == routine.size();
  const bool flushed =
      written && FlushInstructionCache(target->ProcessInfo.hProcess,
                                       reinterpret_cast<LPCVOID>(remoteRoutine),
                                       routine.size());

  DWORD ignored = 0;
  const bool restored =
      VirtualProtectEx(target->ProcessInfo.hProcess,
                       reinterpret_cast<LPVOID>(remoteRoutine), routine.size(),
                       oldProtection, &ignored) != FALSE;
  if (!written || !flushed || !restored) {
    BkaesPrint("[FAIL] remote image patch failed write=%d flush=%d restore=%d "
               "error=%lu\n",
               written, flushed, restored, GetLastError());
    return false;
  }

  if (originalProtection != nullptr) {
    *originalProtection = oldProtection;
  }
  return true;
}

bool BkaesPpirArmPeb(BkaesPpirRemoteTarget *target, ULONGLONG remoteRoutine) {
  if (target == nullptr || target->ProcessInfo.hProcess == nullptr ||
      target->PebAddress == nullptr || remoteRoutine == 0) {
    return false;
  }

  MEMORY_BASIC_INFORMATION memory = {};
  if (VirtualQueryEx(target->ProcessInfo.hProcess,
                     reinterpret_cast<LPCVOID>(remoteRoutine), &memory,
                     sizeof(memory)) < sizeof(memory) ||
      memory.State != MEM_COMMIT || memory.Type != MEM_IMAGE ||
      !IsExecutableProtection(memory.Protect) ||
      reinterpret_cast<ULONGLONG>(memory.AllocationBase) != target->ImageBase) {
    BkaesPrint(
        "[FAIL] callback target is not executable target-image memory\n");
    return false;
  }

  const ULONGLONG fieldAddress =
      reinterpret_cast<ULONGLONG>(target->PebAddress) +
      offsetof(PEB, PostProcessInitRoutine);
  SIZE_T transferred = 0;
  if (!ReadProcessMemory(
          target->ProcessInfo.hProcess, reinterpret_cast<LPCVOID>(fieldAddress),
          &target->OriginalPostProcessInitRoutine,
          sizeof(target->OriginalPostProcessInitRoutine), &transferred) ||
      transferred != sizeof(target->OriginalPostProcessInitRoutine)) {
    BkaesPrint("[FAIL] reading PEB.PostProcessInitRoutine failed error=%lu\n",
               GetLastError());
    return false;
  }

  const PVOID routine = reinterpret_cast<PVOID>(remoteRoutine);
  transferred = 0;
  if (!WriteProcessMemory(target->ProcessInfo.hProcess,
                          reinterpret_cast<LPVOID>(fieldAddress), &routine,
                          sizeof(routine), &transferred) ||
      transferred != sizeof(routine)) {
    BkaesPrint("[FAIL] writing PEB.PostProcessInitRoutine failed error=%lu\n",
               GetLastError());
    return false;
  }

  BkaesPrint("[OK] armed PEB.PostProcessInitRoutine field=%p callback=%p "
             "original=%p\n",
             reinterpret_cast<PVOID>(fieldAddress), routine,
             target->OriginalPostProcessInitRoutine);
  return true;
}

bool BkaesPpirResumeAndVerify(BkaesPpirRemoteTarget *target,
                              ULONGLONG remoteState, ULONGLONG remoteRelease,
                              ULONGLONG remoteMainMarker,
                              const char *fixtureName) {
  if (target == nullptr || target->ProcessInfo.hThread == nullptr ||
      fixtureName == nullptr) {
    return false;
  }

  DWORD holdMs = 0;
  if (!ReadPreResumeHold(&holdMs)) {
    return false;
  }
  if (holdMs != 0) {
    BkaesPrint("[INFO] debugger hold child_pid=%lu hold_ms=%lu\n",
               target->ProcessInfo.dwProcessId, holdMs);
    Sleep(holdMs);
  }

  if (ResumeThread(target->ProcessInfo.hThread) == static_cast<DWORD>(-1)) {
    BkaesPrint("[FAIL] ResumeThread failed error=%lu\n", GetLastError());
    return false;
  }

  LONG state = 0;
  if (!WaitForRemoteLong(target->ProcessInfo.hProcess, remoteState,
                         kBkaesPpirEntered, kBkaesPpirTimeoutMs, &state)) {
    BkaesPrint("[FAIL] %s callback did not report entry state=0x%08lx\n",
               fixtureName, static_cast<ULONG>(state));
    return false;
  }

  LONG mainMarker = 0;
  if (!ReadRemoteLong(target->ProcessInfo.hProcess, remoteMainMarker,
                      &mainMarker) ||
      mainMarker == kBkaesPpirMain) {
    BkaesPrint("[FAIL] %s normal entry ran before blocked loader callback\n",
               fixtureName);
    return false;
  }

  if (!WriteRemoteLong(target->ProcessInfo.hProcess, remoteRelease, 1)) {
    BkaesPrint("[FAIL] %s could not release loader callback error=%lu\n",
               fixtureName, GetLastError());
    return false;
  }

  if (!WaitForRemoteLong(target->ProcessInfo.hProcess, remoteState,
                         kBkaesPpirDone, kBkaesPpirTimeoutMs, &state)) {
    BkaesPrint("[FAIL] %s callback did not return cleanly state=0x%08lx\n",
               fixtureName, static_cast<ULONG>(state));
    return false;
  }

  if (!WaitForRemoteLong(target->ProcessInfo.hProcess, remoteMainMarker,
                         kBkaesPpirMain, kBkaesPpirTimeoutMs, &mainMarker)) {
    BkaesPrint("[FAIL] %s normal entry was not reached marker=0x%08lx\n",
               fixtureName, static_cast<ULONG>(mainMarker));
    return false;
  }

  const DWORD waitResult =
      WaitForSingleObject(target->ProcessInfo.hProcess, kBkaesPpirTimeoutMs);
  DWORD exitCode = STILL_ACTIVE;
  if (waitResult != WAIT_OBJECT_0 ||
      !GetExitCodeProcess(target->ProcessInfo.hProcess, &exitCode) ||
      exitCode != 0) {
    BkaesPrint("[FAIL] %s target did not exit normally wait=%lu exit=%lu\n",
               fixtureName, waitResult, exitCode);
    return false;
  }

  BkaesPrint("[OK] %s order verified: callback ENTERED while main blocked; "
             "callback DONE; main MAIN; exit=0\n",
             fixtureName);
  return true;
}

void BkaesPpirCleanup(BkaesPpirRemoteTarget *target, bool terminate) {
  if (target == nullptr) {
    return;
  }
  BkaesCleanupProcess(&target->ProcessInfo, terminate);
  target->PebAddress = nullptr;
  target->ImageBase = 0;
  target->OriginalPostProcessInitRoutine = nullptr;
}
