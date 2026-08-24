#pragma once

#include "bkaes_sample.h"

#include <array>

constexpr ULONG kBkaesPpirSignature = 0x31524950;           // "PIR1"
constexpr ULONG kBkaesPpirPrepatchedSignature = 0x31505050; // "PPP1"
constexpr LONG kBkaesPpirIdle = 0;
constexpr LONG kBkaesPpirEntered = 0x52544E45;  // "ENTR"
constexpr LONG kBkaesPpirDone = 0x454E4F44;     // "DONE"
constexpr LONG kBkaesPpirTimedOut = 0x54554F54; // "TOUT"
constexpr LONG kBkaesPpirMain = 0x4E49414D;     // "MAIN"
constexpr DWORD kBkaesPpirTimeoutMs = 10000;

struct BkaesPpirSharedState {
  ULONG Signature;
  volatile LONG State;
  volatile LONG Release;
};

struct BkaesPpirRemoteTarget {
  PROCESS_INFORMATION ProcessInfo{};
  PVOID PebAddress = nullptr;
  ULONGLONG ImageBase = 0;
  PVOID OriginalPostProcessInitRoutine = nullptr;
};

bool BkaesPpirLaunchSuspended(const wchar_t *childMode,
                              BkaesPpirRemoteTarget *target);
bool BkaesPpirFindImageSection(const char *name, PVOID *base, SIZE_T *size,
                               DWORD *characteristics = nullptr);
ULONGLONG BkaesPpirRemoteAddress(const volatile void *localAddress,
                                 ULONGLONG remoteImageBase);
bool BkaesPpirBuildRoutine(ULONGLONG remoteRoutine, ULONGLONG remoteState,
                           ULONGLONG remoteRelease,
                           std::array<BYTE, 50> *routine);
bool BkaesPpirPatchImageRoutine(BkaesPpirRemoteTarget *target,
                                ULONGLONG remoteRoutine,
                                const std::array<BYTE, 50> &routine,
                                DWORD *originalProtection);
bool BkaesPpirArmPeb(BkaesPpirRemoteTarget *target, ULONGLONG remoteRoutine);
bool BkaesPpirResumeAndVerify(BkaesPpirRemoteTarget *target,
                              ULONGLONG remoteState, ULONGLONG remoteRelease,
                              ULONGLONG remoteMainMarker,
                              const char *fixtureName);
void BkaesPpirCleanup(BkaesPpirRemoteTarget *target, bool terminate = true);
