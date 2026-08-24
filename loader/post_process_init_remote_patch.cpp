#include "post_process_init_common.h"

#pragma section(".ppirc", read, execute)
__declspec(allocate(".ppirc")) const BYTE gPpirRemoteCodeCave[128] = {0xCC};

#pragma section(".ppird", read, write)
__declspec(allocate(".ppird")) BkaesPpirSharedState gPpirRemotePatchState = {
    kBkaesPpirSignature, kBkaesPpirIdle, 0};
__declspec(allocate(".ppird")) volatile LONG gPpirRemotePatchMainMarker = 0;

namespace {

constexpr wchar_t kChildMode[] = L"--ppir-remote-patch-child";

int RunChild() {
  InterlockedExchange(&gPpirRemotePatchMainMarker, kBkaesPpirMain);
  BkaesPrint("[OK] remote-patch child reached normal executable entry\n");
  Sleep(1200);
  return 0;
}

} // namespace

int RunPostProcessInitRemotePatch(int argc, wchar_t **argv) {
  if (argc == 2 && std::wcscmp(argv[1], kChildMode) == 0) {
    return RunChild();
  }
  if (argc != 1) {
    BkaesPrint("[FAIL] unexpected arguments\n");
    return 2;
  }

  PVOID codeSection = nullptr;
  SIZE_T codeCaveSize = 0;
  DWORD characteristics = 0;
  if (!BkaesPpirFindImageSection(".ppirc", &codeSection, &codeCaveSize,
                                 &characteristics) ||
      codeCaveSize < sizeof(gPpirRemoteCodeCave) ||
      (characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) {
    BkaesPrint("[FAIL] executable image code cave is absent or invalid\n");
    return 1;
  }

  auto localCodeCave = const_cast<BYTE *>(gPpirRemoteCodeCave);
  if (localCodeCave < codeSection ||
      localCodeCave + sizeof(gPpirRemoteCodeCave) >
          static_cast<BYTE *>(codeSection) + codeCaveSize) {
    BkaesPrint("[FAIL] code cave symbol is outside .ppirc\n");
    return 1;
  }

  BkaesPpirRemoteTarget target = {};
  if (!BkaesPpirLaunchSuspended(kChildMode, &target)) {
    return 1;
  }

  const ULONGLONG remoteRoutine =
      BkaesPpirRemoteAddress(localCodeCave, target.ImageBase);
  const ULONGLONG remoteState =
      BkaesPpirRemoteAddress(&gPpirRemotePatchState.State, target.ImageBase);
  const ULONGLONG remoteRelease =
      BkaesPpirRemoteAddress(&gPpirRemotePatchState.Release, target.ImageBase);
  const ULONGLONG remoteMain =
      BkaesPpirRemoteAddress(&gPpirRemotePatchMainMarker, target.ImageBase);

  std::array<BYTE, 50> routine = {};
  DWORD originalProtection = 0;
  bool verified = remoteRoutine != 0 && remoteState != 0 &&
                  remoteRelease != 0 && remoteMain != 0 &&
                  BkaesPpirBuildRoutine(remoteRoutine, remoteState,
                                        remoteRelease, &routine) &&
                  BkaesPpirPatchImageRoutine(&target, remoteRoutine, routine,
                                             &originalProtection) &&
                  BkaesPpirArmPeb(&target, remoteRoutine) &&
                  BkaesPpirResumeAndVerify(&target, remoteState, remoteRelease,
                                           remoteMain, "remote-image-patch");

  if (verified) {
    BkaesPrint(
        "[OK] remote image callback bytes=%zu original_protect=0x%08lx\n",
        routine.size(), originalProtection);
    BkaesWriteAuditText(
        L"post_process_init_remote_patch.txt",
        "supplemental_fixture_result=callback_before_main_then_normal_exit\n"
        "callback_storage=remote_write_into_executable_image_section\n"
        "peb_field=written_by_parent_after_create_suspended\n");
    BkaesSettleTelemetry(2500);
  }

  BkaesPpirCleanup(&target, !verified);
  return verified ? 0 : 1;
}
