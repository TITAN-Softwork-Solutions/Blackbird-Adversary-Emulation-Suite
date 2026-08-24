#include "post_process_init_common.h"

#pragma section(".ppird", read, write)
__declspec(allocate(".ppird")) BkaesPpirSharedState gPpirPrepatchedState = {
    kBkaesPpirPrepatchedSignature, kBkaesPpirIdle, 0};
__declspec(allocate(".ppird")) volatile LONG gPpirPrepatchedMainMarker = 0;

namespace {

constexpr wchar_t kChildMode[] = L"--ppir-prepatched-child";

int RunChild() {
  InterlockedExchange(&gPpirPrepatchedMainMarker, kBkaesPpirMain);
  BkaesPrint("[OK] prepatched child reached normal executable entry\n");
  Sleep(1200);
  return 0;
}

} // namespace

int RunPostProcessInitPrepatched(int argc, wchar_t **argv) {
  if (argc == 2 && std::wcscmp(argv[1], kChildMode) == 0) {
    return RunChild();
  }
  if (argc != 1) {
    BkaesPrint("[FAIL] unexpected arguments\n");
    return 2;
  }

  PVOID localRoutine = nullptr;
  SIZE_T routineSize = 0;
  DWORD characteristics = 0;
  if (!BkaesPpirFindImageSection(".ppir", &localRoutine, &routineSize,
                                 &characteristics) ||
      routineSize < 50 || (characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) {
    BkaesPrint(
        "[FAIL] post-link .ppir callback section is absent or invalid\n");
    return 1;
  }

  BkaesPpirRemoteTarget target = {};
  if (!BkaesPpirLaunchSuspended(kChildMode, &target)) {
    return 1;
  }

  const ULONGLONG remoteRoutine =
      BkaesPpirRemoteAddress(localRoutine, target.ImageBase);
  const ULONGLONG remoteState =
      BkaesPpirRemoteAddress(&gPpirPrepatchedState.State, target.ImageBase);
  const ULONGLONG remoteRelease =
      BkaesPpirRemoteAddress(&gPpirPrepatchedState.Release, target.ImageBase);
  const ULONGLONG remoteMain =
      BkaesPpirRemoteAddress(&gPpirPrepatchedMainMarker, target.ImageBase);

  bool verified = remoteRoutine != 0 && remoteState != 0 &&
                  remoteRelease != 0 && remoteMain != 0 &&
                  BkaesPpirArmPeb(&target, remoteRoutine) &&
                  BkaesPpirResumeAndVerify(&target, remoteState, remoteRelease,
                                           remoteMain, "prepatched-image");

  if (verified) {
    BkaesWriteAuditText(
        L"post_process_init_prepatched.txt",
        "supplemental_fixture_result=callback_before_main_then_normal_exit\n"
        "callback_storage=post_link_executable_image_section\n"
        "peb_field=written_by_parent_after_create_suspended\n");
    BkaesSettleTelemetry(2500);
  }

  BkaesPpirCleanup(&target, !verified);
  return verified ? 0 : 1;
}
