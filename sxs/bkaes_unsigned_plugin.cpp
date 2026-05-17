#include "../common/bkaes_common.h"

extern "C" __declspec(dllexport) DWORD BkaesPluginMarker()
{
    return GetCurrentProcessId();
}

extern "C" __declspec(dllexport) LRESULT CALLBACK BkaesNoopHookProc(int code, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(code);
    UNREFERENCED_PARAMETER(wParam);
    UNREFERENCED_PARAMETER(lParam);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
    UNREFERENCED_PARAMETER(module);
    UNREFERENCED_PARAMETER(reserved);

    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(module);
    }
    return TRUE;
}
