#include "..\common\bkaes_sample.h"

using BkaesHookProc = LRESULT(CALLBACK*)(int, WPARAM, LPARAM);

int RunSetWindowsHookEx()
{
    std::wstring dllPath = BkaesJoinPath(BkaesSelfDirectory(), L"bb_unsigned_plugin.dll");
    HMODULE plugin = LoadLibraryW(dllPath.c_str());
    MSG msg = {};

    if (plugin == nullptr)
    {
        BkaesPrint("[FAIL] LoadLibrary plugin path=%ls err=%lu\n", dllPath.c_str(), GetLastError());
        return 1;
    }

    auto hookProc = (BkaesHookProc)GetProcAddress(plugin, "BkaesNoopHookProc");
    if (hookProc == nullptr)
    {
        FreeLibrary(plugin);
        return 1;
    }

    PeekMessageW(&msg, nullptr, WM_USER, WM_USER, PM_NOREMOVE);
    HHOOK hook = SetWindowsHookExW(WH_GETMESSAGE, hookProc, plugin, GetCurrentThreadId());
    if (hook != nullptr)
    {
        PostThreadMessageW(GetCurrentThreadId(), WM_USER + 42, 0, 0);
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        UnhookWindowsHookEx(hook);
    }

    BkaesSettleTelemetry();
    BkaesPrint("[OK] SetWindowsHookEx local hook dll=%ls hook=%p\n", dllPath.c_str(), hook);
    FreeLibrary(plugin);
    return hook != nullptr ? 0 : 1;
}
