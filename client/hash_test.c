/*
 * hash_test.c — verifica hash ROR13 per etw_patch.c e process_inject.c
 * Copre: 5 funzioni ETW + 5 funzioni NT (process_inject) + NtTraceEvent
 * Compila: gcc hash_test.c -o hash_test && ./hash_test
 */
#include <stdio.h>
#include <string.h>

static unsigned int ror13(unsigned int v) {
    return (v >> 13) | (v << 19);
}

static unsigned int hash_ascii(const char *s) {
    unsigned int h = 0;
    do { h = ror13(h); h += (unsigned int)(*s); } while (*++s);
    return h;
}

int main(void) {
        struct { const char *name; unsigned int expected; } tbl[] = {
        { "EtwEventWrite",         0x2047C3EEU },
        { "EtwEventWriteEx",       0x1418FC00U },
        { "EtwEventWriteFull",     0x0B9EFFB1U },
        { "EtwEventWriteString",   0x772FDBF0U },
        { "EtwEventWriteTransfer", 0x59174C67U },
        { "NtCreateSection",        0x5BB29BCBU },
{ "NtMapViewOfSection",     0xD5159B94U },
{ "NtUnmapViewOfSection",   0xF21037D0U },
{ "NtClose",                0xDCD44C5FU },
{ "RtlCreateUserThread",    0x442F2041U },
{ "NtTraceEvent",           0xE39F1624U },  /* etw_patch.c — 6a funzione */
    };

    int ok = 1;
    printf("%-30s  %-12s  %-12s  %s\n",
           "Funzione", "Calcolato", "Atteso", "Stato");
    printf("%-30s  %-12s  %-12s  %s\n",
           "--------", "---------", "-------", "-----");

    for (size_t i = 0; i < sizeof(tbl)/sizeof(tbl[0]); i++) {
        unsigned int got = hash_ascii(tbl[i].name);
        int match = (got == tbl[i].expected);
        printf("%-30s  0x%08X  0x%08X  %s\n",
               tbl[i].name, got, tbl[i].expected,
               match ? "OK" : "MISMATCH !!!");
        if (!match) ok = 0;
    }

    printf("\n%s\n", ok ? "Tutti gli hash corretti." : "ERRORE: uno o piu hash errati — aggiorna i #define in etw_patch.c");
    return ok ? 0 : 1;
}
