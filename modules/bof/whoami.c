/* SquidC5 lab BOF-style whoami - authorized only */
#ifdef _WIN32
#include <windows.h>
void go(char* args, int alen) { (void)args; (void)alen; /* BeaconPrintf identity */ }
#else
void go(char* args, int alen) { (void)args; (void)alen; }
#endif
