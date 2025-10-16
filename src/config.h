#ifndef CONFIG_H
#define CONFIG_H

#define CR_REMOTE_THREAD_EXECUTION 1 // 0 = no remote thread, 1 = create thread to call Sleep
#define RS_DBGOUT 1 // 1=enable debug output, 0=disable

#if RS_DBGOUT
#include <windows.h>
#include <cstdio>
#define DBGPRINT(fmt, ...) do { \
        char __dbg_buf[512]; \
        int __dbg_len = snprintf(__dbg_buf, sizeof(__dbg_buf), "[RS7] " fmt "\n", ##__VA_ARGS__); \
        if (__dbg_len > 0) { \
            printf("%s", __dbg_buf); \
            OutputDebugStringA(__dbg_buf); \
        } \
    } while (0)
#else
#define DBGPRINT(fmt, ...) do {} while (0)
#endif

#endif // CONFIG_H