#ifndef AARCH64_TARGET_SIGNAL_H
#define AARCH64_TARGET_SIGNAL_H

/* this struct defines a stack used during syscall handling */

typedef struct target_sigaltstack {
    abi_ulong ss_sp;
    abi_int ss_flags;
    abi_ulong ss_size;
} target_stack_t;


/*
 * sigaltstack controls
 */
#define TARGET_SS_ONSTACK 1
#define TARGET_SS_DISABLE 2

#define TARGET_MINSIGSTKSZ 2048
#define TARGET_SIGSTKSZ 8192

#include "../generic/signal.h"

#define TARGET_SEGV_MTEAERR  8  /* Asynchronous ARM MTE error */
#define TARGET_SEGV_MTESERR  9  /* Synchronous ARM MTE exception */

#define TARGET_ARCH_HAS_SETUP_FRAME
#define TARGET_ARCH_HAS_SIGTRAMP_PAGE 1

#endif /* AARCH64_TARGET_SIGNAL_H */
