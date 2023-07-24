/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_TRAP_PF_H
#define _ASM_X86_TRAP_PF_H

#include <linux/bits.h>  /* BIT() macro */

/*
 * Page fault error code bits:
 *
 *   bit 0 ==	 0: no page found	1: protection fault
 *   bit 1 ==	 0: read access		1: write access
 *   bit 2 ==	 0: kernel-mode access	1: user-mode access
 *   bit 3 ==				1: use of reserved bit detected
 *   bit 4 ==				1: fault was an instruction fetch
 *   bit 5 ==				1: protection keys block access
 *   bit 15 ==				1: SGX MMU page-fault
 *   bit 31 ==				1: fault was due to RMP violation
 */
enum x86_pf_error_code {
	X86_PF_PROT	=		BIT_ULL(0),
	X86_PF_WRITE	=		BIT_ULL(1),
	X86_PF_USER	=		BIT_ULL(2),
	X86_PF_RSVD	=		BIT_ULL(3),
	X86_PF_INSTR	=		BIT_ULL(4),
	X86_PF_PK	=		BIT_ULL(5),
	X86_PF_SGX	=		BIT_ULL(15),
	X86_PF_RMP	=		BIT_ULL(31),
};

#endif /* _ASM_X86_TRAP_PF_H */
