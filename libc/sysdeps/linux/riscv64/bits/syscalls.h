/*
 * Copyright (C) 2022-2023 Hesham Almatary <hesham.almatary@cl.cam.ac.uk>
 * Copyright (C) 2018 by Waldemar Brodkorb <wbx@uclibc-ng.org>
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 * ported from GNU C Library
 */

#ifndef _BITS_SYSCALLS_H
#define _BITS_SYSCALLS_H
#ifndef _SYSCALL_H
# error "Never use <bits/syscalls.h> directly; include <sys/syscall.h> instead."
#endif

#define INTERNAL_SYSCALL_NCS(name, err, nr, args...)	\
  ({ __uintcap_t _sys_result;					\
     {							\
	register __intcap_t _a7 __asm__ ("ca7");		\
	LOAD_ARGS_##nr (args)				\
	_a7 = (name);					\
							\
        __asm__ volatile (				\
		"scall\n\t"				\
		: "=C" (_a0) 				\
		: "C"(_a7) ASM_ARGS_##nr  		\
		: "memory"); 				\
	_sys_result = _a0;				\
     } 							\
     _sys_result; 					\
  })

/* Macros for setting up inline __asm__ input regs */
# define ASM_ARGS_0
# define ASM_ARGS_1	, "C" (_a0)
# define ASM_ARGS_2	ASM_ARGS_1, "C" (_a1)
# define ASM_ARGS_3	ASM_ARGS_2, "C" (_a2)
# define ASM_ARGS_4	ASM_ARGS_3, "C" (_a3)
# define ASM_ARGS_5	ASM_ARGS_4, "C" (_a4)
# define ASM_ARGS_6	ASM_ARGS_5, "C" (_a5)
# define ASM_ARGS_7	ASM_ARGS_6, "C" (_a6)

/* Macros for converting sys-call wrapper args into sys call args */
# define LOAD_ARGS_0()				\
  register __uintcap_t _a0 __asm__ ("ca0");
# define LOAD_ARGS_1(a0)			\
  __uintcap_t _a0tmp;					\
  LOAD_ARGS_0 ()				\
  _a0tmp = (__uintcap_t) (a0);				\
  _a0 = _a0tmp;
# define LOAD_ARGS_2(a0, a1)			\
  register __uintcap_t _a1 __asm__ ("ca1");		\
  __uintcap_t _a1tmp;					\
  LOAD_ARGS_1 (a0)				\
  _a1tmp = (__uintcap_t) (a1);				\
  _a1 = _a1tmp;
# define LOAD_ARGS_3(a0, a1, a2)		\
  register __uintcap_t _a2 __asm__ ("ca2");		\
  __uintcap_t _a2tmp;					\
  LOAD_ARGS_2 (a0, a1)				\
  _a2tmp = (__uintcap_t) (a2);				\
  _a2 = _a2tmp;
# define LOAD_ARGS_4(a0, a1, a2, a3)		\
  register __uintcap_t _a3 __asm__ ("ca3");		\
  __uintcap_t _a3tmp;					\
  LOAD_ARGS_3 (a0, a1, a2)			\
  _a3tmp = (__uintcap_t) (a3);				\
  _a3 = _a3tmp;
# define LOAD_ARGS_5(a0, a1, a2, a3, a4)	\
  register __uintcap_t _a4 __asm__ ("ca4");		\
  __uintcap_t _a4tmp;					\
  LOAD_ARGS_4 (a0, a1, a2, a3)			\
  _a4tmp = (__uintcap_t) (a4);				\
  _a4 = _a4tmp;
# define LOAD_ARGS_6(a0, a1, a2, a3, a4, a5)	\
  register __uintcap_t _a5 __asm__ ("ca5");		\
  __uintcap_t _a5tmp;					\
  LOAD_ARGS_5 (a0, a1, a2, a3, a4)		\
  _a5tmp = (__uintcap_t) (a5);				\
  _a5 = _a5tmp;
# define LOAD_ARGS_7(a0, a1, a2, a3, a4, a5, a6)\
  register __uintcap_t _a6 __asm__ ("ca6");		\
  __uintcap_t _a6tmp;					\
  LOAD_ARGS_6 (a0, a1, a2, a3, a4, a5)		\
  _a6tmp = (__uintcap_t) (a6);				\
  _a6 = _a6tmp;

#endif
