/*
 * Copyright (C) 2022-2023 Hesham Almatary <hesham.almatary@cl.cam.ac.uk>
 * syscall() library function
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <stdarg.h>
#include <sys/syscall.h>
#include <unistd.h>

__uintcap_t syscall(__uintcap_t sysnum, ...)
{

	uintptr_t arg1, arg2, arg3, arg4, arg5, arg6;
	va_list arg;

	va_start (arg, sysnum);
	arg1 = va_arg (arg, uintptr_t);
	arg2 = va_arg (arg, uintptr_t);
	arg3 = va_arg (arg, uintptr_t);
	arg4 = va_arg (arg, uintptr_t);
	arg5 = va_arg (arg, uintptr_t);
	arg6 = va_arg (arg, uintptr_t);
	va_end (arg);

        __asm__ volatile ( "" ::: "memory" );
	return INLINE_SYSCALL_NCS(sysnum, 6, arg1, arg2, arg3, arg4, arg5, arg6);
}
