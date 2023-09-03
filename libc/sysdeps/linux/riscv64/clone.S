/* Wrapper around clone system call.  RISC-V version.
   Copyright (C) 2022-2023 Hesham Almatary <hesham.almatary@cl.cam.ac.uk>
   Copyright (C) 1996-2018 Free Software Foundation, Inc.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library.  If not, see
   <http://www.gnu.org/licenses/>.  */

/* clone() is even more special than fork() as it mucks with stacks
   and invokes a function in the right context after its all over.  */

#include <sys/asm.h>
#include <sysdep.h>
#define _ERRNO_H	1
#include <bits/errno.h>

/* int clone(int (*fn)(void *arg), void *child_stack, int flags, void *arg,
	     void *parent_tidptr, void *tls, void *child_tidptr) */

	.text
LEAF (clone)

	/* Sanity check arguments.  */
	beqz		a0,L (invalid)	/* No NULL function pointers.  */
	beqz		a1,L (invalid)	/* No NULL stack pointers.  */

	cincoffset		ca1,ca1,-16	/* Reserve argument save space.  */
	REG_S		ca0,0(ca1)	/* Save function pointer.  */
	REG_S		ca3,SZREG(ca1)	/* Save argument pointer.  */

	/* The syscall expects the args to be in different slots.  */
	cmove		ca0,ca2
	cmove		ca2,ca4
	cmove		ca3,ca5
	cmove		ca4,ca6

	/* Do the system call.  */
	li		a7,__NR_clone
	scall

	bltz		a0,L (error)
	beqz		a0,L (thread_start)

	/* Successful return from the parent.  */
	cret

L (invalid):
	li		a0, -EINVAL
	/* Something bad happened -- no child created.  */
L (error):
	j		__syscall_error
	END (clone)

/* Load up the arguments to the function.  Put this block of code in
   its own function so that we can terminate the stack trace with our
   debug info.  */

ENTRY (__thread_start)
L (thread_start):
	/* Restore the arg for user's function.  */
	REG_L		ca1,0(csp)	/* Function pointer.  */
	REG_L		ca0,SZREG(csp)	/* Argument pointer.  */

	/* Call the user's function.  */
	cjalr		ca1

	/* Call exit with the function's return value.  */
	li		a7, __NR_exit
	scall

	END (__thread_start)
