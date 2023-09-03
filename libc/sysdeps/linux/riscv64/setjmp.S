/* setjmp for RISC-V.
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

#include <sysdep.h>
#include <sys/asm.h>

ENTRY (_setjmp)
  li	a1, 0
  j	HIDDEN_JUMPTARGET (__sigsetjmp)
END (_setjmp)
ENTRY (setjmp)
  li	a1, 1
  /* Fallthrough */
END (setjmp)
ENTRY (__sigsetjmp)
	REG_S cra,  0*SZREG(ca0)
	REG_S cs0,  1*SZREG(ca0)
	REG_S cs1,  2*SZREG(ca0)
	REG_S cs2,  3*SZREG(ca0)
	REG_S cs3,  4*SZREG(ca0)
	REG_S cs4,  5*SZREG(ca0)
	REG_S cs5,  6*SZREG(ca0)
	REG_S cs6,  7*SZREG(ca0)
	REG_S cs7,  8*SZREG(ca0)
	REG_S cs8,  9*SZREG(ca0)
	REG_S cs9, 10*SZREG(ca0)
	REG_S cs10,11*SZREG(ca0)
	REG_S cs11,12*SZREG(ca0)
	REG_S csp, 13*SZREG(ca0)

#ifndef __riscv_float_abi_soft
	FREG_S fs0, 14*SZREG+ 0*SZFREG(a0)
	FREG_S fs1, 14*SZREG+ 1*SZFREG(a0)
	FREG_S fs2, 14*SZREG+ 2*SZFREG(a0)
	FREG_S fs3, 14*SZREG+ 3*SZFREG(a0)
	FREG_S fs4, 14*SZREG+ 4*SZFREG(a0)
	FREG_S fs5, 14*SZREG+ 5*SZFREG(a0)
	FREG_S fs6, 14*SZREG+ 6*SZFREG(a0)
	FREG_S fs7, 14*SZREG+ 7*SZFREG(a0)
	FREG_S fs8, 14*SZREG+ 8*SZFREG(a0)
	FREG_S fs9, 14*SZREG+ 9*SZFREG(a0)
	FREG_S fs10,14*SZREG+10*SZFREG(a0)
	FREG_S fs11,14*SZREG+11*SZFREG(a0)
#endif

#if !IS_IN_libc && IS_IN_rtld
  /* In ld.so we never save the signal mask.  */
  li a0, 0
  cret
#else
  /* Make a tail call to __sigjmp_save; it takes the same args.  */
  j __sigjmp_save
#endif


END (__sigsetjmp)

hidden_def (__sigsetjmp)
weak_alias (_setjmp, __GI__setjmp)
