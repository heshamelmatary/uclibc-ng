/* longjmp, RISC-V version.
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

ENTRY (__longjmp)
	REG_L cra,  0*SZREG(ca0)
	REG_L cs0,  1*SZREG(ca0)
	REG_L cs1,  2*SZREG(ca0)
	REG_L cs2,  3*SZREG(ca0)
	REG_L cs3,  4*SZREG(ca0)
	REG_L cs4,  5*SZREG(ca0)
	REG_L cs5,  6*SZREG(ca0)
	REG_L cs6,  7*SZREG(ca0)
	REG_L cs7,  8*SZREG(ca0)
	REG_L cs8,  9*SZREG(ca0)
	REG_L cs9, 10*SZREG(ca0)
	REG_L cs10,11*SZREG(ca0)
	REG_L cs11,12*SZREG(ca0)
	REG_L csp, 13*SZREG(ca0)

#ifndef __riscv_float_abi_soft
	FREG_L fs0, 14*SZREG+ 0*SZFREG(a0)
	FREG_L fs1, 14*SZREG+ 1*SZFREG(a0)
	FREG_L fs2, 14*SZREG+ 2*SZFREG(a0)
	FREG_L fs3, 14*SZREG+ 3*SZFREG(a0)
	FREG_L fs4, 14*SZREG+ 4*SZFREG(a0)
	FREG_L fs5, 14*SZREG+ 5*SZFREG(a0)
	FREG_L fs6, 14*SZREG+ 6*SZFREG(a0)
	FREG_L fs7, 14*SZREG+ 7*SZFREG(a0)
	FREG_L fs8, 14*SZREG+ 8*SZFREG(a0)
	FREG_L fs9, 14*SZREG+ 9*SZFREG(a0)
	FREG_L fs10,14*SZREG+10*SZFREG(a0)
	FREG_L fs11,14*SZREG+11*SZFREG(a0)
#endif

	seqz a0, a1
	cincoffset  ca0, ca0, a1   # a0 = (a1 == 0) ? 1 : a1
	cret

END (__longjmp)
libc_hidden_def(__longjmp)
