/* Copyright (C) 2002 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@redhat.com>, 2002.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#include <errno.h>
#include <pthreadP.h>


int
__pthread_mutexattr_settype (attr, kind)
     pthread_mutexattr_t *attr;
     int kind;
{
  struct pthread_mutexattr *iattr;

  if (kind < PTHREAD_MUTEX_NORMAL || kind > PTHREAD_MUTEX_ADAPTIVE_NP)
    return EINVAL;

  iattr = (struct pthread_mutexattr *) attr;

  /* We use bit 31 to signal whether the mutex is going to be
     process-shared or not.  */
  iattr->mutexkind = (iattr->mutexkind & 0x80000000) | kind;

  return 0;
}
weak_alias (__pthread_mutexattr_settype, pthread_mutexattr_setkind_np)
strong_alias (__pthread_mutexattr_settype, pthread_mutexattr_settype)