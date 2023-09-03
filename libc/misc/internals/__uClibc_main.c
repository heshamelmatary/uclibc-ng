/*
 * Copyright (C) 2022-2023 Hesham Almatary <hesham.almatary@cl.cam.ac.uk>
 * Copyright (C) 2006 by Steven J. Hill <sjhill@realitydiluted.com>
 * Copyright (C) 2001 by Manuel Novoa III <mjn3@uclibc.org>
 * Copyright (C) 2000-2005 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 *
 * __uClibc_main is the routine to be called by all the arch-specific
 * versions of crt1.S in uClibc.
 *
 * It is meant to handle any special initialization needed by the library
 * such as setting the global variable(s) __environ (environ) and
 * initializing the stdio package.  Using weak symbols, the latter is
 * avoided in the static library case.
 */

#include <features.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <link.h>
#include <bits/uClibc_page.h>
#include <paths.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#ifndef __ARCH_HAS_NO_LDSO__
#include <fcntl.h>
#endif
#ifdef __UCLIBC_HAS_THREADS_NATIVE__
#include <not-cancel.h>
#include <atomic.h>
#include <tls.h>
#endif
#ifdef __UCLIBC_HAS_THREADS__
#include <pthread.h>
#endif
#ifdef __UCLIBC_HAS_LOCALE__
#include <locale.h>
#endif

/* Are we in a secure process environment or are we dealing
 * with setuid stuff?  If we are dynamically linked, then we
 * already have _dl_secure, otherwise we need to re-examine
 * auxvt[] below.
 */
int _pe_secure = 0;
libc_hidden_data_def(_pe_secure)

#if !defined(SHARED) && defined(__FDPIC__)
struct funcdesc_value
{
	void *entry_point;
	void *got_value;
} __attribute__((__aligned__(16)));


/* Prevent compiler optimization that removes GOT assignment.

  Due to optimization passes (block split and move), in the rare case
  where use r9 is the single instruction in a block we can have the
  following behaviour:
  - this block is marked as a forward block since use is not
  considered as an active instruction after reload pass.

  - In this case a jump in this block can be moved to the start of the
  next one and so remove use in this flow of instructions which can
  lead to a removal of r9 restoration after a call. */
#define _dl_stabilize_funcdesc(val)			\
	({ __asm__ ("" : "+m" (*(val))); (val); })

static void fdpic_init_array_jump(void *addr)
{
	struct funcdesc_value *fm = (struct funcdesc_value *) fdpic_init_array_jump;
	struct funcdesc_value fd = {addr, fm->got_value};

	void (*pf)(void) = (void*) _dl_stabilize_funcdesc(&fd);

	(*pf)();
}
#endif

#ifndef SHARED
void *__libc_stack_end = NULL;

# ifdef __UCLIBC_HAS_SSP__
#  include <dl-osinfo.h>
static uintptr_t stack_chk_guard;
#  ifndef THREAD_SET_STACK_GUARD
/* Only exported for architectures that don't store the stack guard canary
 * in thread local area. */
/* for gcc-4.1 non-TLS */
uintptr_t __stack_chk_guard attribute_relro;
#  endif
# endif

/*
 * Needed to initialize _dl_phdr when statically linked
 */

void internal_function _dl_aux_init (ElfW(auxv_t) *av);

#ifdef __UCLIBC_HAS_THREADS__
/*
 * uClibc internal locking requires that we have weak aliases
 * for dummy functions in case a single threaded application is linked.
 * This needs to be in compilation unit that is pulled always
 * in or linker will disregard these weaks.
 */

static int __pthread_return_0 (pthread_mutex_t *unused) { return 0; }
weak_alias (__pthread_return_0, __pthread_mutex_lock)
weak_alias (__pthread_return_0, __pthread_mutex_trylock)
weak_alias (__pthread_return_0, __pthread_mutex_unlock)

int weak_function
__pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr)
{
        return 0;
}

void weak_function
_pthread_cleanup_push_defer(struct _pthread_cleanup_buffer *__buffer,
                            void (*__routine) (void *), void *__arg)
{
        __buffer->__routine = __routine;
        __buffer->__arg = __arg;
}

void weak_function
_pthread_cleanup_pop_restore(struct _pthread_cleanup_buffer *__buffer,
                             int __execute)
{
        if (__execute)
                __buffer->__routine(__buffer->__arg);
}

#endif /* __UCLIBC_HAS_THREADS__ */

#endif /* !SHARED */

/* Defeat compiler optimization which assumes function addresses are never NULL */
static __always_inline int not_null_ptr(const void *p)
{
	const void *q;
	__asm__ (""
		: "=C" (q) /* output */
		: "0" (p) /* input */
	);
	return q != 0;
}

/*
 * Prototypes.
 */
#ifdef __UCLIBC_HAS_THREADS__
#if !defined (__UCLIBC_HAS_THREADS_NATIVE__) || defined (SHARED)
extern void weak_function __pthread_initialize_minimal(void);
#else
extern void __pthread_initialize_minimal(void);
#endif
#endif

#ifndef SHARED
extern void __libc_setup_tls (size_t tcbsize, size_t tcbalign);
#endif

/* If __UCLIBC_FORMAT_SHARED_FLAT__, all array initialisation and finalisation
 * is handled by the routines passed to __uClibc_main().  */
#if defined (__UCLIBC_CTOR_DTOR__) && !defined (__UCLIBC_FORMAT_SHARED_FLAT__)
extern void _dl_app_init_array(void);
extern void _dl_app_fini_array(void);
# ifndef SHARED
/* These magic symbols are provided by the linker.  */
extern void (*__preinit_array_start []) (void) attribute_hidden;
extern void (*__preinit_array_end []) (void) attribute_hidden;
extern void (*__init_array_start []) (void) attribute_hidden;
extern void (*__init_array_end []) (void) attribute_hidden;
extern void (*__fini_array_start []) (void) attribute_hidden;
extern void (*__fini_array_end []) (void) attribute_hidden;
# endif
#endif

#ifdef SHARED
extern int _dl_secure;
#endif
extern size_t _dl_pagesize;

const char *__uclibc_progname = "";
#if !defined __UCLIBC_HAS___PROGNAME__ && defined __USE_GNU && defined __UCLIBC_HAS_PROGRAM_INVOCATION_NAME__
# define __progname program_invocation_short_name
# define __progname_full program_invocation_name
#endif
#if defined __UCLIBC_HAS___PROGNAME__ || (defined __USE_GNU && defined __UCLIBC_HAS_PROGRAM_INVOCATION_NAME__)
const char *__progname = "";
/* psm: why have a visible __progname_full? */
const char *__progname_full = "";
# if defined __UCLIBC_HAS___PROGNAME__ && defined __USE_GNU && defined __UCLIBC_HAS_PROGRAM_INVOCATION_NAME__
weak_alias (__progname, program_invocation_short_name)
weak_alias (__progname_full, program_invocation_name)
# endif
#endif

/*
 * Declare the __environ global variable and create a weak alias environ.
 * This must be initialized; we cannot have a weak alias into bss.
 */
char **__environ = 0;
weak_alias(__environ, environ)

size_t __pagesize = 0;

#ifndef O_NOFOLLOW
# define O_NOFOLLOW	0
#endif

#ifndef __ARCH_HAS_NO_LDSO__
static void __check_one_fd(int fd, int mode)
{
    /* Check if the specified fd is already open */
    if (fcntl(fd, F_GETFD) == -1)
    {
	/* The descriptor is probably not open, so try to use /dev/null */
	int nullfd = open(_PATH_DEVNULL, mode);
	/* /dev/null is major=1 minor=3.  Make absolutely certain
	 * that is in fact the device that we have opened and not
	 * some other wierd file... [removed in uclibc] */
	if (nullfd!=fd)
	{
		abort();
	}
    }
}

#ifndef SHARED
static int __check_suid(void)
{
    uid_t uid, euid;
    gid_t gid, egid;

    uid  = getuid();
    euid = geteuid();
    if (uid != euid)
	return 1;
    gid  = getgid();
    egid = getegid();
    if (gid != egid)
	return 1;
    return 0; /* we are not suid */
}
#endif
#endif

/* __uClibc_init completely initialize uClibc so it is ready to use.
 *
 * On ELF systems (with a dynamic loader) this function must be called
 * from the dynamic loader (see TIS and ELF Specification), so that
 * constructors of shared libraries (which depend on libc) can use all
 * the libc code without restriction.  For this we link the shared
 * version of the uClibc with -init __uClibc_init so DT_INIT for
 * uClibc is the address of __uClibc_init
 *
 * In all other cases we call it from the main stub
 * __uClibc_main.
 */

extern void __uClibc_init(void) attribute_hidden;
void __uClibc_init(void)
{
    /* Don't recurse */
    if (__pagesize)
	return;

    /* Setup an initial value.  This may not be perfect, but is
     * better than  malloc using __pagesize=0 for atexit, ctors, etc.  */
    __pagesize = PAGE_SIZE;

#ifdef __UCLIBC_HAS_THREADS__

#if defined (__UCLIBC_HAS_THREADS_NATIVE__) && !defined (SHARED)
    /* Unlike in the dynamically linked case the dynamic linker has not
       taken care of initializing the TLS data structures.  */
    __libc_setup_tls (TLS_TCB_SIZE, TLS_TCB_ALIGN);
#endif

    /* Before we start initializing uClibc we have to call
     * __pthread_initialize_minimal so we can use pthread_locks
     * whenever they are needed.
     */
#if !defined (__UCLIBC_HAS_THREADS_NATIVE__) || defined (SHARED)
    if (likely(__pthread_initialize_minimal!=NULL))
#endif
	__pthread_initialize_minimal();
#endif

#ifndef SHARED
# ifdef __UCLIBC_HAS_SSP__
    /* Set up the stack checker's canary.  */
    stack_chk_guard = _dl_setup_stack_chk_guard();
#  ifdef THREAD_SET_STACK_GUARD
    THREAD_SET_STACK_GUARD (stack_chk_guard);
#  else
    __stack_chk_guard = stack_chk_guard;
#  endif
# endif
#endif

#ifdef __UCLIBC_HAS_LOCALE__
    /* Initialize the global locale structure. */
    if (likely(not_null_ptr(_locale_init)))
	_locale_init();
#endif

    /*
     * Initialize stdio here.  In the static library case, this will
     * be bypassed if not needed because of the weak alias above.
     * Thus we get a nice size savings because the stdio functions
     * won't be pulled into the final static binary unless used.
     */
    if (likely(not_null_ptr(_stdio_init)))
	_stdio_init();

}

#ifdef __UCLIBC_CTOR_DTOR__
void attribute_hidden (*__app_fini)(void) = NULL;
#endif

void attribute_hidden (*__rtld_fini)(void) = NULL;

extern void __uClibc_fini(void) attribute_hidden;
void __uClibc_fini(void)
{
#ifdef __UCLIBC_CTOR_DTOR__
    /* If __UCLIBC_FORMAT_SHARED_FLAT__, all array finalisation is handled
     * by __app_fini.  */
# ifdef SHARED
    _dl_app_fini_array();
# elif !defined (__UCLIBC_FORMAT_SHARED_FLAT__)
    size_t i = __fini_array_end - __fini_array_start;
    while (i-- > 0)
#if !defined(SHARED) && defined(__FDPIC__)
    //fdpic_init_array_jump(__fini_array_start[i]);
#else
    (*__fini_array_start [i]) ();
#endif
# endif
    if (__app_fini != NULL)
        (__app_fini)();
#endif
    if (__rtld_fini != NULL)
    {
        //(__rtld_fini)();
    }
}

#ifndef SHARED
extern void __nptl_deallocate_tsd (void) __attribute ((weak));
extern unsigned int __nptl_nthreads __attribute ((weak));
#endif

#ifdef __CHERI_PURE_CAPABILITY__
/* Bump this on every incompatible change */
#define CHERI_INIT_GLOBALS_VERSION 5
#define CHERI_INIT_GLOBALS_NUM_ARGS 7
#define CHERI_INIT_GLOBALS_SUPPORTS_CONSTANT_FLAG 1

struct capreloc {
  __SIZE_TYPE__ capability_location;
  __SIZE_TYPE__ object;
  __SIZE_TYPE__ offset;
  __SIZE_TYPE__ size;
  __SIZE_TYPE__ permissions;
};
static const __SIZE_TYPE__ function_reloc_flag = (__SIZE_TYPE__)1
                                                 << (__SIZE_WIDTH__ - 1);
static const __SIZE_TYPE__ function_pointer_permissions_mask =
    ~(__SIZE_TYPE__)(__CHERI_CAP_PERMISSION_PERMIT_SEAL__ |
                     __CHERI_CAP_PERMISSION_PERMIT_STORE_CAPABILITY__ |
                     __CHERI_CAP_PERMISSION_PERMIT_STORE__);
static const __SIZE_TYPE__ constant_reloc_flag = (__SIZE_TYPE__)1
                                                 << (__SIZE_WIDTH__ - 2);
static const __SIZE_TYPE__ constant_pointer_permissions_mask =
    ~(__SIZE_TYPE__)(__CHERI_CAP_PERMISSION_PERMIT_SEAL__ |
                     __CHERI_CAP_PERMISSION_PERMIT_STORE_CAPABILITY__ |
                     __CHERI_CAP_PERMISSION_PERMIT_STORE_LOCAL__ |
                     __CHERI_CAP_PERMISSION_PERMIT_STORE__ |
                     __CHERI_CAP_PERMISSION_PERMIT_EXECUTE__);
static const __SIZE_TYPE__ global_pointer_permissions_mask =
    ~(__SIZE_TYPE__)(__CHERI_CAP_PERMISSION_PERMIT_SEAL__ |
                     __CHERI_CAP_PERMISSION_PERMIT_EXECUTE__);

__attribute__((weak)) extern struct capreloc __start___cap_relocs;
__attribute__((weak)) extern struct capreloc __stop___cap_relocs;

__attribute__((weak)) extern void *__capability __cap_table_start;
__attribute__((weak)) extern void *__capability __cap_table_end;

/*
 * Sandbox data segments are relocated by moving DDC, since they're compiled as
 * position-dependent executables.
 */
#ifdef CHERI_INIT_GLOBALS_USE_OFFSET
#define cgetaddr_or_offset "cgetoffset"
#define csetaddr_or_offset "csetoffset"
#define cheri_address_or_offset_set(_cap, _val)                                \
  __builtin_cheri_offset_set((_cap), (_val))
#else
#define cgetaddr_or_offset "cgetaddr"
#define csetaddr_or_offset "csetaddr"
#define cheri_address_or_offset_set(_cap, _val)                                \
  __builtin_cheri_address_set((_cap), (_val))
#endif

#define __STRINGIFY2(x) #x
#define __STRINGIFY(x) __STRINGIFY2(x)
#define CGP_PERMISSIONS                                                        \
  __STRINGIFY((__CHERI_CAP_PERMISSION_PERMIT_LOAD_CAPABILITY__ |               \
               __CHERI_CAP_PERMISSION_PERMIT_LOAD__))

/* By default derive $cgp from $pcc on startup */
#ifndef GET_GCP_BASE_CAPABILITY
/* The initial PCC should have load+load_cap and span the current binary */
#define GET_GCP_BASE_CAPABILITY "cgetpcc $cgp\n\t"
#endif

static __attribute__((always_inline)) void
cheri_init_globals_impl(const struct capreloc *start_relocs,
                        const struct capreloc *stop_relocs,
                        void *__capability data_cap,
                        const void *__capability code_cap,
                        const void *__capability rodata_cap,
                        int tight_code_bounds, __SIZE_TYPE__ base_addr) {
  data_cap =
      __builtin_cheri_perms_and(data_cap, global_pointer_permissions_mask);
  code_cap =
      __builtin_cheri_perms_and(code_cap, function_pointer_permissions_mask);
  rodata_cap =
      __builtin_cheri_perms_and(rodata_cap, constant_pointer_permissions_mask);
  for (const struct capreloc *reloc = start_relocs; reloc < stop_relocs;
       reloc++) {
    const void *__capability *__capability dest =
        (const void *__capability *__capability)cheri_address_or_offset_set(
            data_cap, reloc->capability_location + base_addr);
    if (reloc->object == 0) {
      /* XXXAR: clang fills uninitialized capabilities with 0xcacaca..., so we
       * we need to explicitly write NULL here */
      *dest = (void *__capability)0;
      continue;
    }
    const void *__capability base_cap;
    int can_set_bounds = 1;
    if ((reloc->permissions & function_reloc_flag) == function_reloc_flag) {
      base_cap = code_cap; /* code pointer */
      /* Do not set tight bounds for functions (unless we are in the plt ABI) */
      can_set_bounds = tight_code_bounds;
    } else if ((reloc->permissions & constant_reloc_flag) ==
               constant_reloc_flag) {
      base_cap = rodata_cap; /* read-only data pointer */
    } else {
      base_cap = data_cap; /* read-write data */
    }
    const void *__capability src =
        cheri_address_or_offset_set(base_cap, reloc->object + base_addr);
    if (can_set_bounds && (reloc->size != 0)) {
      src = __builtin_cheri_bounds_set(src, reloc->size);
    }
    src = __builtin_cheri_offset_increment(src, reloc->offset);
    if ((reloc->permissions & function_reloc_flag) == function_reloc_flag) {
      /* Convert function pointers to sentries: */
      src = __builtin_cheri_seal_entry(src);
    }
    *dest = src;
  }
}

static __attribute__((always_inline)) void
cheri_init_globals_3(void *__capability data_cap,
                     const void *__capability code_cap,
                     const void *__capability rodata_cap) {
  const struct capreloc *start_relocs;
  const struct capreloc *stop_relocs;
  __SIZE_TYPE__ start_addr, stop_addr;
#if defined(__mips__)
  __asm__(".option pic0\n\t"
          "dla %0, __start___cap_relocs\n\t"
          "dla %1, __stop___cap_relocs\n\t"
          : "=r"(start_addr), "=r"(stop_addr));
#elif defined(__riscv)
#if !defined(__CHERI_PURE_CAPABILITY__)
  __asm__("lla %0, __start___cap_relocs\n\t"
          "lla %1, __stop___cap_relocs\n\t"
          : "=r"(start_addr), "=r"(stop_addr));
#else
  void *__capability tmp;
  __asm__ (
       "cllc %2, __start___cap_relocs\n\t"
       cgetaddr_or_offset " %0, %2\n\t"
       "cllc %2, __stop___cap_relocs\n\t"
       cgetaddr_or_offset " %1, %2\n\t"
       :"=r"(start_addr), "=r"(stop_addr), "=&C"(tmp));
#endif
#else
#error Unknown architecture
#endif

#if !defined(__CHERI_PURE_CAPABILITY__)
  start_relocs = (const struct capreloc *)(__UINTPTR_TYPE__)start_addr;
  stop_relocs = (const struct capreloc *)(__UINTPTR_TYPE__)stop_addr;
#else
  __SIZE_TYPE__ relocs_size = stop_addr - start_addr;
  /*
   * Always get __cap_relocs relative to the initial $pcc. This should span
   * rodata and rw data, too so we can access __cap_relocs, no matter where it
   * was placed.
   */
  start_relocs = (const struct capreloc *)cheri_address_or_offset_set(
      __builtin_cheri_program_counter_get(), start_addr);
  start_relocs = __builtin_cheri_bounds_set(start_relocs, relocs_size);
  /*
   * Note: with imprecise capabilities start_relocs could have a non-zero offset
   * so we must not use setoffset!
   * TODO: use csetboundsexact and teach the linker to align __cap_relocs.
   */
  stop_relocs =
      (const struct capreloc *)(const void *)((const char *)start_relocs +
                                              relocs_size);
#endif

#if !defined(__CHERI_PURE_CAPABILITY__) || __CHERI_CAPABILITY_TABLE__ == 3
  /* pc-relative or hybrid ABI -> need large bounds on $pcc */
  int can_set_code_bounds = 0;
#else
  int can_set_code_bounds = 1; /* fn-desc/plt ABI -> tight bounds okay */
#endif
  /*
   * We can assume that all relocations in the __cap_relocs section have already
   * been processed so we don't need to add a relocation base address to the
   * location of the capreloc.
   */
  cheri_init_globals_impl(start_relocs, stop_relocs, data_cap, code_cap,
                          rodata_cap, can_set_code_bounds, 0);
}

void __start_purecap(void);
void __start_purecap(void) {
        cheri_init_globals_3( __builtin_cheri_global_data_get(),
                              __builtin_cheri_program_counter_get(),
                              __builtin_cheri_global_data_get() );
}
#endif /* __CHERI_PURE_CAPABILITY__ */

/* __uClibc_main is the new main stub for uClibc. This function is
 * called from crt1 (version 0.9.28 or newer), after ALL shared libraries
 * are initialized, just before we call the application's main function.
 */
void __uClibc_main(int (*main)(int, char **, char **), int argc,
		    char **argv, void (*app_init)(void), void (*app_fini)(void),
		    void (*rtld_fini)(void),
		    void *stack_end attribute_unused) attribute_noreturn;
void __uClibc_main(int (*main)(int, char **, char **), int argc,
		    char **argv, void (*app_init)(void), void (*app_fini)(void),
		    void (*rtld_fini)(void), void *stack_end attribute_unused)
{
#ifndef SHARED
    unsigned long *aux_dat;
    ElfW(auxv_t) auxvt[AT_EGID + 1];
#endif

#ifdef __UCLIBC_HAS_THREADS_NATIVE__
	/* Result of the 'main' function.  */
	int result;
#endif

#ifndef SHARED
    __libc_stack_end = stack_end;
#endif

    __rtld_fini = rtld_fini;

    /* The environment begins right after argv.  */
    __environ = &argv[argc + 1];

    /* If the first thing after argv is the arguments
     * then the environment is empty. */
    if ((char *) __environ == *argv) {
	/* Make __environ point to the NULL at argv[argc] */
	__environ = &argv[argc];
    }

#ifndef SHARED
    /* Pull stuff from the ELF header when possible */
    memset(auxvt, 0x00, sizeof(auxvt));
    aux_dat = (unsigned long*)__environ;
    while (*aux_dat) {
	aux_dat++;
    }
    aux_dat++;
    while (*aux_dat) {
	ElfW(auxv_t) *auxv_entry = (ElfW(auxv_t) *) aux_dat;
	if (auxv_entry->a_type <= AT_EGID) {
	    memcpy(&(auxvt[auxv_entry->a_type]), auxv_entry, sizeof(ElfW(auxv_t)));
	}
	aux_dat += 2;
    }
    /* Get the program headers (_dl_phdr) from the aux vector
       It will be used into __libc_setup_tls. */

    _dl_aux_init (auxvt);
#endif

    /* We need to initialize uClibc.  If we are dynamically linked this
     * may have already been completed by the shared lib loader.  We call
     * __uClibc_init() regardless, to be sure the right thing happens. */
    __uClibc_init();

#ifndef __ARCH_HAS_NO_LDSO__
    /* Make certain getpagesize() gives the correct answer.
     * _dl_pagesize is defined into ld.so if SHARED or into libc.a otherwise. */
    __pagesize = _dl_pagesize;

#ifndef SHARED
    /* Prevent starting SUID binaries where the stdin. stdout, and
     * stderr file descriptors are not already opened. */
    if ((auxvt[AT_UID].a_un.a_val == (size_t)-1 && __check_suid()) ||
	    (auxvt[AT_UID].a_un.a_val != (size_t)-1 &&
	    (auxvt[AT_UID].a_un.a_val != auxvt[AT_EUID].a_un.a_val ||
	     auxvt[AT_GID].a_un.a_val != auxvt[AT_EGID].a_un.a_val)))
#else
    if (_dl_secure)
#endif
    {
	__check_one_fd (STDIN_FILENO, O_RDONLY | O_NOFOLLOW);
	__check_one_fd (STDOUT_FILENO, O_RDWR | O_NOFOLLOW);
	__check_one_fd (STDERR_FILENO, O_RDWR | O_NOFOLLOW);
	_pe_secure = 1 ;
    }
    else
	_pe_secure = 0 ;
#endif

    __uclibc_progname = *argv;
#if defined __UCLIBC_HAS___PROGNAME__ || (defined __USE_GNU && defined __UCLIBC_HAS_PROGRAM_INVOCATION_NAME__)
    if (*argv != NULL) {
	__progname_full = *argv;
	__progname = strrchr(*argv, '/');
	if (__progname != NULL)
	    ++__progname;
	else
	    __progname = *argv;
    }
#endif

#ifdef __UCLIBC_CTOR_DTOR__
    /* Arrange for the application's dtors to run before we exit.  */
    __app_fini = app_fini;

    /* If __UCLIBC_FORMAT_SHARED_FLAT__, all array initialisation is handled
     * by __app_init.  */
# if !defined (SHARED) && !defined (__UCLIBC_FORMAT_SHARED_FLAT__)
    /* For dynamically linked executables the preinit array is executed by
       the dynamic linker (before initializing any shared object).
       For static executables, preinit happens rights before init.  */
    {
	const size_t size = __preinit_array_end - __preinit_array_start;
	size_t i;
	for (i = 0; i < size; i++)
#if !defined(SHARED) && defined(__FDPIC__)
	    fdpic_init_array_jump(__preinit_array_start[i]);
#else
	    (*__preinit_array_start [i]) ();
#endif
    }
# endif
    /* Run all the application's ctors now.  */
    if (app_init!=NULL) {
	app_init();
    }
    /* If __UCLIBC_FORMAT_SHARED_FLAT__, all array initialisation is handled
     * by __app_init.  */
# ifdef SHARED
    _dl_app_init_array();
# elif !defined (__UCLIBC_FORMAT_SHARED_FLAT__)
    {
	const size_t size = __init_array_end - __init_array_start;
	size_t i;
	for (i = 0; i < size; i++)
#if !defined(SHARED) && defined(__FDPIC__)
	    fdpic_init_array_jump(__init_array_start[i]);
#else
	    (*__init_array_start [i]) ();
#endif
    }
# endif
#endif

    /* Note: It is possible that any initialization done above could
     * have resulted in errno being set nonzero, so set it to 0 before
     * we call main.
     */
    if (likely(not_null_ptr(__errno_location)))
	*(__errno_location()) = 0;

    /* Set h_errno to 0 as well */
    if (likely(not_null_ptr(__h_errno_location)))
	*(__h_errno_location()) = 0;

#if defined HAVE_CLEANUP_JMP_BUF && defined __UCLIBC_HAS_THREADS_NATIVE__
	/* Memory for the cancellation buffer.  */
	struct pthread_unwind_buf unwind_buf;

	int not_first_call;
	not_first_call =
		setjmp ((struct __jmp_buf_tag *) unwind_buf.cancel_jmp_buf);
	if (__builtin_expect (! not_first_call, 1))
	{
		struct pthread *self = THREAD_SELF;

		/* Store old info.  */
		unwind_buf.priv.data.prev = THREAD_GETMEM (self, cleanup_jmp_buf);
		unwind_buf.priv.data.cleanup = THREAD_GETMEM (self, cleanup);

		/* Store the new cleanup handler info.  */
		THREAD_SETMEM (self, cleanup_jmp_buf, &unwind_buf);

		/* Run the program.  */
		result = main (argc, argv, __environ);
	}
	else
	{
		/* Remove the thread-local data.  */
		__nptl_deallocate_tsd ();

		/* One less thread.  Decrement the counter.  If it is zero we
		   terminate the entire process.  */
		result = 0;
		unsigned int *const ptr = &__nptl_nthreads;

		if (ptr && ! atomic_decrement_and_test (ptr))
			/* Not much left to do but to exit the thread, not the process.  */
			__exit_thread_inline (0);
	}

	exit (result);
#else
	/*
	 * Finally, invoke application's main and then exit.
	 */
	exit (main (argc, argv, __environ));
#endif
}
