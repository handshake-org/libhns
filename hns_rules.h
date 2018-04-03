#ifndef __HNS_RULES_H
#define __HNS_RULES_H


/* Copyright (C) 2009 by Daniel Stenberg et al
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted, provided
 * that the above copyright notice appear in all copies and that both that
 * copyright notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in advertising or
 * publicity pertaining to distribution of the software without specific,
 * written prior permission.  M.I.T. makes no representations about the
 * suitability of this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */

/* ================================================================ */
/*                    COMPILE TIME SANITY CHECKS                    */
/* ================================================================ */

/*
 * NOTE 1:
 * -------
 *
 * All checks done in this file are intentionally placed in a public
 * header file which is pulled by hns.h when an application is
 * being built using an already built hns library. Additionally
 * this file is also included and used when building the library.
 *
 * If compilation fails on this file it is certainly sure that the
 * problem is elsewhere. It could be a problem in the hns_build.h
 * header file, or simply that you are using different compilation
 * settings than those used to build the library.
 *
 * Nothing in this file is intended to be modified or adjusted by the
 * hns library user nor by the hns library builder.
 *
 * Do not deactivate any check, these are done to make sure that the
 * library is properly built and used.
 *
 * You can find further help on the hns development mailing list:
 * http://cool.haxx.se/mailman/listinfo/c-ares/
 *
 * NOTE 2
 * ------
 *
 * Some of the following compile time checks are based on the fact
 * that the dimension of a constant array can not be a negative one.
 * In this way if the compile time verification fails, the compilation
 * will fail issuing an error. The error description wording is compiler
 * dependent but it will be quite similar to one of the following:
 *
 *   "negative subscript or subscript is too large"
 *   "array must have at least one element"
 *   "-1 is an illegal array size"
 *   "size of array is negative"
 *
 * If you are building an application which tries to use an already
 * built hns library and you are getting this kind of errors on
 * this file, it is a clear indication that there is a mismatch between
 * how the library was built and how you are trying to use it for your
 * application. Your already compiled or binary library provider is the
 * only one who can give you the details you need to properly use it.
 */

/*
 * Verify that some macros are actually defined.
 */

#ifndef HNS_TYPEOF_HNS_SOCKLEN_T
#  error "HNS_TYPEOF_HNS_SOCKLEN_T definition is missing!"
   Error Compilation_aborted_HNS_TYPEOF_HNS_SOCKLEN_T_is_missing
#endif

/*
 * Macros private to this header file.
 */

#define HnschkszEQ(t, s) sizeof(t) == s ? 1 : -1

#define HnschkszGE(t1, t2) sizeof(t1) >= sizeof(t2) ? 1 : -1

/*
 * Verify that the size previously defined and expected for
 * hns_socklen_t is actually the the same as the one reported
 * by sizeof() at compile time.
 */

typedef char
  __hns_rule_02__
    [HnschkszEQ(hns_socklen_t, sizeof(HNS_TYPEOF_HNS_SOCKLEN_T))];

/*
 * Verify at compile time that the size of hns_socklen_t as reported
 * by sizeof() is greater or equal than the one reported for int for
 * the current compilation.
 */

typedef char
  __hns_rule_03__
    [HnschkszGE(hns_socklen_t, int)];

/* ================================================================ */
/*          EXTERNALLY AND INTERNALLY VISIBLE DEFINITIONS           */
/* ================================================================ */

/*
 * Get rid of macros private to this header file.
 */

#undef HnschkszEQ
#undef HnschkszGE

/*
 * Get rid of macros not intended to exist beyond this point.
 */

#undef HNS_PULL_WS2TCPIP_H
#undef HNS_PULL_SYS_TYPES_H
#undef HNS_PULL_SYS_SOCKET_H

#undef HNS_TYPEOF_HNS_SOCKLEN_T

#endif /* __HNS_RULES_H */
