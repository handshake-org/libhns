#ifndef HEADER_HNS_NOWARN_H
#define HEADER_HNS_NOWARN_H


/* Copyright (C) 2010-2012 by Daniel Stenberg
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */

long  hnsx_uztosl(size_t uznum);
int   hnsx_uztosi(size_t uznum);
short hnsx_uztoss(size_t uznum);

short hnsx_sitoss(int sinum);

int hnsx_sltosi(long slnum);

int hnsx_sztosi(hns_ssize_t sznum);

unsigned int hnsx_sztoui(hns_ssize_t sznum);

unsigned short hnsx_sitous(int sinum);

#if defined(__INTEL_COMPILER) && defined(__unix__)

int hnsx_FD_ISSET(int fd, fd_set *fdset);

void hnsx_FD_SET(int fd, fd_set *fdset);

void hnsx_FD_ZERO(fd_set *fdset);

unsigned short hnsx_htons(unsigned short usnum);

unsigned short hnsx_ntohs(unsigned short usnum);

#ifndef BUILDING_HNS_NOWARN_C
#  undef  FD_ISSET
#  define FD_ISSET(a,b) hnsx_FD_ISSET((a),(b))
#  undef  FD_SET
#  define FD_SET(a,b)   hnsx_FD_SET((a),(b))
#  undef  FD_ZERO
#  define FD_ZERO(a)    hnsx_FD_ZERO((a))
#  undef  htons
#  define htons(a)      hnsx_htons((a))
#  undef  ntohs
#  define ntohs(a)      hnsx_ntohs((a))
#endif

#endif /* __INTEL_COMPILER && __unix__ */

#endif /* HEADER_HNS_NOWARN_H */