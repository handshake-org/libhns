
/* Copyright 1998 by the Massachusetts Institute of Technology.
 * Copyright (C) 2009 by Jakub Hrozek <jhrozek@redhat.com>
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

#include "ares_setup.h"

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif
#ifdef HAVE_ARPA_NAMESER_H
#  include <arpa/nameser.h>
#else
#  include "nameser.h"
#endif
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#  include <arpa/nameser_compat.h>
#endif

#include "ares.h"
#include "ares_dns.h"
#include "ares_data.h"
#include "ares_private.h"

/* AIX portability check */
#ifndef T_SSHFP
#  define T_SSHFP 44
#endif

int
ares_parse_sshfp_reply (const unsigned char *abuf, int alen,
                      struct ares_sshfp_reply **sshfp_out)
{
  unsigned int qdcount, ancount, i;
  const unsigned char *aptr, *vptr;
  int status, rr_type, rr_class, rr_len;
  long len;
  char *hostname = NULL, *rr_name = NULL;
  struct ares_sshfp_reply *sshfp_head = NULL;
  struct ares_sshfp_reply *sshfp_last = NULL;
  struct ares_sshfp_reply *sshfp_curr;
  char *a, *b;
  size_t alen, blen;

  /* Set *sshfp_out to NULL for all failure cases. */
  *sshfp_out = NULL;

  /* Give up if abuf doesn't have room for a header. */
  if (alen < HFIXEDSZ)
    return ARES_EBADRESP;

  if (DNS_HEADER_AD(abuf) == 0)
    return ARES_EINSECURE;

  /* Fetch the question and answer count from the header. */
  qdcount = DNS_HEADER_QDCOUNT (abuf);
  ancount = DNS_HEADER_ANCOUNT (abuf);
  if (qdcount != 1)
    return ARES_EBADRESP;
  if (ancount == 0)
    return ARES_ENODATA;

  /* Expand the name from the question, and skip past the question. */
  aptr = abuf + HFIXEDSZ;
  status = ares_expand_name (aptr, abuf, alen, &hostname, &len);
  if (status != ARES_SUCCESS)
    return status;

  if (aptr + len + QFIXEDSZ > abuf + alen)
    {
      ares_free (hostname);
      return ARES_EBADRESP;
    }
  aptr += len + QFIXEDSZ;

  /* Examine each answer resource record (RR) in turn. */
  for (i = 0; i < ancount; i++)
    {
      /* Decode the RR up to the data field. */
      status = ares_expand_name (aptr, abuf, alen, &rr_name, &len);
      if (status != ARES_SUCCESS)
        {
          break;
        }
      aptr += len;
      if (aptr + RRFIXEDSZ > abuf + alen)
        {
          status = ARES_EBADRESP;
          break;
        }
      rr_type = DNS_RR_TYPE (aptr);
      rr_class = DNS_RR_CLASS (aptr);
      rr_len = DNS_RR_LEN (aptr);
      aptr += RRFIXEDSZ;
      if (aptr + rr_len > abuf + alen)
        {
          status = ARES_EBADRESP;
          break;
        }

      /* Check if we are really looking at a SSHFP record */
      if (rr_class == C_IN && rr_type == T_SSHFP)
        {
          /* parse the SSHFP record itself */
          if (rr_len < 2)
            {
              status = ARES_EBADRESP;
              break;
            }

          /* Allocate storage for this SSHFP answer appending it to the list */
          sshfp_curr = ares_malloc_data(ARES_DATATYPE_SSHFP_REPLY);
          if (!sshfp_curr)
            {
              status = ARES_ENOMEM;
              break;
            }
          if (sshfp_last)
            {
              sshfp_last->next = sshfp_curr;
            }
          else
            {
              sshfp_head = sshfp_curr;
            }
          sshfp_last = sshfp_curr;

          vptr = aptr;
          sshfp_curr->algorithm = *vptr;
          vptr += 1;
          sshfp_curr->digest_type = *vptr;
          vptr += 1;

          sshfp_curr->fingerprint_len = rr_len - 2;

          if (sshfp_curr->fingerprint_len != 0) {
            sshfp_curr->fingerprint = ares_malloc(sshfp_curr->fingerprint_len);

            if (!sshfp_curr->fingerprint) {
              status = ARES_ENOMEM;
              break;
            }

            memcpy(sshfp_curr->fingerprint, vptr, sshfp_curr->fingerprint_len);
          }
        }

      /* Don't lose memory in the next iteration */
      ares_free (rr_name);
      rr_name = NULL;

      /* Move on to the next record */
      aptr += rr_len;
    }

  if (hostname)
    ares_free (hostname);
  if (rr_name)
    ares_free (rr_name);

  /* clean up on error */
  if (status != ARES_SUCCESS)
    {
      if (sshfp_head)
        ares_free_data (sshfp_head);
      return status;
    }

  /* everything looks fine, return the data */
  *sshfp_out = sshfp_head;

  return ARES_SUCCESS;
}
