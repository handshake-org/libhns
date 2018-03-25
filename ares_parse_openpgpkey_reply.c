
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
#ifndef T_OPENPGPKEY
#  define T_OPENPGPKEY 61
#endif

int
ares_parse_openpgpkey_reply (const unsigned char *abuf, int alen,
                      struct ares_openpgpkey_reply **openpgpkey_out)
{
  unsigned int qdcount, ancount, i;
  const unsigned char *aptr;
  int status, rr_type, rr_class, rr_len;
  long len;
  char *hostname = NULL, *rr_name = NULL;
  struct ares_openpgpkey_reply *openpgpkey_head = NULL;
  struct ares_openpgpkey_reply *openpgpkey_last = NULL;
  struct ares_openpgpkey_reply *openpgpkey_curr;

  /* Set *openpgpkey_out to NULL for all failure cases. */
  *openpgpkey_out = NULL;

  /* Give up if abuf doesn't have room for a header. */
  if (alen < HFIXEDSZ)
    return ARES_EBADRESP;

  if (DNS_HEADER_AD(abuf) != 1)
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

      /* Check if we are really looking at a OPENPGPKEY record */
      if (rr_class == C_IN && rr_type == T_OPENPGPKEY)
        {
          /* Allocate storage for this OPENPGPKEY answer appending it */
          openpgpkey_curr = ares_malloc_data(ARES_DATATYPE_OPENPGPKEY_REPLY);
          if (!openpgpkey_curr)
            {
              status = ARES_ENOMEM;
              break;
            }
          if (openpgpkey_last)
            {
              openpgpkey_last->next = openpgpkey_curr;
            }
          else
            {
              openpgpkey_head = openpgpkey_curr;
            }
          openpgpkey_last = openpgpkey_curr;

          openpgpkey_curr->pubkey_len = rr_len;

          if (openpgpkey_curr->pubkey_len != 0) {
            openpgpkey_curr->pubkey = ares_malloc(openpgpkey_curr->pubkey_len);

            if (!openpgpkey_curr->pubkey) {
              status = ARES_ENOMEM;
              break;
            }

            memcpy(openpgpkey_curr->pubkey, aptr, openpgpkey_curr->pubkey_len);
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
      if (openpgpkey_head)
        ares_free_data (openpgpkey_head);
      return status;
    }

  /* everything looks fine, return the data */
  *openpgpkey_out = openpgpkey_head;

  return ARES_SUCCESS;
}
