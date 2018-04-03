
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

#include "hns_setup.h"

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

#include "hns.h"
#include "hns_dns.h"
#include "hns_data.h"
#include "hns_private.h"

/* AIX portability check */
#ifndef T_NAPTR
	#define T_NAPTR 35 /* naming authority pointer */
#endif

int
hns_parse_naptr_reply (const unsigned char *abuf, int alen,
                        struct hns_naptr_reply **naptr_out)
{
  unsigned int qdcount, ancount, i;
  const unsigned char *aptr, *vptr;
  int status, rr_type, rr_class, rr_len;
  long len;
  char *hostname = NULL, *rr_name = NULL;
  struct hns_naptr_reply *naptr_head = NULL;
  struct hns_naptr_reply *naptr_last = NULL;
  struct hns_naptr_reply *naptr_curr;

  /* Set *naptr_out to NULL for all failure cases. */
  *naptr_out = NULL;

  /* Give up if abuf doesn't have room for a header. */
  if (alen < HFIXEDSZ)
    return HNS_EBADRESP;

  /* Fetch the question and answer count from the header. */
  qdcount = DNS_HEADER_QDCOUNT (abuf);
  ancount = DNS_HEADER_ANCOUNT (abuf);
  if (qdcount != 1)
    return HNS_EBADRESP;
  if (ancount == 0)
    return HNS_ENODATA;

  /* Expand the name from the question, and skip past the question. */
  aptr = abuf + HFIXEDSZ;
  status = hns_expand_name (aptr, abuf, alen, &hostname, &len);
  if (status != HNS_SUCCESS)
    return status;

  if (aptr + len + QFIXEDSZ > abuf + alen)
    {
      hns_free (hostname);
      return HNS_EBADRESP;
    }
  aptr += len + QFIXEDSZ;

  /* Examine each answer resource record (RR) in turn. */
  for (i = 0; i < ancount; i++)
    {
      /* Decode the RR up to the data field. */
      status = hns_expand_name (aptr, abuf, alen, &rr_name, &len);
      if (status != HNS_SUCCESS)
        {
          break;
        }
      aptr += len;
      if (aptr + RRFIXEDSZ > abuf + alen)
        {
          status = HNS_EBADRESP;
          break;
        }
      rr_type = DNS_RR_TYPE (aptr);
      rr_class = DNS_RR_CLASS (aptr);
      rr_len = DNS_RR_LEN (aptr);
      aptr += RRFIXEDSZ;
      if (aptr + rr_len > abuf + alen)
        {
          status = HNS_EBADRESP;
          break;
        }

      /* Check if we are really looking at a NAPTR record */
      if (rr_class == C_IN && rr_type == T_NAPTR)
        {
          /* parse the NAPTR record itself */

          /* RR must contain at least 7 bytes = 2 x int16 + 3 x name */
          if (rr_len < 7)
            {
              status = HNS_EBADRESP;
              break;
            }

          /* Allocate storage for this NAPTR answer appending it to the list */
          naptr_curr = hns_malloc_data(HNS_DATATYPE_NAPTR_REPLY);
          if (!naptr_curr)
            {
              status = HNS_ENOMEM;
              break;
            }
          if (naptr_last)
            {
              naptr_last->next = naptr_curr;
            }
          else
            {
              naptr_head = naptr_curr;
            }
          naptr_last = naptr_curr;

          vptr = aptr;
          naptr_curr->order = DNS__16BIT(vptr);
          vptr += sizeof(unsigned short);
          naptr_curr->preference = DNS__16BIT(vptr);
          vptr += sizeof(unsigned short);

          status = hns_expand_string(vptr, abuf, alen, &naptr_curr->flags, &len);
          if (status != HNS_SUCCESS)
            break;
          vptr += len;

          status = hns_expand_string(vptr, abuf, alen, &naptr_curr->service, &len);
          if (status != HNS_SUCCESS)
            break;
          vptr += len;

          status = hns_expand_string(vptr, abuf, alen, &naptr_curr->regexp, &len);
          if (status != HNS_SUCCESS)
            break;
          vptr += len;

          status = hns_expand_name(vptr, abuf, alen, &naptr_curr->replacement, &len);
          if (status != HNS_SUCCESS)
            break;
        }

      /* Don't lose memory in the next iteration */
      hns_free (rr_name);
      rr_name = NULL;

      /* Move on to the next record */
      aptr += rr_len;
    }

  if (hostname)
    hns_free (hostname);
  if (rr_name)
    hns_free (rr_name);

  /* clean up on error */
  if (status != HNS_SUCCESS)
    {
      if (naptr_head)
        hns_free_data (naptr_head);
      return status;
    }

  /* everything looks fine, return the data */
  *naptr_out = naptr_head;

  return HNS_SUCCESS;
}
