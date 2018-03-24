
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
#ifndef T_TLSA
#  define T_TLSA 52
#endif
#ifndef T_SMIMEA
#  define T_SMIMEA 53
#endif

static int
read_labels(
  const char *name,
  char **left,
  size_t *left_len,
  char **right,
  size_t *right_len
) {
  char *left_end = NULL;
  char *right_end = NULL;
  char *s = (char *)name;

  if (s == NULL)
    return 0;

  while (*s) {
    if (*s == '.') {
      if (!left_end)
        left_end = s;
      else if (!right_end)
        right_end = s;
      else
        break;
    }
    s += 1;
  }

  if (!*s)
    return 0;

  int leftlen = left_end - name;
  int rightlen = right_end - (left_end + 1);

  if (leftlen < 2 || rightlen < 2)
    return 0;

  if (name[0] != '_')
    return 0;

  if (left_end[1] != '_')
    return 0;

  *left = (char *)&name[1];
  *left_len = leftlen - 1;
  *right = &left_end[2];
  *right_len = rightlen - 1;

  return 1;
}

static int
to_nibble(char s) {
  if (s >= '0' && s <= '9')
    return s - '0';

  if (s >= 'A' && s <= 'F')
    return (s - 'A') + 10;

  if (s >= 'a' && s <= 'f')
    return (s - 'a') + 10;

  return -1;
}

static int
decode_hex(const char *str, size_t len, unsigned char *data) {
  if (str == NULL)
    return 1;

  if (data == NULL)
    return 0;

  unsigned char w;
  int p = 0;
  int i, n;

  for (i = 0; i < len; i++) {
    n = to_nibble(str[i]);

    if (n == -1)
      return 0;

    if (i & 1) {
      w |= (unsigned char)n;
      data[p] = w;
      p += 1;
    } else {
      w = ((unsigned char)n) << 4;
    }
  }

  if (i & 1)
    return 0;

  return 1;
}

static int
read_port(const char *str, size_t len, unsigned int *port) {
  if (len > 5)
    return 0;

  unsigned long word = 0;
  int i, ch;

  for (i = 0; i < len; i++) {
    ch = ((int)str[i]) - 0x30;

    if (ch < 0 || ch > 9)
      return 0;

    word *= 10;
    word += ch;
  }

  if (word > 0xffff)
    return 0;

  *port = word;

  return 1;
}

static int
read_protocol(const char *str, size_t len, char **protocol) {
  char *proto = ares_malloc(len + 1);

  if (!proto)
    return 0;

  memcpy(proto, str, len);
  proto[len] = '\0';

  *protocol = proto;

  return 1;
}

static int
read_hash(const char *str, size_t len, unsigned char **hash) {
  if (len != 56)
    return 0;

  unsigned char *ha = ares_malloc(28);

  if (!ha)
    return 0;

  if (!decode_hex(str, len, ha)) {
    free(ha);
    return 0;
  }

  *hash = ha;

  return 1;
}

static int
read_smimea(const char *str, size_t len) {
  if (len != 6)
    return 0;

  int i;
  char c;

  for (i = 0; i < 6; i++) {
    c = str[i];

    if (c >= 'A' && c <= 'Z')
      c += ' ';

    if (c != "smimea"[i])
      return 0;
  }

  return 1;
}

static int
ares_parse_dane_reply (const unsigned char *abuf, int alen,
                      struct ares_dane_reply **dane_out, int expect)
{
  unsigned int qdcount, ancount, i;
  const unsigned char *aptr, *vptr;
  int status, rr_type, rr_class, rr_len;
  long len;
  char *hostname = NULL, *rr_name = NULL;
  struct ares_dane_reply *dane_head = NULL;
  struct ares_dane_reply *dane_last = NULL;
  struct ares_dane_reply *dane_curr;
  char *left, *right;
  size_t left_len, right_len;

  /* Set *dane_out to NULL for all failure cases. */
  *dane_out = NULL;

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

      /* Check if we are really looking at a DANE record */
      if (rr_class == C_IN && rr_type == expect)
        {
          /* parse the DANE record itself */
          if (rr_len < 3)
            {
              status = ARES_EBADRESP;
              break;
            }

          /* Allocate storage for this DANE answer appending it to the list */
          dane_curr = ares_malloc_data(ARES_DATATYPE_DANE_REPLY);
          if (!dane_curr)
            {
              status = ARES_ENOMEM;
              break;
            }
          if (dane_last)
            {
              dane_last->next = dane_curr;
            }
          else
            {
              dane_head = dane_curr;
            }
          dane_last = dane_curr;

          dane_curr->type = rr_type;
          vptr = aptr;
          dane_curr->usage = *vptr;
          vptr += 1;
          dane_curr->selector = *vptr;
          vptr += 1;
          dane_curr->matching_type = *vptr;
          vptr += 1;

          dane_curr->cert_len = rr_len - 3;

          if (dane_curr->cert_len != 0) {
            dane_curr->cert = ares_malloc(dane_curr->cert_len);

            if (!dane_curr->cert) {
              status = ARES_ENOMEM;
              break;
            }

            memcpy(dane_curr->cert, vptr, dane_curr->cert_len);
          }

          /* Parse the first two labels, minus the `_` prefixes. */
          if (!read_labels(rr_name, &left, &left_len, &right, &right_len)) {
            status = ARES_EBADRESP;
            break;
          }

          /* TLSA record. */
          if (rr_type == T_TLSA) {
            /* TLSA RR names exist as _[port]._[protocol].name. */

            /* Parse the port. */
            if (!read_port(left, left_len, &dane_curr->port)) {
              status = ARES_EBADRESP;
              break;
            }

            /* Parse the protocol name. */
            if (!read_protocol(right, right_len, &dane_curr->protocol)) {
              status = ARES_ENOMEM;
              break;
            }

            continue;
          }

          /* SMIMEA record. */
          if (rr_type == T_SMIMEA) {
            /* SMIMEA RR names exist as _[hash]._smimea.name. */

            /* Parse the 28 byte hash (hex encoded). */
            if (!read_hash(left, left_len, &dane_curr->hash)) {
              status = ARES_EBADRESP;
              break;
            }

            /* Ensure the second label is `smimea`. */
            if (!read_smimea(right, right_len)) {
              status = ARES_EBADRESP;
              break;
            }

            continue;
          }

          /* Reserved for future use. */
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
      if (dane_head)
        ares_free_data (dane_head);
      return status;
    }

  /* everything looks fine, return the data */
  *dane_out = dane_head;

  return ARES_SUCCESS;
}

int
ares_parse_tlsa_reply (const unsigned char *abuf, int alen,
                      struct ares_tlsa_reply **tlsa_out)
{
  return ares_parse_dane_reply(abuf, alen, tlsa_out, T_TLSA);
}

int
ares_parse_smimea_reply (const unsigned char *abuf, int alen,
                      struct ares_smimea_reply **smimea_out)
{
  return ares_parse_dane_reply(abuf, alen, smimea_out, T_SMIMEA);
}
