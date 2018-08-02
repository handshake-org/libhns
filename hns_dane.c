
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

#include <assert.h>
#include "hns.h"
#include "hns_dns.h"
#include "hns_data.h"
#include "hns_dane.h"
#include "hns_private.h"
#include "hns_sha256.h"
#include "hns_sha512.h"

static int
read_tag(
  const unsigned char *data,
  size_t data_len,
  int off,
  int expect,
  int explicit,
  int *off_out,
  size_t *size_out
) {
  if (off >= data_len)
    return 0;

  int start = off;
  int type = data[off++];
  int primitive = (type & 0x20) == 0;

  if ((type & 0x1f) == 0x1f) {
    int oct = type;
    type = 0;
    while ((oct & 0x80) == 0x80) {
      if (off >= data_len)
        return 0;
      oct = data[off++];
      type <<= 7;
      type |= oct & 0x7f;
    }
  } else {
    type &= 0x1f;
  }

  if (type != expect) {
    if (explicit) {
      if (off_out)
        *off_out = start;
      if (size_out)
        *size_out = 0;
      return 1;
    }
    return 0;
  }

  if (off >= data_len)
    return 0;

  size_t size = data[off++];

  if (!primitive && size == 0x80)
    return 0;

  if ((size & 0x80) == 0) {
    if (off_out)
      *off_out = off;
    if (size_out)
      *size_out = size;
    return 1;
  }

  int bytes = size & 0x7f;

  if (bytes > 3)
    return 0;

  size = 0;

  int i;
  for (i = 0; i < bytes; i++) {
    if (off >= data_len)
      return 0;
    size <<= 8;
    size |= data[off++];
  }

  /* Offset after the header. */
  if (off_out)
    *off_out = off;

  /* Size of bytes to read next. */
  if (size_out)
    *size_out = size;

  return 1;
}

static int
read_seq(
  const unsigned char *data,
  size_t data_len,
  int off,
  int *off_out,
  size_t *size_out
) {
  /* Read seq-header, update offset to after header. */
  return read_tag(data, data_len, off, 0x10, 0, off_out, size_out);
}

static int
gauge_seq(
  const unsigned char *data,
  size_t data_len,
  int off,
  size_t *size_out
) {
  int pos;
  size_t size;

  /* Get total size of seq-header + data. */
  if (!read_seq(data, data_len, off, &pos, &size))
    return 0;

  *size_out = (pos - off) + size;

  return 1;
}

static int
eat_seq(const unsigned char *data, size_t data_len, int off, int *off_out) {
  /* Read seq-header, return offset after header. */
  return read_seq(data, data_len, off, off_out, NULL);
}

static int
skip_seq(const unsigned char *data, size_t data_len, int off, int *off_out) {
  int offset;
  size_t size;

  /* Read seq-header, return offset after header+data. */
  if (!read_seq(data, data_len, off, &offset, &size))
    return 0;

  *off_out = offset + size;

  return 1;
}

static int
skip_int(const unsigned char *data, size_t data_len, int off, int *off_out) {
  int offset;
  size_t size;

  /* Read int-header, return offset after header+data. */
  if (!read_tag(data, data_len, off, 0x02, 0, &offset, &size))
    return 0;

  *off_out = offset + size;

  return 1;
}

static int
skip_xint(const unsigned char *data, size_t data_len, int off, int *off_out) {
  int offset;
  size_t size;

  /* Read int-header, return offset after header+data. */
  if (!read_tag(data, data_len, off, 0x00, 1, &offset, &size))
    return 0;

  *off_out = offset + size;

  return 1;
}

static int
get_cert(
  const unsigned char *data,
  size_t cert_len,
  unsigned char **out,
  size_t *out_len
) {
  size_t size;

  if (!gauge_seq(data, cert_len, 0, &size))
    return 0;

  *out = (unsigned char *)data;
  *out_len = size;

  return 1;
}

static int
get_pubkeyinfo(
  const unsigned char *data,
  size_t data_len,
  unsigned char **out,
  size_t *out_len
) {
  int off = 0;
  size_t size;

  /* cert */
  if (!eat_seq(data, data_len, off, &off))
    return 0;

  /* tbs */
  if (!eat_seq(data, data_len, off, &off))
    return 0;

  /* version */
  if (!skip_xint(data, data_len, off, &off))
    return 0;

  /* serial */
  if (!skip_int(data, data_len, off, &off))
    return 0;

  /* alg ident */
  if (!skip_seq(data, data_len, off, &off))
    return 0;

  /* issuer */
  if (!skip_seq(data, data_len, off, &off))
    return 0;

  /* validity */
  if (!skip_seq(data, data_len, off, &off))
    return 0;

  /* subject */
  if (!skip_seq(data, data_len, off, &off))
    return 0;

  /* pubkeyinfo */
  if (!gauge_seq(data, data_len, off, &size))
    return 0;

  if (off + size >= data_len)
    return 0;

  *out = (unsigned char *)&data[off];
  *out_len = size;

  return 1;
}

static int
hns_dane_validate(
  const unsigned char *cert,
  size_t cert_len,
  unsigned short selector,
  unsigned short matching_type,
  const unsigned char *certificate,
  size_t certificate_len
) {
  if (cert == NULL || certificate == NULL)
    return 0;

  unsigned char *data = NULL;
  size_t data_len = 0;
  unsigned char buf[64];
  unsigned char *hash = NULL;
  size_t hash_len = 0;

  switch (selector) {
    case 0: /* Full */
      if (!get_cert(cert, cert_len, &data, &data_len))
        return 0;
      break;
    case 1: /* SPKI */
      if (!get_pubkeyinfo(cert, cert_len, &data, &data_len))
        return 0;
      break;
  }

  if (!data)
    return 0;

  switch (matching_type) {
    case 0: { /* NONE */
      hash = data;
      hash_len = data_len;
      break;
    }

    case 1: { /* SHA256 */
      hns_sha256_ctx ctx;
      hns_sha256_init(&ctx);
      hns_sha256_update(&ctx, data, data_len);
      hns_sha256_final(&ctx, &buf[0]);
      hash = &buf[0];
      hash_len = 32;
      break;
    }

    case 2: { /* SHA512 */
      hns_sha512_ctx ctx;
      hns_sha512_init(&ctx);
      hns_sha512_update(&ctx, data, data_len);
      hns_sha512_final(&ctx, &buf[0]);
      hash = &buf[0];
      hash_len = 64;
      break;
    }
  }

  if (!hash)
    return 0;

  if (hash_len != certificate_len)
    return 0;

  return memcmp(hash, certificate, hash_len) == 0;
}

int
hns_dane_verify(
  struct hns_dane_reply *dane_reply,
  const unsigned char *cert,
  size_t cert_len
) {
  return hns_dane_validate(
    cert,
    cert_len,
    dane_reply->selector,
    dane_reply->matching_type,
    dane_reply->certificate,
    dane_reply->certificate_len
  );
}

static char
to_char(uint8_t n) {
  if (n >= 0x00 && n <= 0x09)
    return n + '0';

  if (n >= 0x0a && n <= 0x0f)
    return (n - 10) + 'a';

  return -1;
}

static int
encode_hex(unsigned char *data, size_t data_len, char *str) {
  if (data == NULL && data_len != 0)
    return 0;

  if (str == NULL)
    return 0;

  size_t size = data_len << 1;

  int i;
  int p = 0;
  char ch;

  for (i = 0; i < size; i++) {
    if (i & 1) {
      ch = to_char(data[p] & 15);
      p += 1;
    } else {
      ch = to_char(data[p] >> 4);
    }

    if (ch == -1)
      return 0;

    str[i] = ch;
  }

  str[i] = '\0';

  return 1;
}

static void
to_lower(char *name) {
  assert(name);

  char *s = name;

  while (*s) {
    if (*s >= 'A' && *s <= 'Z')
      *s += ' ';
    s += 1;
  }
}

int
hns_dane_encode_email(
  const char *tag,
  const char *email,
  char *out,
  size_t out_len
) {
  if (tag == NULL || email == NULL)
    return 0;

  size_t email_len = strlen(email);

  if (email_len > 320)
    return 0;

  char *at = strchr(email, '@');

  if (at == NULL)
    return 0;

  size_t local_len = at - email;

  if (local_len > 64)
    return 0;

  char local[65];
  memcpy(local, email, local_len);
  local[local_len] = '\0';
  to_lower(local);

  size_t name_len = email_len - (local_len + 1);

  if (name_len > 254)
    return 0;

  char name[256];
  memcpy(name, at + 1, name_len);

  if (name_len == 0 || name[name_len - 1] != '.') {
    name[name_len] = '.';
    name_len += 1;
  }

  name[name_len] = '\0';

  return hns_dane_encode_name(tag, name, local, out, out_len);
}

int
hns_dane_encode_name(
  const char *tag,
  const char *name,
  const char *local,
  char *out,
  size_t out_len
) {
  if (tag == NULL || name == NULL || local == NULL)
    return 0;

  size_t size = hns_dane_name_size(tag, name);

  if (size > out_len)
    return 0;

  unsigned char hash[32];
  char hex[57];

  hns_sha256_ctx ctx;
  hns_sha256_init(&ctx);
  hns_sha256_update(&ctx, local, strlen(local));
  hns_sha256_final(&ctx, hash);

  assert(encode_hex(hash, 28, hex) == 1);

  return sprintf(out, "%s._%s.%s", hex, tag, name);
}

size_t
hns_dane_email_size(const char *tag, const char *email) {
  char *at = strchr(email, '@');

  if (at == NULL)
    return 0;

  size_t local_len = at - email;

  if (local_len > 64)
    return 0;

  size_t email_len = strlen(email);

  if (email_len > 320)
    return 0;

  size_t name_len = email_len - (local_len + 1);

  if (name_len > 254)
    return 0;

  name_len += 1;

  return 56 + 1 + 1 + strlen(tag) + 1 + name_len;
}

size_t
hns_dane_name_size(const char *tag, const char *name) {
  return 56 + 1 + 1 + strlen(tag) + 1 + strlen(name);
}

int
hns_parse_dane_reply (const unsigned char *abuf, int alen,
                      struct hns_dane_reply **dane_out, int expect)
{
  unsigned int qdcount, ancount, i;
  const unsigned char *aptr, *vptr;
  int status, rr_type, rr_class, rr_len;
  long len;
  char *hostname = NULL, *rr_name = NULL;
  struct hns_dane_reply *dane_head = NULL;
  struct hns_dane_reply *dane_last = NULL;
  struct hns_dane_reply *dane_curr;
  char *left, *right;
  size_t left_len, right_len;

  /* Set *dane_out to NULL for all failure cases. */
  *dane_out = NULL;

  /* Give up if abuf doesn't have room for a header. */
  if (alen < HFIXEDSZ)
    return HNS_EBADRESP;

  if (DNS_HEADER_AD(abuf) != 1)
    return HNS_EINSECURE;

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

      /* Check if we are really looking at a DANE record */
      if (rr_class == C_IN && rr_type == expect)
        {
          /* parse the DANE record itself */
          if (rr_len < 3)
            {
              status = HNS_EBADRESP;
              break;
            }

          /* Allocate storage for this DANE answer appending it to the list */
          dane_curr = hns_malloc_data(HNS_DATATYPE_DANE_REPLY);
          if (!dane_curr)
            {
              status = HNS_ENOMEM;
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

          vptr = aptr;
          dane_curr->usage = *vptr;
          vptr += 1;
          dane_curr->selector = *vptr;
          vptr += 1;
          dane_curr->matching_type = *vptr;
          vptr += 1;

          dane_curr->certificate_len = rr_len - 3;

          if (dane_curr->certificate_len != 0) {
            dane_curr->certificate = hns_malloc(dane_curr->certificate_len);

            if (!dane_curr->certificate) {
              status = HNS_ENOMEM;
              break;
            }

            memcpy(dane_curr->certificate, vptr, dane_curr->certificate_len);
          }
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
      if (dane_head)
        hns_free_data (dane_head);
      return status;
    }

  /* everything looks fine, return the data */
  *dane_out = dane_head;

  return HNS_SUCCESS;
}
