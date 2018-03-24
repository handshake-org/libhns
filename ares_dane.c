
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
    ares_free(ha);
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
tag(
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

  /* Return: */
  /* [0]: Offset after the header. */
  /* [1]: Size of bytes to read next. */
  if (off_out)
    *off_out = off;
  if (size_out)
    *size_out = size;

  return 1;
}

static int
read(
  const unsigned char *data,
  size_t data_len,
  int off,
  int *off_out,
  size_t *size_out
) {
  // Read seq-header, update offset to after header.
  return tag(data, data_len, off, 0x10, 0, off_out, size_out);
}

static int
gauge(const unsigned char *data, size_t data_len, int off, size_t *size_out) {
  int pos;
  size_t size;

  // Get total size of seq-header + data.
  if (!read(data, data_len, off, &pos, &size))
    return 0;

  *size_out = (pos - off) + size;

  return 1;
}

static int
seq(const unsigned char *data, size_t data_len, int off, size_t *off_out) {
  // Read seq-header, return offset after header.
  return read(data, data_len, off, off_out, NULL);
}

static int
skip(const unsigned char *data, size_t data_len, int off, int *off_out) {
  int offset;
  size_t size;

  // Read seq-header, return offset after header+data.
  if (!read(data, data_len, off, &offset, &size))
    return 0;

  *off_out = offset + size;

  return 1;
}

static int
iint(const unsigned char *data, size_t data_len, int off, int *off_out) {
  int offset;
  size_t size;

  // Read int-header, return offset after header+data.
  if (!tag(data, data_len, off, 0x02, 0, &offset, &size))
    return 0;

  *off_out = offset + size;

  return 1;
}

static int
xint(const unsigned char *data, size_t data_len, int off, int *off_out) {
  int offset;
  size_t size;

  // Read int-header, return offset after header+data.
  if (!tag(data, data_len, off, 0x00, 1, &offset, &size))
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

  if (!gauge(data, cert_len, 0, &size))
    return 0;

  *out = data;
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

  // cert
  if (!seq(data, data_len, off, &off))
    return 0;

  // tbs
  if (!seq(data, data_len, off, &off))
    return 0;

  // version
  if (!xint(data, data_len, off, &off))
    return 0;

  // serial
  if (!iint(data, data_len, off, &off))
    return 0;

  // alg ident
  if (!skip(data, data_len, off, &off))
    return 0;

  // issuer
  if (!skip(data, data_len, off, &off))
    return 0;

  // validity
  if (!skip(data, data_len, off, &off))
    return 0;

  // subject
  if (!skip(data, data_len, off, &off))
    return 0;

  // pubkeyinfo
  if (!gauge(data, data_len, off, &size))
    return 0;

  if (off + size >= data_len)
    return 0;

  *out = &data[off];
  *out_len = size;

  return 1;
}

static int
ares_dane_verify(
  unsigned char *cert,
  size_t cert_len,
  unsigned short selector,
  unsigned short matching_type,
  unsigned char *certificate,
  size_t certificate_len
) {
  unsigned char *data = NULL;
  size_t data_len = 0;
  unsigned char buf[64];
  unsigned char *hash = NULL;
  size_t hash_len = 0;

  switch (selector) {
    case 0: // Full
      if (!get_cert(cert, cert_len, &data, &data_len))
        return 0;
      break;
    case 1: // SPKI
      if (!get_pubkeyinfo(cert, cert_len, &data, &data_len))
        return 0;
      break;
  }

  if (!data)
    return 0;

  switch (matching_type) {
    case 0: { // NONE
      hash = data;
      hash_len = data_len;
      break;
    }

    case 1: { // SHA256
      ares_sha256_ctx ctx;
      ares_sha256_init(&ctx);
      ares_sha256_update(&ctx, data, data_len);
      ares_sha256_final(&ctx, &buf[0]);
      hash = &buf[0];
      hash_len = 32;
      break;
    }

    case 2: { // SHA512
      ares_sha512_ctx ctx;
      ares_sha512_init(&ctx);
      ares_sha512_update(&ctx, data, data_len);
      ares_sha512_final(&ctx, &buf[0]);
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
ares_tlsa_encode_name(
  const char *name,
  const char *protocol,
  unsigned int port,
  char *out,
  size_t out_len
) {
  if (out) {
    size_t size = ares_tlsa_encode_name(name, protocol, port, NULL, 0);
    if (size > out_len)
      return 0;
  }
  return sprintf(out, "_%u._%s.%s", port, protocol, name);
}

size_t
ares_tlsa_name_size(
  const char *name,
  char *protocol,
  unsigned int port
) {
  return ares_tlsa_encode_name(name, protocol, port, NULL, 0);
}

int
ares_tlsa_decode_name(const char *name, char **protocol, unsigned int *port) {
  char *a, *b;
  size_t al, bl;

  if (name == NULL || port == NULL || protocol == NULL)
    return 0;

  /* TLSA RR names exist as _[port]._[protocol].name. */

  /* Parse the first two labels, minus the `_` prefixes. */
  if (!read_labels(name, &a, &al, &b, &bl))
    return 0;

  /* Parse the port. */
  if (!read_port(a, al, port))
    return 0;

  /* Parse the protocol name. */
  if (!read_protocol(b, bl, protocol))
    return 0;

  return 1;
}

int
ares_tlsa_verify(
  struct ares_tlsa_reply *tlsa_reply,
  unsigned char *cert,
  size_t cert_len
) {
  if (tlsa_reply->type != T_TLSA)
    return 0;

  if (!tlsa_reply->certificate)
    return 0;

  return ares_dane_verify(
    cert,
    cert_len,
    tlsa_reply->selector,
    tlsa_reply->matching_type,
    tlsa_reply->certificate,
    tlsa_reply->certificate_len
  );
}

int
ares_tlsa_verify_name(
  struct ares_tlsa_reply *tlsa_reply,
  const char *protocol,
  unsigned int port
) {
  if (tlsa_reply->type != T_TLSA)
    return 0;

  if (!tlsa_reply->protocol)
    return 0;

  if (strcmp(tlsa_reply->protocol, protocol) != 0)
    return 0;

  if (tlsa_reply->port != port)
    return 0;

  return 1;
}

int
ares_smimea_encode_name(
  const char *name,
  const char *email,
  char *out,
  size_t out_len
) {
  char hex[57];

  if (out) {
    size_t size = ares_smimea_encode_name(name, email, NULL, 0);

    if (size > out_len)
      return 0;

    unsigned char hash[32];

    ares_sha256_ctx ctx;
    ares_sha256_init(&ctx);
    ares_sha256_update(&ctx, email, strlen(email));
    ares_sha256_final(&ctx, hash);

    encode_hex(hash, 28, hex);
  } else {
    memset(hex, '0', sizeof(hex) - 1);
    hex[56] = '\0';
  }

  return sprintf(out, "_%s._smimea.%s", hex, name);
}

size_t
ares_smimea_name_size(
  const char *name,
  char *protocol,
  unsigned int port
) {
  return ares_smimea_encode_name(name, protocol, port, NULL, 0);
}

int
ares_smimea_decode_name(const char *name, unsigned char **hash) {
  char *a, *b;
  size_t al, bl;

  if (name == NULL || hash == NULL)
    return 0;

  /* SMIMEA RR names exist as _[hash]._smimea.name. */

  /* Parse the first two labels, minus the `_` prefixes. */
  if (!read_labels(name, &a, &al, &b, &bl))
    return 0;

  /* Parse the 28 byte hash (hex encoded). */
  if (!read_hash(a, al, hash))
    return 0;

  /* Ensure the second label is `smimea`. */
  if (!read_smimea(b, bl))
    return 0;

  return 1;
}

int
ares_smimea_verify(
  struct ares_smimea_reply *smimea_reply,
  unsigned char *cert,
  size_t cert_len
) {
  if (smimea_reply->type != T_SMIMEA)
    return 0;

  if (!smimea_reply->certificate)
    return 0;

  return ares_dane_verify(
    cert,
    cert_len,
    smimea_reply->selector,
    smimea_reply->matching_type,
    smimea_reply->certificate,
    smimea_reply->certificate_len
  );
}

int
ares_smimea_verify_name(
  struct ares_smimea_reply *smimea_reply,
  const char *email
) {
  if (smimea_reply->type != T_SMIMEA)
    return 0;

  if (!smimea_reply->hash)
    return 0;

  unsigned char hash[32];

  ares_sha256_ctx ctx;
  ares_sha256_init(&ctx);
  ares_sha256_update(&ctx, email, strlen(email));
  ares_sha256_final(&ctx, hash);

  if (memcmp(smimea_reply->hash, hash, 28) != 0)
    return 0;

  return 1;
}
