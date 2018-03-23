#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "ares_setup.h"

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "ares.h"
#include "ares_inet_net_pton.h"
#include "ares_private.h"
#include "ares_base32.h"
#include "ares_addr.h"

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 65
#endif

int
ares_addr_from_string(
  struct ares_addr *addr,
  char *src,
  unsigned short port
) {
  assert(addr);

  if (!src)
    return 0;

  addr->key = NULL;

  char *at = strchr(src, '@');

  if (at) {
    char pubkey[54];
    size_t pubkey_len = at - src;

    if (pubkey_len > 53)
      return 0;

    memcpy(pubkey, src, pubkey_len);
    pubkey[pubkey_len] = '\0';

    if (ares_base32_decode_size(pubkey) != 33)
      return 0;

    if (ares_base32_decode(pubkey, addr->key_, 0) == -1)
      return 0;

    addr->key = &addr->key_[0];
    src = &at[1];
  }

  char host[INET6_ADDRSTRLEN + 1];
  char *host_start;
  size_t host_len;
  char *port_s = NULL;

  if (src[0] == '[') {
    char *bracket = strchr(src, ']');

    if (!bracket)
      return 0;

    host_start = &src[1];
    host_len = bracket - host_start;

    if (bracket[1] == ':')
      port_s = &bracket[2];
    else if (bracket[1] == '\0')
      port_s = NULL;
    else
      return 0;
  } else {
    char *colon = strchr(src, ':');

    // ipv6 with no port.
    if (colon && strchr(&colon[1], ':'))
      colon = NULL;

    host_start = src;

    if (colon) {
      host_len = colon - src;
      port_s = &colon[1];
    } else {
      host_len = strlen(src);
      port_s = NULL;
    }
  }

  if (host_len > INET6_ADDRSTRLEN)
    return 0;

  memcpy(host, host_start, host_len);
  host[host_len] = '\0';

  unsigned short sin_port = port;

  if (port && port_s) {
    int i = 0;
    unsigned int word = 0;
    char *s = port_s;

    for (; *s; s++) {
      int ch = ((int)*s) - 0x30;

      if (ch < 0 || ch > 9)
        return 0;

      if (i == 5)
        return 0;

      word *= 10;
      word += ch;

      i += 1;
    }

    sin_port = (unsigned short)word;
  } else if (!port && port_s) {
    return 0;
  }

  unsigned char sin_addr[16];
  unsigned short af;

  if (ares_inet_pton(AF_INET, host, sin_addr) == 1) {
    af = AF_INET;
  } else if (ares_inet_pton(AF_INET6, host, sin_addr) == 1) {
    af = AF_INET6;
  } else {
    return 0;
  }

  addr->family = af;

  if (addr->family == AF_INET)
    memcpy(addr->addrV4, sin_addr, sizeof(addr->addrV4));
  else
    memcpy(addr->addrV6, sin_addr, sizeof(addr->addrV6));

  addr->udp_port = htons(sin_port);
  addr->tcp_port = htons(sin_port);

  return 1;
}

int
ares_addr_to_string(
  struct ares_addr *addr,
  char *dst,
  size_t dst_len,
  unsigned short fb
) {
  assert(addr);

  if (!dst)
    return 0;

  unsigned short af = addr->family;
  unsigned char *ip;

  if (addr->family == AF_INET)
    ip = addr->addrV4;
  else
    ip = addr->addrV6;

  unsigned short port = ntohs(addr->udp_port);

  if (ares_inet_ntop(af, ip, dst, dst_len) == 0)
    return 0;

  if (fb) {
    size_t len = strlen(dst);
    size_t need = af == AF_INET6 ? 9 : 7;

    if (dst_len - len < need)
      return 0;

    if (!port)
      port = fb;

    if (af == AF_INET6) {
      assert(len + need < ARES_MAX_HOST);
      char tmp[ARES_MAX_HOST];
      sprintf(tmp, "[%s]:%d", dst, port);
      strcpy(dst, tmp);
    } else {
      sprintf(dst, "%s:%d", dst, port);
    }
  }

  return 1;
}

int
ares_addr_to_full(
  struct ares_addr *addr,
  char *dst,
  size_t dst_len,
  unsigned short fb
) {
  if (!ares_addr_to_string(addr, dst, dst_len, fb))
    return 0;

  if (!addr->key)
    return 1;

  size_t len = strlen(dst);
  size_t size = ares_base32_encode_size(addr->key, 33, 0);

  if (dst_len - len < size + 1)
    return 0;

  assert(size <= 54);
  assert(len + (size - 1) + 1 < ARES_MAX_HOST);

  char b32[54];
  ares_base32_encode(addr->key, 33, b32, 0);

  char tmp[ARES_MAX_HOST];
  sprintf(tmp, "%s@%s", b32, dst);
  strcpy(dst, tmp);

  return 1;
}
