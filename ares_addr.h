#ifndef HEADER_CARES_ADDR_H
#define HEADER_CARES_ADDR_H

#include <stdlib.h>

/* INET6_ADDRSTRLEN = 65 */
/* 65 + 5 + 1 + 2 = 73 - long enough for [ipv6]:port */
/* 73 + 53  + 1 = 127 - long enough for pubkey@[ipv6]:port */
#define ARES_MAX_HOST 127

void
ares_addr_init(struct ares_addr *addr);

int
ares_addr_from_string(
  struct ares_addr *addr,
  const char *src,
  unsigned int port
);

int
ares_addr_to_string(
  struct ares_addr *addr,
  char *dst,
  size_t dst_len,
  unsigned int fb
);

int
ares_addr_to_full(
  struct ares_addr *addr,
  char *dst,
  size_t dst_len,
  unsigned int fb
);
#endif