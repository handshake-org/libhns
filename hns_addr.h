#ifndef HEADER_HNS_ADDR_H
#define HEADER_HNS_ADDR_H

#include <stdlib.h>

/* INET6_ADDRSTRLEN = 65 */
/* 65 + 5 + 1 + 2 = 73 - long enough for [ipv6]:port */
/* 73 + 53  + 1 = 127 - long enough for pubkey@[ipv6]:port */
#define HNS_MAX_HOST 127

void
hns_addr_init(struct hns_addr *addr);

int
hns_addr_from_string(
  struct hns_addr *addr,
  const char *src,
  unsigned int port
);

int
hns_addr_to_string(
  struct hns_addr *addr,
  char *dst,
  size_t dst_len,
  unsigned int fb
);

int
hns_addr_to_full(
  struct hns_addr *addr,
  char *dst,
  size_t dst_len,
  unsigned int fb
);
#endif
