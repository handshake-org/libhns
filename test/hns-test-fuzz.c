#include <stddef.h>

#include "hns.h"

// Entrypoint for Clang's libfuzzer
int LLVMFuzzerTestOneInput(const unsigned char *data,
                           unsigned long size) {
  // Feed the data into each of the hns_parse_*_reply functions.
  struct hostent *host = NULL;
  struct hns_addrttl info[5];
  int count = 5;
  hns_parse_a_reply(data, size, &host, info, &count);
  if (host) hns_free_hostent(host);

  host = NULL;
  struct hns_addr6ttl info6[5];
  count = 5;
  hns_parse_aaaa_reply(data, size, &host, info6, &count);
  if (host) hns_free_hostent(host);

  host = NULL;
  unsigned char addrv4[4] = {0x10, 0x20, 0x30, 0x40};
  hns_parse_ptr_reply(data, size, addrv4, sizeof(addrv4), AF_INET, &host);
  if (host) hns_free_hostent(host);

  host = NULL;
  hns_parse_ns_reply(data, size, &host);
  if (host) hns_free_hostent(host);

  struct hns_srv_reply* srv = NULL;
  hns_parse_srv_reply(data, size, &srv);
  if (srv) hns_free_data(srv);

  struct hns_mx_reply* mx = NULL;
  hns_parse_mx_reply(data, size, &mx);
  if (mx) hns_free_data(mx);

  struct hns_txt_reply* txt = NULL;
  hns_parse_txt_reply(data, size, &txt);
  if (txt) hns_free_data(txt);

  struct hns_soa_reply* soa = NULL;
  hns_parse_soa_reply(data, size, &soa);
  if (soa) hns_free_data(soa);

  struct hns_naptr_reply* naptr = NULL;
  hns_parse_naptr_reply(data, size, &naptr);
  if (naptr) hns_free_data(naptr);

  return 0;
}
