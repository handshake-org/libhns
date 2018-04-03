
/* Copyright (C) 2009-2013 by Daniel Stenberg
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

typedef enum {
  HNS_DATATYPE_UNKNOWN = 1,  /* unknown data type     - introduced in 1.7.0 */
  HNS_DATATYPE_SRV_REPLY,    /* struct hns_srv_reply - introduced in 1.7.0 */
  HNS_DATATYPE_TXT_REPLY,    /* struct hns_txt_reply - introduced in 1.7.0 */
  HNS_DATATYPE_TXT_EXT,      /* struct hns_txt_ext   - introduced in 1.11.0 */
  HNS_DATATYPE_ADDR_NODE,    /* struct hns_addr_node - introduced in 1.7.1 */
  HNS_DATATYPE_MX_REPLY,     /* struct hns_mx_reply   - introduced in 1.7.2 */
  HNS_DATATYPE_NAPTR_REPLY,  /* struct hns_naptr_reply - introduced in 1.7.6 */
  HNS_DATATYPE_SOA_REPLY,    /* struct hns_soa_reply - introduced in 1.9.0 */
  HNS_DATATYPE_SSHFP_REPLY,  /* struct hns_sshfp_reply */
  HNS_DATATYPE_DANE_REPLY,   /* struct hns_dane_reply */
  HNS_DATATYPE_OPENPGPKEY_REPLY, /* struct hns_openpgpkey_reply */
#if 0
  HNS_DATATYPE_ADDR6TTL,     /* struct hns_addrttl   */
  HNS_DATATYPE_ADDRTTL,      /* struct hns_addr6ttl  */
  HNS_DATATYPE_HOSTENT,      /* struct hostent        */
  HNS_DATATYPE_OPTIONS,      /* struct hns_options   */
#endif
  HNS_DATATYPE_ADDR_PORT_NODE, /* struct hns_addr_port_node - introduced in 1.11.0 */
  HNS_DATATYPE_LAST          /* not used              - introduced in 1.7.0 */
} hns_datatype;

#define HNS_DATATYPE_MARK 0xbead

/*
 * hns_data struct definition is internal to hns and shall not
 * be exposed by the public API in order to allow future changes
 * and extensions to it without breaking ABI.  This will be used
 * internally by hns as the container of multiple types of data
 * dynamically allocated for which a reference will be returned
 * to the calling application.
 *
 * hns API functions returning a pointer to hns internally
 * allocated data will actually be returning an interior pointer
 * into this hns_data struct.
 *
 * All this is 'invisible' to the calling application, the only
 * requirement is that this kind of data must be free'ed by the
 * calling application using hns_free_data() with the pointer
 * it has received from a previous hns function call.
 */

struct hns_data {
  hns_datatype type;  /* Actual data type identifier. */
  unsigned int  mark;  /* Private hns_data signature. */
  union {
    struct hns_txt_reply    txt_reply;
    struct hns_txt_ext      txt_ext;
    struct hns_srv_reply    srv_reply;
    struct hns_addr_node    addr_node;
    struct hns_addr_port_node  addr_port_node;
    struct hns_mx_reply     mx_reply;
    struct hns_naptr_reply  naptr_reply;
    struct hns_soa_reply    soa_reply;
    struct hns_sshfp_reply    sshfp_reply;
    struct hns_dane_reply   dane_reply;
    struct hns_openpgpkey_reply   openpgpkey_reply;
  } data;
};

void *hns_malloc_data(hns_datatype type);

