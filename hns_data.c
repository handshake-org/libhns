
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


#include "hns_setup.h"

#include <stddef.h>

#include "hns.h"
#include "hns_data.h"
#include "hns_private.h"


/*
** hns_free_data() - hns external API function.
**
** This function must be used by the application to free data memory that
** has been internally allocated by some hns function and for which a
** pointer has already been returned to the calling application. The list
** of hns functions returning pointers that must be free'ed using this
** function is:
**
**   hns_get_servers()
**   hns_parse_srv_reply()
**   hns_parse_txt_reply()
*/

void hns_free_data(void *dataptr)
{
  while (dataptr != NULL) {
    struct hns_data *ptr;
    void *next_data = NULL;

#ifdef __INTEL_COMPILER
#  pragma warning(push)
#  pragma warning(disable:1684)
   /* 1684: conversion from pointer to same-sized integral type */
#endif

    ptr = (void *)((char *)dataptr - offsetof(struct hns_data, data));

#ifdef __INTEL_COMPILER
#  pragma warning(pop)
#endif

    if (ptr->mark != HNS_DATATYPE_MARK)
      return;

    switch (ptr->type)
      {
        case HNS_DATATYPE_MX_REPLY:

          if (ptr->data.mx_reply.next)
            next_data = ptr->data.mx_reply.next;
          if (ptr->data.mx_reply.host)
            hns_free(ptr->data.mx_reply.host);
          break;

        case HNS_DATATYPE_SRV_REPLY:

          if (ptr->data.srv_reply.next)
            next_data = ptr->data.srv_reply.next;
          if (ptr->data.srv_reply.host)
            hns_free(ptr->data.srv_reply.host);
          break;

        case HNS_DATATYPE_TXT_REPLY:
        case HNS_DATATYPE_TXT_EXT:

          if (ptr->data.txt_reply.next)
            next_data = ptr->data.txt_reply.next;
          if (ptr->data.txt_reply.txt)
            hns_free(ptr->data.txt_reply.txt);
          break;

        case HNS_DATATYPE_ADDR_NODE:

          if (ptr->data.addr_node.next)
            next_data = ptr->data.addr_node.next;
          break;

        case HNS_DATATYPE_ADDR_PORT_NODE:

          if (ptr->data.addr_port_node.next)
            next_data = ptr->data.addr_port_node.next;
          break;

        case HNS_DATATYPE_NAPTR_REPLY:

          if (ptr->data.naptr_reply.next)
            next_data = ptr->data.naptr_reply.next;
          if (ptr->data.naptr_reply.flags)
            hns_free(ptr->data.naptr_reply.flags);
          if (ptr->data.naptr_reply.service)
            hns_free(ptr->data.naptr_reply.service);
          if (ptr->data.naptr_reply.regexp)
            hns_free(ptr->data.naptr_reply.regexp);
          if (ptr->data.naptr_reply.replacement)
            hns_free(ptr->data.naptr_reply.replacement);
          break;

        case HNS_DATATYPE_SOA_REPLY:
          if (ptr->data.soa_reply.nsname)
            hns_free(ptr->data.soa_reply.nsname);
          if (ptr->data.soa_reply.hostmaster)
            hns_free(ptr->data.soa_reply.hostmaster);
          break;

        case HNS_DATATYPE_SSHFP_REPLY:
          if (ptr->data.sshfp_reply.next)
            next_data = ptr->data.sshfp_reply.next;
          if (ptr->data.sshfp_reply.fingerprint)
            hns_free(ptr->data.sshfp_reply.fingerprint);
          break;

        case HNS_DATATYPE_DANE_REPLY:
          if (ptr->data.dane_reply.next)
            next_data = ptr->data.dane_reply.next;
          if (ptr->data.dane_reply.certificate)
            hns_free(ptr->data.dane_reply.certificate);
          break;

        case HNS_DATATYPE_OPENPGPKEY_REPLY:
          if (ptr->data.openpgpkey_reply.next)
            next_data = ptr->data.openpgpkey_reply.next;
          if (ptr->data.openpgpkey_reply.pubkey)
            hns_free(ptr->data.openpgpkey_reply.pubkey);
          break;

        default:
          return;
      }

    hns_free(ptr);
    dataptr = next_data;
  }
}


/*
** hns_malloc_data() - hns internal helper function.
**
** This function allocates memory for a hns private hns_data struct
** for the specified hns_datatype, initializes hns private fields
** and zero initializes those which later might be used from the public
** API. It returns an interior pointer which can be passed by hns
** functions to the calling application, and that must be free'ed using
** hns external API function hns_free_data().
*/

void *hns_malloc_data(hns_datatype type)
{
  struct hns_data *ptr;

  ptr = hns_malloc(sizeof(struct hns_data));
  if (!ptr)
    return NULL;

  switch (type)
    {
      case HNS_DATATYPE_MX_REPLY:
        ptr->data.mx_reply.next = NULL;
        ptr->data.mx_reply.host = NULL;
        ptr->data.mx_reply.priority = 0;
        break;

      case HNS_DATATYPE_SRV_REPLY:
        ptr->data.srv_reply.next = NULL;
        ptr->data.srv_reply.host = NULL;
        ptr->data.srv_reply.priority = 0;
        ptr->data.srv_reply.weight = 0;
        ptr->data.srv_reply.port = 0;
        break;

      case HNS_DATATYPE_TXT_EXT:
        ptr->data.txt_ext.record_start = 0;
        /* FALLTHROUGH */

      case HNS_DATATYPE_TXT_REPLY:
        ptr->data.txt_reply.next = NULL;
        ptr->data.txt_reply.txt = NULL;
        ptr->data.txt_reply.length = 0;
        break;

      case HNS_DATATYPE_ADDR_NODE:
        ptr->data.addr_node.next = NULL;
        ptr->data.addr_node.family = 0;
        memset(&ptr->data.addr_node.addrV6, 0,
               sizeof(ptr->data.addr_node.addrV6));
        break;

      case HNS_DATATYPE_ADDR_PORT_NODE:
        ptr->data.addr_port_node.next = NULL;
        ptr->data.addr_port_node.family = 0;
        ptr->data.addr_port_node.udp_port = 0;
        ptr->data.addr_port_node.tcp_port = 0;
        memset(&ptr->data.addr_port_node.addrV6, 0,
               sizeof(ptr->data.addr_port_node.addrV6));
        break;

      case HNS_DATATYPE_NAPTR_REPLY:
        ptr->data.naptr_reply.next = NULL;
        ptr->data.naptr_reply.flags = NULL;
        ptr->data.naptr_reply.service = NULL;
        ptr->data.naptr_reply.regexp = NULL;
        ptr->data.naptr_reply.replacement = NULL;
        ptr->data.naptr_reply.order = 0;
        ptr->data.naptr_reply.preference = 0;
        break;

      case HNS_DATATYPE_SOA_REPLY:
        ptr->data.soa_reply.nsname = NULL;
        ptr->data.soa_reply.hostmaster = NULL;
        ptr->data.soa_reply.serial = 0;
        ptr->data.soa_reply.refresh = 0;
        ptr->data.soa_reply.retry = 0;
        ptr->data.soa_reply.expire = 0;
        ptr->data.soa_reply.minttl = 0;
        break;

      case HNS_DATATYPE_SSHFP_REPLY:
        ptr->data.sshfp_reply.next = NULL;
        ptr->data.sshfp_reply.algorithm = 0;
        ptr->data.sshfp_reply.digest_type = 0;
        ptr->data.sshfp_reply.fingerprint = NULL;
        ptr->data.sshfp_reply.fingerprint_len = 0;
        break;

      case HNS_DATATYPE_DANE_REPLY:
        ptr->data.dane_reply.next = NULL;
        ptr->data.dane_reply.usage = 0;
        ptr->data.dane_reply.selector = 0;
        ptr->data.dane_reply.matching_type = 0;
        ptr->data.dane_reply.certificate = NULL;
        ptr->data.dane_reply.certificate_len = 0;
        break;

      case HNS_DATATYPE_OPENPGPKEY_REPLY:
        ptr->data.openpgpkey_reply.next = NULL;
        ptr->data.openpgpkey_reply.pubkey = NULL;
        ptr->data.openpgpkey_reply.pubkey_len = 0;
        break;

      default:
        hns_free(ptr);
        return NULL;
    }

  ptr->mark = HNS_DATATYPE_MARK;
  ptr->type = type;

  return &ptr->data;
}
