
/* Copyright 1998 by the Massachusetts Institute of Technology.
 * Copyright (C) 2008-2013 by Daniel Stenberg
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

#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif

#include "hns.h"
#include "hns_data.h"
#include "hns_inet_net_pton.h"
#include "hns_private.h"
#include "hns_addr.h"


int hns_get_servers(hns_channel channel,
                     struct hns_addr_node **servers)
{
  struct hns_addr_node *srvr_head = NULL;
  struct hns_addr_node *srvr_last = NULL;
  struct hns_addr_node *srvr_curr;
  int status = HNS_SUCCESS;
  int i;

  if (!channel)
    return HNS_ENODATA;

  for (i = 0; i < channel->nservers; i++)
    {
      /* Allocate storage for this server node appending it to the list */
      srvr_curr = hns_malloc_data(HNS_DATATYPE_ADDR_NODE);
      if (!srvr_curr)
        {
          status = HNS_ENOMEM;
          break;
        }
      if (srvr_last)
        {
          srvr_last->next = srvr_curr;
        }
      else
        {
          srvr_head = srvr_curr;
        }
      srvr_last = srvr_curr;

      /* Fill this server node data */
      srvr_curr->family = channel->servers[i].addr.family;
      if (srvr_curr->family == AF_INET)
        memcpy(&srvr_curr->addrV4, &channel->servers[i].addr.addrV4,
               sizeof(srvr_curr->addrV4));
      else
        memcpy(&srvr_curr->addrV6, &channel->servers[i].addr.addrV6,
               sizeof(srvr_curr->addrV6));
    }

  if (status != HNS_SUCCESS)
    {
      if (srvr_head)
        {
          hns_free_data(srvr_head);
          srvr_head = NULL;
        }
    }

  *servers = srvr_head;

  return status;
}

int hns_get_servers_ports(hns_channel channel,
                           struct hns_addr_port_node **servers)
{
  struct hns_addr_port_node *srvr_head = NULL;
  struct hns_addr_port_node *srvr_last = NULL;
  struct hns_addr_port_node *srvr_curr;
  int status = HNS_SUCCESS;
  int i;

  if (!channel)
    return HNS_ENODATA;

  for (i = 0; i < channel->nservers; i++)
    {
      /* Allocate storage for this server node appending it to the list */
      srvr_curr = hns_malloc_data(HNS_DATATYPE_ADDR_PORT_NODE);
      if (!srvr_curr)
        {
          status = HNS_ENOMEM;
          break;
        }
      if (srvr_last)
        {
          srvr_last->next = srvr_curr;
        }
      else
        {
          srvr_head = srvr_curr;
        }
      srvr_last = srvr_curr;

      /* Fill this server node data */
      srvr_curr->family = channel->servers[i].addr.family;
      srvr_curr->udp_port = ntohs((unsigned short)channel->servers[i].addr.udp_port);
      srvr_curr->tcp_port = ntohs((unsigned short)channel->servers[i].addr.tcp_port);
      if (srvr_curr->family == AF_INET)
        memcpy(&srvr_curr->addrV4, &channel->servers[i].addr.addrV4,
               sizeof(srvr_curr->addrV4));
      else
        memcpy(&srvr_curr->addrV6, &channel->servers[i].addr.addrV6,
               sizeof(srvr_curr->addrV6));
    }

  if (status != HNS_SUCCESS)
    {
      if (srvr_head)
        {
          hns_free_data(srvr_head);
          srvr_head = NULL;
        }
    }

  *servers = srvr_head;

  return status;
}

int hns_set_servers(hns_channel channel,
                     struct hns_addr_node *servers)
{
  struct hns_addr_node *srvr;
  int num_srvrs = 0;
  int i;

  if (hns_library_initialized() != HNS_SUCCESS)
    return HNS_ENOTINITIALIZED;  /* LCOV_EXCL_LINE: n/a on non-WinSock */

  if (!channel)
    return HNS_ENODATA;

  hns__destroy_servers_state(channel);

  for (srvr = servers; srvr; srvr = srvr->next)
    {
      num_srvrs++;
    }

  if (num_srvrs > 0)
    {
      /* Allocate storage for servers state */
      channel->servers = hns_malloc(num_srvrs * sizeof(struct server_state));
      if (!channel->servers)
        {
          return HNS_ENOMEM;
        }
      channel->nservers = num_srvrs;
      /* Fill servers state address data */
      for (i = 0, srvr = servers; srvr; i++, srvr = srvr->next)
        {
          hns_addr_init(&channel->servers[i].addr);
          channel->servers[i].addr.family = srvr->family;
          channel->servers[i].addr.udp_port = 0;
          channel->servers[i].addr.tcp_port = 0;
          if (srvr->family == AF_INET)
            memcpy(&channel->servers[i].addr.addrV4, &srvr->addrV4,
                   sizeof(srvr->addrV4));
          else
            memcpy(&channel->servers[i].addr.addrV6, &srvr->addrV6,
                   sizeof(srvr->addrV6));
        }
      /* Initialize servers state remaining data */
      hns__init_servers_state(channel);
    }

  return HNS_SUCCESS;
}

int hns_set_servers_ports(hns_channel channel,
                           struct hns_addr_port_node *servers)
{
  struct hns_addr_port_node *srvr;
  int num_srvrs = 0;
  int i;

  if (hns_library_initialized() != HNS_SUCCESS)
    return HNS_ENOTINITIALIZED;  /* LCOV_EXCL_LINE: n/a on non-WinSock */

  if (!channel)
    return HNS_ENODATA;

  hns__destroy_servers_state(channel);

  for (srvr = servers; srvr; srvr = srvr->next)
    {
      num_srvrs++;
    }

  if (num_srvrs > 0)
    {
      /* Allocate storage for servers state */
      channel->servers = hns_malloc(num_srvrs * sizeof(struct server_state));
      if (!channel->servers)
        {
          return HNS_ENOMEM;
        }
      channel->nservers = num_srvrs;
      /* Fill servers state address data */
      for (i = 0, srvr = servers; srvr; i++, srvr = srvr->next)
        {
          hns_addr_init(&channel->servers[i].addr);
          channel->servers[i].addr.family = srvr->family;
          channel->servers[i].addr.udp_port = htons((unsigned short)srvr->udp_port);
          channel->servers[i].addr.tcp_port = htons((unsigned short)srvr->tcp_port);
          if (srvr->family == AF_INET)
            memcpy(&channel->servers[i].addr.addrV4, &srvr->addrV4,
                   sizeof(srvr->addrV4));
          else
            memcpy(&channel->servers[i].addr.addrV6, &srvr->addrV6,
                   sizeof(srvr->addrV6));
        }
      /* Initialize servers state remaining data */
      hns__init_servers_state(channel);
    }

  return HNS_SUCCESS;
}

/* Incomming string format: host[:port][,host[:port]]... */
/* IPv6 addresses with ports require square brackets [fe80::1%lo0]:53 */
static int set_servers_csv(hns_channel channel,
                           const char* _csv, int use_port)
{
  size_t i;
  char* csv = NULL;
  char* ptr;
  char* start_host;
  int cc = 0;
  int rv = HNS_SUCCESS;
  struct hns_addr_port_node *servers = NULL;
  struct hns_addr_port_node *last = NULL;

  if (hns_library_initialized() != HNS_SUCCESS)
    return HNS_ENOTINITIALIZED;  /* LCOV_EXCL_LINE: n/a on non-WinSock */

  if (!channel)
    return HNS_ENODATA;

  i = strlen(_csv);
  if (i == 0)
     return HNS_SUCCESS; /* blank all servers */

  csv = hns_malloc(i + 2);
  if (!csv)
    return HNS_ENOMEM;

  strcpy(csv, _csv);
  if (csv[i-1] != ',') { /* make parsing easier by ensuring ending ',' */
    csv[i] = ',';
    csv[i+1] = 0;
  }

  start_host = csv;
  for (ptr = csv; *ptr; ptr++) {
    if (*ptr == ':') {
      /* count colons to determine if we have an IPv6 number or IPv4 with
         port */
      cc++;
    }
    else if (*ptr == '[') {
      /* move start_host if an open square bracket is found wrapping an IPv6
         address */
      start_host = ptr + 1;
    }
    else if (*ptr == ',') {
      char* pp = ptr - 1;
      char* p = ptr;
      int port = 0;
      struct in_addr in4;
      struct hns_in6_addr in6;
      struct hns_addr_port_node *s = NULL;

      *ptr = 0; /* null terminate host:port string */
      /* Got an entry..see if the port was specified. */
      if (cc > 0) {
        while (pp > start_host) {
          /* a single close square bracket followed by a colon, ']:' indicates
             an IPv6 address with port */
          if ((*pp == ']') && (*p == ':'))
            break; /* found port */
          /* a single colon, ':' indicates an IPv4 address with port */
          if ((*pp == ':') && (cc == 1))
            break; /* found port */
          if (!(ISDIGIT(*pp) || (*pp == ':'))) {
            /* Found end of digits before we found :, so wasn't a port */
            /* must allow ':' for IPv6 case of ']:' indicates we found a port */
            pp = p = ptr;
            break;
          }
          pp--;
          p--;
        }
        if ((pp != start_host) && ((pp + 1) < ptr)) {
          /* Found it. Parse over the port number */
          /* when an IPv6 address is wrapped with square brackets the port
             starts at pp + 2 */
          if (*pp == ']')
            p++; /* move p before ':' */
          /* p will point to the start of the port */
          port = (int)strtol(p, NULL, 10);
          *pp = 0; /* null terminate host */
        }
      }
      /* resolve host, try ipv4 first, rslt is in network byte order */
      rv = hns_inet_pton(AF_INET, start_host, &in4);
      if (!rv) {
        /* Ok, try IPv6 then */
        rv = hns_inet_pton(AF_INET6, start_host, &in6);
        if (!rv) {
          rv = HNS_EBADSTR;
          goto out;
        }
        /* was ipv6, add new server */
        s = hns_malloc(sizeof(*s));
        if (!s) {
          rv = HNS_ENOMEM;
          goto out;
        }
        s->family = AF_INET6;
        memcpy(&s->addr, &in6, sizeof(struct hns_in6_addr));
      }
      else {
        /* was ipv4, add new server */
        s = hns_malloc(sizeof(*s));
        if (!s) {
          rv = HNS_ENOMEM;
          goto out;
        }
        s->family = AF_INET;
        memcpy(&s->addr, &in4, sizeof(struct in_addr));
      }
      if (s) {
        s->udp_port = use_port ? port: 0;
        s->tcp_port = s->udp_port;
        s->next = NULL;
        if (last) {
          last->next = s;
          /* need to move last to maintain the linked list */
          last = last->next;
        }
        else {
          servers = s;
          last = s;
        }
      }

      /* Set up for next one */
      start_host = ptr + 1;
      cc = 0;
    }
  }

  rv = hns_set_servers_ports(channel, servers);

  out:
  if (csv)
    hns_free(csv);
  while (servers) {
    struct hns_addr_port_node *s = servers;
    servers = servers->next;
    hns_free(s);
  }

  return rv;
}

int hns_set_servers_csv(hns_channel channel,
                         const char* _csv)
{
  return set_servers_csv(channel, _csv, FALSE);
}

int hns_set_servers_ports_csv(hns_channel channel,
                               const char* _csv)
{
  return set_servers_csv(channel, _csv, TRUE);
}

