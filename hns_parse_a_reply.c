
/* Copyright 1998 by the Massachusetts Institute of Technology.
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

#ifdef HAVE_STRINGS_H
#  include <strings.h>
#endif

#ifdef HAVE_LIMITS_H
#  include <limits.h>
#endif

#include "hns.h"
#include "hns_dns.h"
#include "hns_private.h"

int hns_parse_a_reply(const unsigned char *abuf, int alen,
                       struct hostent **host,
                       struct hns_addrttl *addrttls, int *naddrttls)
{
  unsigned int qdcount, ancount;
  int status, i, rr_type, rr_class, rr_len, rr_ttl, naddrs;
  int cname_ttl = INT_MAX;  /* the TTL imposed by the CNAME chain */
  int naliases;
  long len;
  const unsigned char *aptr;
  char *hostname, *rr_name, *rr_data, **aliases;
  struct in_addr *addrs;
  struct hostent *hostent;
  const int max_addr_ttls = (addrttls && naddrttls) ? *naddrttls : 0;

  /* Set *host to NULL for all failure cases. */
  if (host)
    *host = NULL;
  /* Same with *naddrttls. */
  if (naddrttls)
    *naddrttls = 0;

  /* Give up if abuf doesn't have room for a header. */
  if (alen < HFIXEDSZ)
    return HNS_EBADRESP;

  /* Fetch the question and answer count from the header. */
  qdcount = DNS_HEADER_QDCOUNT(abuf);
  ancount = DNS_HEADER_ANCOUNT(abuf);
  if (qdcount != 1)
    return HNS_EBADRESP;

  /* Expand the name from the question, and skip past the question. */
  aptr = abuf + HFIXEDSZ;
  status = hns__expand_name_for_response(aptr, abuf, alen, &hostname, &len);
  if (status != HNS_SUCCESS)
    return status;
  if (aptr + len + QFIXEDSZ > abuf + alen)
    {
      hns_free(hostname);
      return HNS_EBADRESP;
    }
  aptr += len + QFIXEDSZ;

  if (host)
    {
      /* Allocate addresses and aliases; ancount gives an upper bound for
         both. */
      addrs = hns_malloc(ancount * sizeof(struct in_addr));
      if (!addrs)
        {
          hns_free(hostname);
          return HNS_ENOMEM;
        }
      aliases = hns_malloc((ancount + 1) * sizeof(char *));
      if (!aliases)
        {
          hns_free(hostname);
          hns_free(addrs);
          return HNS_ENOMEM;
        }
    }
  else
    {
      addrs = NULL;
      aliases = NULL;
    }

  naddrs = 0;
  naliases = 0;

  /* Examine each answer resource record (RR) in turn. */
  for (i = 0; i < (int)ancount; i++)
    {
      /* Decode the RR up to the data field. */
      status = hns__expand_name_for_response(aptr, abuf, alen, &rr_name, &len);
      if (status != HNS_SUCCESS)
        break;
      aptr += len;
      if (aptr + RRFIXEDSZ > abuf + alen)
        {
          hns_free(rr_name);
          status = HNS_EBADRESP;
          break;
        }
      rr_type = DNS_RR_TYPE(aptr);
      rr_class = DNS_RR_CLASS(aptr);
      rr_len = DNS_RR_LEN(aptr);
      rr_ttl = DNS_RR_TTL(aptr);
      aptr += RRFIXEDSZ;
      if (aptr + rr_len > abuf + alen)
        {
          hns_free(rr_name);
          status = HNS_EBADRESP;
          break;
        }

      if (rr_class == C_IN && rr_type == T_A
          && rr_len == sizeof(struct in_addr)
          && strcasecmp(rr_name, hostname) == 0)
        {
          if (addrs)
            {
              if (aptr + sizeof(struct in_addr) > abuf + alen)
              {  /* LCOV_EXCL_START: already checked above */
                hns_free(rr_name);
                status = HNS_EBADRESP;
                break;
              }  /* LCOV_EXCL_STOP */
              memcpy(&addrs[naddrs], aptr, sizeof(struct in_addr));
            }
          if (naddrs < max_addr_ttls)
            {
              struct hns_addrttl * const at = &addrttls[naddrs];
              if (aptr + sizeof(struct in_addr) > abuf + alen)
              {  /* LCOV_EXCL_START: already checked above */
                hns_free(rr_name);
                status = HNS_EBADRESP;
                break;
              }  /* LCOV_EXCL_STOP */
              memcpy(&at->ipaddr, aptr,  sizeof(struct in_addr));
              at->ttl = rr_ttl;
            }
          naddrs++;
          status = HNS_SUCCESS;
        }

      if (rr_class == C_IN && rr_type == T_CNAME)
        {
          /* Record the RR name as an alias. */
          if (aliases)
            aliases[naliases] = rr_name;
          else
            hns_free(rr_name);
          naliases++;

          /* Decode the RR data and replace the hostname with it. */
          status = hns__expand_name_for_response(aptr, abuf, alen, &rr_data,
                                                  &len);
          if (status != HNS_SUCCESS)
            break;
          hns_free(hostname);
          hostname = rr_data;

          /* Take the min of the TTLs we see in the CNAME chain. */
          if (cname_ttl > rr_ttl)
            cname_ttl = rr_ttl;
        }
      else
        hns_free(rr_name);

      aptr += rr_len;
      if (aptr > abuf + alen)
        {  /* LCOV_EXCL_START: already checked above */
          status = HNS_EBADRESP;
          break;
        }  /* LCOV_EXCL_STOP */
    }

  if (status == HNS_SUCCESS && naddrs == 0 && naliases == 0)
    /* the check for naliases to be zero is to make sure CNAME responses
       don't get caught here */
    status = HNS_ENODATA;
  if (status == HNS_SUCCESS)
    {
      /* We got our answer. */
      if (naddrttls)
        {
          const int n = naddrs < max_addr_ttls ? naddrs : max_addr_ttls;
          for (i = 0; i < n; i++)
            {
              /* Ensure that each A TTL is no larger than the CNAME TTL. */
              if (addrttls[i].ttl > cname_ttl)
                addrttls[i].ttl = cname_ttl;
            }
          *naddrttls = n;
        }
      if (aliases)
        aliases[naliases] = NULL;
      if (host)
        {
          /* Allocate memory to build the host entry. */
          hostent = hns_malloc(sizeof(struct hostent));
          if (hostent)
            {
              hostent->h_addr_list = hns_malloc((naddrs + 1) * sizeof(char *));
              if (hostent->h_addr_list)
                {
                  /* Fill in the hostent and return successfully. */
                  hostent->h_name = hostname;
                  hostent->h_aliases = aliases;
                  hostent->h_addrtype = AF_INET;
                  hostent->h_length = sizeof(struct in_addr);
                  for (i = 0; i < naddrs; i++)
                    hostent->h_addr_list[i] = (char *) &addrs[i];
                  hostent->h_addr_list[naddrs] = NULL;
                  if (!naddrs && addrs)
                    hns_free(addrs);
                  *host = hostent;
                  return HNS_SUCCESS;
                }
              hns_free(hostent);
            }
          status = HNS_ENOMEM;
        }
     }
  if (aliases)
    {
      for (i = 0; i < naliases; i++)
        hns_free(aliases[i]);
      hns_free(aliases);
    }
  hns_free(addrs);
  hns_free(hostname);
  return status;
}
