
/* Copyright 1998, 2011 by the Massachusetts Institute of Technology.
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

#include "hns.h"
#include "hns_inet_net_pton.h"
#include "hns_nowarn.h"
#include "hns_private.h"
#include "hns_addr.h"

int hns__get_hostent(FILE *fp, int family, struct hostent **host)
{
  char *line = NULL, *p, *q, **alias;
  char *txtaddr, *txthost, *txtalias;
  int status;
  size_t addrlen, linesize, naliases;
  struct hns_addr addr;
  struct hostent *hostent = NULL;

  hns_addr_init(&addr);

  *host = NULL; /* Assume failure */

  /* Validate family */
  switch (family) {
    case AF_INET:
    case AF_INET6:
    case AF_UNSPEC:
      break;
    default:
      return HNS_EBADFAMILY;
  }

  while ((status = hns__read_line(fp, &line, &linesize)) == HNS_SUCCESS)
    {

      /* Trim line comment. */
      p = line;
      while (*p && (*p != '#'))
        p++;
      *p = '\0';

      /* Trim trailing whitespace. */
      q = p - 1;
      while ((q >= line) && ISSPACE(*q))
        q--;
      *++q = '\0';

      /* Skip leading whitespace. */
      p = line;
      while (*p && ISSPACE(*p))
        p++;
      if (!*p)
        /* Ignore line if empty. */
        continue;

      /* Pointer to start of IPv4 or IPv6 address part. */
      txtaddr = p;

      /* Advance past address part. */
      while (*p && !ISSPACE(*p))
        p++;
      if (!*p)
        /* Ignore line if reached end of line. */
        continue;

      /* Null terminate address part. */
      *p = '\0';

      /* Advance to host name */
      p++;
      while (*p && ISSPACE(*p))
        p++;
      if (!*p)
        /* Ignore line if reached end of line. */
        continue;  /* LCOV_EXCL_LINE: trailing whitespace already stripped */

      /* Pointer to start of host name. */
      txthost = p;

      /* Advance past host name. */
      while (*p && !ISSPACE(*p))
        p++;

      /* Pointer to start of first alias. */
      txtalias = NULL;
      if (*p)
        {
          q = p + 1;
          while (*q && ISSPACE(*q))
            q++;
          if (*q)
            txtalias = q;
        }

      /* Null terminate host name. */
      *p = '\0';

      /* find out number of aliases. */
      naliases = 0;
      if (txtalias)
        {
          p = txtalias;
          while (*p)
            {
              while (*p && !ISSPACE(*p))
                p++;
              while (*p && ISSPACE(*p))
                p++;
              naliases++;
            }
        }

      /* Convert address string to network address for the requested family. */
      addrlen = 0;
      addr.family = AF_UNSPEC;
      addr.addrV4.s_addr = INADDR_NONE;
      if ((family == AF_INET) || (family == AF_UNSPEC))
        {
          addr.addrV4.s_addr = inet_addr(txtaddr);
          if (addr.addrV4.s_addr != INADDR_NONE)
            {
              /* Actual network address family and length. */
              addr.family = AF_INET;
              addrlen = sizeof(addr.addrV4);
            }
        }
      if ((family == AF_INET6) || ((family == AF_UNSPEC) && (!addrlen)))
        {
          if (hns_inet_pton(AF_INET6, txtaddr, &addr.addrV6) > 0)
            {
              /* Actual network address family and length. */
              addr.family = AF_INET6;
              addrlen = sizeof(addr.addrV6);
            }
        }
      if (!addrlen)
        /* Ignore line if invalid address string for the requested family. */
        continue;

      /*
      ** Actual address family possible values are AF_INET and AF_INET6 only.
      */

      /* Allocate memory for the hostent structure. */
      hostent = hns_malloc(sizeof(struct hostent));
      if (!hostent)
        break;

      /* Initialize fields for out of memory condition. */
      hostent->h_aliases = NULL;
      hostent->h_addr_list = NULL;

      /* Copy official host name. */
      hostent->h_name = hns_strdup(txthost);
      if (!hostent->h_name)
        break;

      /* Copy network address. */
      hostent->h_addr_list = hns_malloc(2 * sizeof(char *));
      if (!hostent->h_addr_list)
        break;
      hostent->h_addr_list[1] = NULL;
      hostent->h_addr_list[0] = hns_malloc(addrlen);
      if (!hostent->h_addr_list[0])
        break;
      if (addr.family == AF_INET)
        memcpy(hostent->h_addr_list[0], &addr.addrV4, sizeof(addr.addrV4));
      else
        memcpy(hostent->h_addr_list[0], &addr.addrV6, sizeof(addr.addrV6));

      /* Copy aliases. */
      hostent->h_aliases = hns_malloc((naliases + 1) * sizeof(char *));
      if (!hostent->h_aliases)
        break;
      alias = hostent->h_aliases;
      while (naliases)
        *(alias + naliases--) = NULL;
      *alias = NULL;
      while (txtalias)
        {
          p = txtalias;
          while (*p && !ISSPACE(*p))
            p++;
          q = p;
          while (*q && ISSPACE(*q))
            q++;
          *p = '\0';
          if ((*alias = hns_strdup(txtalias)) == NULL)
            break;
          alias++;
          txtalias = *q ? q : NULL;
        }
      if (txtalias)
        /* Alias memory allocation failure. */
        break;

      /* Copy actual network address family and length. */
      hostent->h_addrtype = hnsx_sitoss(addr.family);
      hostent->h_length = hnsx_uztoss(addrlen);

      /* Free line buffer. */
      hns_free(line);

      /* Return hostent successfully */
      *host = hostent;
      return HNS_SUCCESS;

    }

  /* If allocated, free line buffer. */
  if (line)
    hns_free(line);

  if (status == HNS_SUCCESS)
    {
      /* Memory allocation failure; clean up. */
      if (hostent)
        {
          if (hostent->h_name)
            hns_free((char *) hostent->h_name);
          if (hostent->h_aliases)
            {
              for (alias = hostent->h_aliases; *alias; alias++)
                hns_free(*alias);
              hns_free(hostent->h_aliases);
            }
          if (hostent->h_addr_list)
            {
              if (hostent->h_addr_list[0])
                hns_free(hostent->h_addr_list[0]);
              hns_free(hostent->h_addr_list);
            }
          hns_free(hostent);
        }
      return HNS_ENOMEM;
    }

  return status;
}
