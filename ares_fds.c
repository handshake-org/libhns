
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

#include "hns.h"
#include "hns_nowarn.h"
#include "hns_private.h"

int hns_fds(hns_channel channel, fd_set *read_fds, fd_set *write_fds)
{
  struct server_state *server;
  hns_socket_t nfds;
  int i;

  /* Are there any active queries? */
  int active_queries = !hns__is_list_empty(&(channel->all_queries));

  nfds = 0;
  for (i = 0; i < channel->nservers; i++)
    {
      server = &channel->servers[i];
      /* We only need to register interest in UDP sockets if we have
       * outstanding queries.
       */
      if (active_queries && server->udp_socket != HNS_SOCKET_BAD)
        {
          FD_SET(server->udp_socket, read_fds);
          if (server->udp_socket >= nfds)
            nfds = server->udp_socket + 1;
        }
      /* We always register for TCP events, because we want to know
       * when the other side closes the connection, so we don't waste
       * time trying to use a broken connection.
       */
      if (server->tcp_socket != HNS_SOCKET_BAD)
       {
         FD_SET(server->tcp_socket, read_fds);
         if (server->qhead)
           FD_SET(server->tcp_socket, write_fds);
         if (server->tcp_socket >= nfds)
           nfds = server->tcp_socket + 1;
	}
    }
  return (int)nfds;
}
