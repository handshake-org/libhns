
/* Copyright 1998 by the Massachusetts Institute of Technology.
 * Copyright (C) 2004-2011 by Daniel Stenberg
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

#include <assert.h>

#include "hns.h"
#include "hns_private.h"

void hns_destroy_options(struct hns_options *options)
{
  int i;

  if(options->servers)
    hns_free(options->servers);
  for (i = 0; i < options->ndomains; i++)
    hns_free(options->domains[i]);
  if(options->domains)
    hns_free(options->domains);
  if(options->sortlist)
    hns_free(options->sortlist);
  if(options->lookups)
    hns_free(options->lookups);
}

void hns_destroy(hns_channel channel)
{
  int i;
  struct query *query;
  struct list_node* list_head;
  struct list_node* list_node;
  
  if (!channel)
    return;

  list_head = &(channel->all_queries);
  for (list_node = list_head->next; list_node != list_head; )
    {
      query = list_node->data;
      list_node = list_node->next;  /* since we're deleting the query */
      query->callback(query->arg, HNS_EDESTRUCTION, 0, NULL, 0);
      hns__free_query(query);
    }
#ifndef NDEBUG
  /* Freeing the query should remove it from all the lists in which it sits,
   * so all query lists should be empty now.
   */
  assert(hns__is_list_empty(&(channel->all_queries)));
  for (i = 0; i < HNS_QID_TABLE_SIZE; i++)
    {
      assert(hns__is_list_empty(&(channel->queries_by_qid[i])));
    }
  for (i = 0; i < HNS_TIMEOUT_TABLE_SIZE; i++)
    {
      assert(hns__is_list_empty(&(channel->queries_by_timeout[i])));
    }
#endif

  hns__destroy_servers_state(channel);

  if (channel->domains) {
    for (i = 0; i < channel->ndomains; i++)
      hns_free(channel->domains[i]);
    hns_free(channel->domains);
  }

  if(channel->sortlist)
    hns_free(channel->sortlist);

  if (channel->lookups)
    hns_free(channel->lookups);

  hns_free(channel);
}

void hns__destroy_servers_state(hns_channel channel)
{
  struct server_state *server;
  int i;

  if (channel->servers)
    {
      for (i = 0; i < channel->nservers; i++)
        {
          server = &channel->servers[i];
          hns__close_sockets(channel, server);
          assert(hns__is_list_empty(&server->queries_to_server));
        }
      hns_free(channel->servers);
      channel->servers = NULL;
    }
  channel->nservers = -1;
}
