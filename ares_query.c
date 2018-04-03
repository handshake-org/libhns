
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
#ifdef HAVE_ARPA_NAMESER_H
#  include <arpa/nameser.h>
#else
#  include "nameser.h"
#endif
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#  include <arpa/nameser_compat.h>
#endif

#include "hns.h"
#include "hns_dns.h"
#include "hns_private.h"

struct qquery {
  hns_callback callback;
  void *arg;
};

static void qcallback(void *arg, int status, int timeouts, unsigned char *abuf, int alen);

static void rc4(rc4_key* key, unsigned char *buffer_ptr, int buffer_len)
{
  unsigned char x;
  unsigned char y;
  unsigned char* state;
  unsigned char xorIndex;
  short counter;

  x = key->x;
  y = key->y;

  state = &key->state[0];
  for(counter = 0; counter < buffer_len; counter ++)
  {
    x = (unsigned char)((x + 1) % 256);
    y = (unsigned char)((state[x] + y) % 256);
    HNS_SWAP_BYTE(&state[x], &state[y]);

    xorIndex = (unsigned char)((state[x] + state[y]) % 256);

    buffer_ptr[counter] = (unsigned char)(buffer_ptr[counter]^state[xorIndex]);
  }
  key->x = x;
  key->y = y;
}

static struct query* find_query_by_id(hns_channel channel, unsigned short id)
{
  unsigned short qid;
  struct list_node* list_head;
  struct list_node* list_node;
  DNS_HEADER_SET_QID(((unsigned char*)&qid), id);

  /* Find the query corresponding to this packet. */
  list_head = &(channel->queries_by_qid[qid % HNS_QID_TABLE_SIZE]);
  for (list_node = list_head->next; list_node != list_head;
       list_node = list_node->next)
    {
       struct query *q = list_node->data;
       if (q->qid == qid)
	  return q;
    }
  return NULL;
}


/* a unique query id is generated using an rc4 key. Since the id may already
   be used by a running query (as infrequent as it may be), a lookup is
   performed per id generation. In practice this search should happen only
   once per newly generated id
*/
static unsigned short generate_unique_id(hns_channel channel)
{
  unsigned short id;

  do {
    id = hns__generate_new_id(&channel->id_key);
  } while (find_query_by_id(channel, id));

  return (unsigned short)id;
}

unsigned short hns__generate_new_id(rc4_key* key)
{
  unsigned short r=0;
  rc4(key, (unsigned char *)&r, sizeof(r));
  return r;
}

void hns_query(hns_channel channel, const char *name, int dnsclass,
                int type, hns_callback callback, void *arg)
{
  struct qquery *qquery;
  unsigned char *qbuf;
  int qlen, rd, status;

  /* Compose the query. */
  rd = !(channel->flags & HNS_FLAG_NORECURSE);
  status = hns_create_query(name, dnsclass, type, channel->next_id, rd, &qbuf,
              &qlen, (channel->flags & HNS_FLAG_EDNS) ? channel->ednspsz : 0);
  if (status != HNS_SUCCESS)
    {
      if (qbuf != NULL) hns_free(qbuf);
      callback(arg, status, 0, NULL, 0);
      return;
    }

  channel->next_id = generate_unique_id(channel);

  /* Allocate and fill in the query structure. */
  qquery = hns_malloc(sizeof(struct qquery));
  if (!qquery)
    {
      hns_free_string(qbuf);
      callback(arg, HNS_ENOMEM, 0, NULL, 0);
      return;
    }
  qquery->callback = callback;
  qquery->arg = arg;

  /* Send it off.  qcallback will be called when we get an answer. */
  hns_send(channel, qbuf, qlen, qcallback, qquery);
  hns_free_string(qbuf);
}

static void qcallback(void *arg, int status, int timeouts, unsigned char *abuf, int alen)
{
  struct qquery *qquery = (struct qquery *) arg;
  unsigned int ancount;
  int rcode;

  if (status != HNS_SUCCESS)
    qquery->callback(qquery->arg, status, timeouts, abuf, alen);
  else
    {
      /* Pull the response code and answer count from the packet. */
      rcode = DNS_HEADER_RCODE(abuf);
      ancount = DNS_HEADER_ANCOUNT(abuf);

      /* Convert errors. */
      switch (rcode)
        {
        case NOERROR:
          status = (ancount > 0) ? HNS_SUCCESS : HNS_ENODATA;
          break;
        case FORMERR:
          status = HNS_EFORMERR;
          break;
        case SERVFAIL:
          status = HNS_ESERVFAIL;
          break;
        case NXDOMAIN:
          status = HNS_ENOTFOUND;
          break;
        case NOTIMP:
          status = HNS_ENOTIMP;
          break;
        case REFUSED:
          status = HNS_EREFUSED;
          break;
        }
      qquery->callback(qquery->arg, status, timeouts, abuf, alen);
    }
  hns_free(qquery);
}
