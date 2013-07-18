/* net.c -- CoAP network interface
 *
 * Copyright (C) 2010--2012 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */

#include "config.h"

#include <ctype.h>
#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#elif HAVE_SYS_UNISTD_H
#include <sys/unistd.h>
#endif
#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "debug.h"
#include "mem.h"
#include "str.h"
#include "async.h"
#include "resource.h"
#include "option.h"
#include "encode.h"
#include "net.h"

#ifndef WITH_CONTIKI

time_t clock_offset;

static inline coap_queue_t *
coap_malloc_node() {
  return (coap_queue_t *)coap_malloc(sizeof(coap_queue_t));
}

static inline void
coap_free_node(coap_queue_t *node) {
  coap_free(node);
}
#else /* WITH_CONTIKI */
# ifndef DEBUG
#  define DEBUG DEBUG_PRINT
# endif /* DEBUG */

#include "memb.h"
#include "net/uip-debug.h"

clock_time_t clock_offset;

#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_UDP_BUF  ((struct uip_udp_hdr *)&uip_buf[UIP_LLIPH_LEN])

void coap_resources_init();
void coap_pdu_resources_init();

unsigned char initialized = 0;
coap_context_t the_coap_context;

MEMB(node_storage, coap_queue_t, COAP_PDU_MAXCNT);

PROCESS(coap_retransmit_process, "message retransmit process");

static inline coap_queue_t *
coap_malloc_node() {
  return (coap_queue_t *)memb_alloc(&node_storage);
}

static inline void
coap_free_node(coap_queue_t *node) {
  memb_free(&node_storage, node);
}
#endif /* WITH_CONTIKI */

int print_wellknown(coap_context_t *, unsigned char *, size_t *, coap_opt_t *);

void coap_handle_failed_notify(coap_context_t *, const coap_address_t *, 
			       const str *);

int
coap_insert_node(coap_queue_t **queue, coap_queue_t *node,
		 int (*order)(coap_queue_t *, coap_queue_t *node) ) {
  coap_queue_t *p, *q;
  if ( !queue || !node )
    return 0;

  /* set queue head if empty */
  if ( !*queue ) {
    *queue = node;
    return 1;
  }

  /* replace queue head if PDU's time is less than head's time */
  q = *queue;
  if ( order( node, q ) < 0) {
    node->next = q;
    *queue = node;
    return 1;
  }

  /* search for right place to insert */
  do {
    p = q;
    q = q->next;
  } while ( q && order( node, q ) >= 0 );

  /* insert new item */
  node->next = q;
  p->next = node;
  return 1;
}

int
coap_delete_node(coap_queue_t *node) {
  if ( !node )
    return 0;

  coap_delete_pdu(node->pdu);
  coap_free_node(node);

  return 1;
}

void
coap_delete_all(coap_queue_t *queue) {
  if ( !queue )
    return;

  coap_delete_all( queue->next );
  coap_delete_node( queue );
}

coap_queue_t *
coap_new_node() {
  coap_queue_t *node;
  node = coap_malloc_node();

  if ( ! node ) {
#ifndef NDEBUG
    coap_log(LOG_WARN, "coap_new_node: malloc");
#endif
    return NULL;
  }

  memset(node, 0, sizeof(*node));
  return node;
}

coap_queue_t *
coap_peek_next( coap_context_t *context ) {
  if ( !context || !context->sendqueue )
    return NULL;

  return context->sendqueue;
}

coap_queue_t *
coap_pop_next( coap_context_t *context ) {
  coap_queue_t *next;

  if ( !context || !context->sendqueue )
    return NULL;

  next = context->sendqueue;
  context->sendqueue = context->sendqueue->next;
  next->next = NULL;
  return next;
}

#ifdef COAP_DEFAULT_WKC_HASHKEY
/** Checks if @p Key is equal to the pre-defined hash key for.well-known/core. */
#define is_wkc(Key)							\
  (memcmp((Key), COAP_DEFAULT_WKC_HASHKEY, sizeof(coap_key_t)) == 0)
#else
/* Implements a singleton to store a hash key for the .wellknown/core
 * resources. */
int
is_wkc(coap_key_t k) {
  static coap_key_t wkc;
  static unsigned char _initialized = 0;
  if (!_initialized) {
    _initialized = coap_hash_path((unsigned char *)COAP_DEFAULT_URI_WELLKNOWN, 
				 sizeof(COAP_DEFAULT_URI_WELLKNOWN) - 1, wkc);
  }
  return memcmp(k, wkc, sizeof(coap_key_t)) == 0;
}
#endif

coap_context_t *
coap_new_context() {
#ifndef WITH_CONTIKI
  coap_context_t *c = coap_malloc( sizeof( coap_context_t ) );
#else /* WITH_CONTIKI */
  coap_context_t *c;

  if (initialized)
    return NULL;
#endif /* WITH_CONTIKI */

  coap_clock_init();
  prng_init((unsigned long)&c ^ clock_offset);

#ifndef WITH_CONTIKI
  if (!c) {
    coap_log(LOG_EMERG, "coap_init: malloc:");
    return NULL;
  }
#else /* WITH_CONTIKI */
  coap_resources_init();
  coap_pdu_resources_init();

  c = &the_coap_context;
  initialized = 1;
#endif /* WITH_CONTIKI */

  memset(c, 0, sizeof( coap_context_t ) );

  /* initialize message id */
  prng((unsigned char *)&c->message_id, sizeof(unsigned short));

  /* register the critical options that we know */
  coap_register_option(c, COAP_OPTION_IF_MATCH);
  coap_register_option(c, COAP_OPTION_URI_HOST);
  coap_register_option(c, COAP_OPTION_IF_NONE_MATCH);
  coap_register_option(c, COAP_OPTION_URI_PORT);
  coap_register_option(c, COAP_OPTION_URI_PATH);
  coap_register_option(c, COAP_OPTION_URI_QUERY);
  coap_register_option(c, COAP_OPTION_PROXY_URI);
  coap_register_option(c, COAP_OPTION_PROXY_SCHEME);

  /* set default callback function for sending data over the network */
  coap_set_cb(c, coap_network_send, write);

#ifdef WITH_CONTIKI  
  process_start(&coap_retransmit_process, (char *)c);

  PROCESS_CONTEXT_BEGIN(&coap_retransmit_process);
#ifndef WITHOUT_OBSERVE
  etimer_set(&c->notify_timer, COAP_RESOURCE_CHECK_TIME * COAP_TICKS_PER_SECOND);
#endif /* WITHOUT_OBSERVE */
  /* the retransmit timer must be initialized to some large value */
  etimer_set(&the_coap_context.retransmit_timer, 0xFFFF);
  PROCESS_CONTEXT_END(&coap_retransmit_process);
#endif /* WITH_CONTIKI */

  return c;
}

void
coap_free_context(coap_context_t *context) {
#ifndef WITH_CONTIKI
  coap_resource_t *res, *rtmp;
#endif /* WITH_CONTIKI */

  if (!context)
    return;

  /* FIXME: free endpoints */

  coap_delete_all(context->recvqueue);
  coap_delete_all(context->sendqueue);

#ifndef WITH_CONTIKI
  HASH_ITER(hh, context->resources, res, rtmp) {
    coap_delete_resource(context, res->key);
  }

  /* coap_delete_list(context->subscriptions); */
  coap_free(context);
#else /* WITH_CONTIKI */
  memset(&the_coap_context, 0, sizeof(coap_context_t));
  initialized = 0;
#endif /* WITH_CONTIKI */
}

int
coap_option_check_critical(coap_context_t *ctx, 
			   coap_pdu_t *pdu,
			   coap_opt_filter_t unknown) {

  coap_opt_iterator_t opt_iter;
  int ok = 1;
  
  coap_option_iterator_init(pdu, &opt_iter, COAP_OPT_ALL);

  while (coap_option_next(&opt_iter)) {

    /* The following condition makes use of the fact that
     * coap_option_getb() returns -1 if type exceeds the bit-vector
     * filter. As the vector is supposed to be large enough to hold
     * the largest known option, we know that everything beyond is
     * bad.
     */
    if (opt_iter.type & 0x01 && 
	coap_option_getb(ctx->known_options, opt_iter.type) < 1) {
      debug("unknown critical option %d\n", opt_iter.type);
      
      ok = 0;

      /* When opt_iter.type is beyond our known option range,
       * coap_option_setb() will return -1 and we are safe to leave
       * this loop. */
      if (coap_option_setb(unknown, opt_iter.type) == -1)
	break;
    }
  }

  return ok;
}

void
coap_transaction_id(const coap_address_t *peer, const coap_pdu_t *pdu, 
		    coap_tid_t *id) {
  coap_key_t h;

  memset(h, 0, sizeof(coap_key_t));

  /* Compare the complete address structure in case of IPv4. For IPv6,
   * we need to look at the transport address only. */

#ifndef WITH_CONTIKI
  switch (peer->addr.sa.sa_family) {
  case AF_INET:
    coap_hash((const unsigned char *)&peer->addr.sa, peer->size, h);
    break;
  case AF_INET6:
    coap_hash((const unsigned char *)&peer->addr.sin6.sin6_port,
	      sizeof(peer->addr.sin6.sin6_port), h);
    coap_hash((const unsigned char *)&peer->addr.sin6.sin6_addr,
	      sizeof(peer->addr.sin6.sin6_addr), h);
    break;
  default:
    return;
  }
#else /* WITH_CONTIKI */
    coap_hash((const unsigned char *)&peer->port, sizeof(peer->port), h);
    coap_hash((const unsigned char *)&peer->addr, sizeof(peer->addr), h);  
#endif /* WITH_CONTIKI */

  coap_hash((const unsigned char *)&pdu->hdr->id, sizeof(unsigned short), h);

  *id = ((h[0] << 8) | h[1]) ^ ((h[2] << 8) | h[3]);
}

coap_tid_t
coap_send_ack(coap_context_t *context, 
	      const coap_endpoint_t *local_interface,
	      const coap_address_t *dst,
	      coap_pdu_t *request) {
  coap_pdu_t *response;
  coap_tid_t result = COAP_INVALID_TID;
  
  if (request && request->hdr->type == COAP_MESSAGE_CON) {
    response = coap_pdu_init(COAP_MESSAGE_ACK, 0, request->hdr->id, 
			     sizeof(coap_pdu_t)); 
    if (response) {
      result = coap_send(context, local_interface, dst, response);
      coap_delete_pdu(response);
    }
  }
  return result;
}

/* releases space allocated by PDU if free_pdu is set */
coap_tid_t
coap_send_impl(coap_context_t *context, 
	       const coap_endpoint_t *local_interface,
	       const coap_address_t *dst,
	       coap_pdu_t *pdu) {
  ssize_t bytes_written = -1;
  coap_tid_t id = COAP_INVALID_TID;


  if (!context || !dst || !pdu || !context->cb_write)
    return id;

  bytes_written = context->cb_write(local_interface, dst,
				    (unsigned char *)pdu->hdr, pdu->length);

  if (bytes_written >= 0) {
    coap_transaction_id(dst, pdu, &id);
  } else {
    coap_log(LOG_CRIT, "coap_send: sendto\n");
  }

  return id;
}

coap_tid_t 
coap_send(coap_context_t *context, 
	  const coap_endpoint_t *local_interface,
	  const coap_address_t *dst,
	  coap_pdu_t *pdu) {
  return coap_send_impl(context, local_interface, dst, pdu);
}

coap_tid_t
coap_send_error(coap_context_t *context, 
		coap_pdu_t *request,
		const coap_endpoint_t *local_interface,
		const coap_address_t *dst,
		unsigned char code,
		coap_opt_filter_t opts) {
  coap_pdu_t *response;
  coap_tid_t result = COAP_INVALID_TID;

  assert(request);
  assert(dst);

  response = coap_new_error_response(request, code, opts);
  if (response) {
    result = coap_send(context, local_interface, dst, response);
    coap_delete_pdu(response);
  }
  
  return result;
}

coap_tid_t
coap_send_message_type(coap_context_t *context, 
		       const coap_endpoint_t *local_interface,
		       const coap_address_t *dst, 
		       coap_pdu_t *request,
		       unsigned char type) {
  coap_pdu_t *response;
  coap_tid_t result = COAP_INVALID_TID;

  if (request) {
    response = coap_pdu_init(type, 0, request->hdr->id, sizeof(coap_pdu_t)); 
    if (response) {
      result = coap_send(context, local_interface, dst, response);
      coap_delete_pdu(response);
    }
  }
  return result;
}

int
_order_timestamp( coap_queue_t *lhs, coap_queue_t *rhs ) {
  return lhs && rhs && ( lhs->t < rhs->t ) ? -1 : 1;
}

coap_tid_t
coap_send_confirmed(coap_context_t *context, 
		    const coap_endpoint_t *local_interface,
		    const coap_address_t *dst,
		    coap_pdu_t *pdu) {
  coap_queue_t *node;
  coap_tick_t now;
  int r;

  node = coap_new_node();
  if (!node) {
    debug("coap_send_confirmed: insufficient memory\n");
    return COAP_INVALID_TID;
  }

  node->id = coap_send_impl(context, local_interface, dst, pdu);
  if (COAP_INVALID_TID == node->id) {
    debug("coap_send_confirmed: error sending pdu\n");
    coap_free_node(node);
    return COAP_INVALID_TID;
  }
  
  prng((unsigned char *)&r,sizeof(r));
  coap_ticks(&now);
  node->t = now;

  /* add randomized RESPONSE_TIMEOUT to determine retransmission timeout */
  node->timeout = COAP_DEFAULT_RESPONSE_TIMEOUT * COAP_TICKS_PER_SECOND +
    (COAP_DEFAULT_RESPONSE_TIMEOUT >> 1) *
    ((COAP_TICKS_PER_SECOND * (r & 0xFF)) >> 8);
  node->t += node->timeout;

  node->local_if = (coap_endpoint_t *)local_interface;
  memcpy(&node->remote, dst, sizeof(coap_address_t));
  node->pdu = pdu;

  assert(&context->sendqueue);
  coap_insert_node(&context->sendqueue, node, _order_timestamp);

#ifdef WITH_CONTIKI
  {			    /* (re-)initialize retransmission timer */
    coap_queue_t *nextpdu;

    nextpdu = coap_peek_next(context);
    assert(nextpdu);		/* we have just inserted a node */

    /* must set timer within the context of the retransmit process */
    PROCESS_CONTEXT_BEGIN(&coap_retransmit_process);
    etimer_set(&context->retransmit_timer, 
	       now < nextpdu->t ? nextpdu->t - now : 0);
    PROCESS_CONTEXT_END(&coap_retransmit_process);
  }
#endif /* WITH_CONTIKI */

  return node->id;
}

coap_tid_t
coap_retransmit(coap_context_t *context, coap_queue_t *node) {
  if (!context || !node)
    return COAP_INVALID_TID;

  /* re-initialize timeout when maximum number of retransmissions are not reached yet */
  if (node->retransmit_cnt < COAP_DEFAULT_MAX_RETRANSMIT) {
    node->retransmit_cnt++;
    node->t += (node->timeout << node->retransmit_cnt);
    coap_insert_node(&context->sendqueue, node, _order_timestamp);

#ifndef WITH_CONTIKI
    debug("** retransmission #%d of transaction %d\n",
	  node->retransmit_cnt, ntohs(node->pdu->hdr->id));
#else /* WITH_CONTIKI */
    debug("** retransmission #%u of transaction %u\n",
	  node->retransmit_cnt, uip_ntohs(node->pdu->hdr->id));
#endif /* WITH_CONTIKI */

    node->id = coap_send_impl(context, node->local_if, 
			      &node->remote, node->pdu);
    return node->id;
  }

  /* no more retransmissions, remove node from system */

  debug("** removed transaction %d\n", node->id);

#ifndef WITHOUT_OBSERVE
  /* Check if subscriptions exist that should be canceled after
     COAP_MAX_NOTIFY_FAILURES */
  if (node->pdu->hdr->code >= 64) {
    str token = { 0, NULL };

    token.length = node->pdu->hdr->token_length;
    token.s = node->pdu->hdr->token;

    coap_handle_failed_notify(context, &node->remote, &token);
  }
#endif /* WITHOUT_OBSERVE */

  /* And finally delete the node */
  coap_delete_node( node );
  return COAP_INVALID_TID;
}

int
_order_transaction_id( coap_queue_t *lhs, coap_queue_t *rhs ) {
  return ( lhs && rhs && lhs->pdu && rhs->pdu &&
	   ( lhs->id < rhs->id ) )
    ? -1
    : 1;
}

/** 
 * Checks if @p opt fits into the message that ends with @p maxpos.
 * This function returns @c 1 on success, or @c 0 if the option @p opt
 * would exceed @p maxpos.
 */
static inline int
check_opt_size(coap_opt_t *opt, unsigned char *maxpos) {
  if (opt && opt < maxpos) {
    if (((*opt & 0x0f) < 0x0f) || (opt + 1 < maxpos))
      return opt + COAP_OPT_SIZE(opt) < maxpos;
  }
  return 0;
}

void coap_dispatch(coap_context_t *context, coap_queue_t *rcvd);

int
coap_handle_message(coap_context_t *ctx,
		    const coap_endpoint_t *local_interface,
		    const coap_address_t *remote, 
		    unsigned char *msg, size_t msg_len) {
  coap_queue_t *node;

  if (msg_len < sizeof(coap_hdr_t) ) {
    debug("coap_handle_message: discarded invalid frame\n" );
    return -1;
  }

  if (msg_len < sizeof(coap_hdr_t) ) {
    debug("coap_handle_message: discarded invalid frame\n");
    return -1;
  }

  /* check version identifier */
  if (((*msg >> 6) & 0x03) != COAP_DEFAULT_VERSION) {
    debug("coap_read: unknown protocol version %d\n", (*msg >> 6) & 0x03);
    return -1;
  }

  node = coap_new_node();
  if (!node)
    return -1;

  node->pdu = coap_pdu_init(0, 0, 0, msg_len);
  if (!node->pdu)
    goto error;

  coap_ticks(&node->t);
  node->local_if = (coap_endpoint_t *)local_interface;
  memcpy(&node->remote, remote, sizeof(coap_address_t));

if (!coap_pdu_parse(msg, msg_len, node->pdu)) {
    warn("discard malformed PDU");
    goto error;
  }

  /* and add new node to receive queue */
  coap_transaction_id(&node->remote, node->pdu, &node->id);
  /* coap_insert_node(&ctx->recvqueue, node, _order_timestamp); */

#ifndef NDEBUG
  if (LOG_DEBUG <= coap_get_log_level()) {
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 40
#endif
    unsigned char addr[INET6_ADDRSTRLEN+8];

    if (coap_print_addr(remote, addr, INET6_ADDRSTRLEN+8))
      debug("** received %d bytes from %s:\n", (int)msg_len, addr);

    coap_show_pdu(node->pdu);
  }
#endif

  coap_dispatch(ctx, node);
  return 0;
 error:
  /* FIXME: send back RST? */
  coap_delete_node(node);
  return -1;
}

int
coap_remove_from_queue(coap_queue_t **queue, coap_tid_t id, coap_queue_t **node) {
  coap_queue_t *p, *q;

  if ( !queue || !*queue)
    return 0;

  /* replace queue head if PDU's time is less than head's time */

  if ( id == (*queue)->id ) { /* found transaction */
    *node = *queue;
    *queue = (*queue)->next;
    (*node)->next = NULL;
    /* coap_delete_node( q ); */
    debug("*** removed transaction %u\n", id);
    return 1;
  }

  /* search transaction to remove (only first occurence will be removed) */
  q = *queue;
  do {
    p = q;
    q = q->next;
  } while ( q && id != q->id );

  if ( q ) {			/* found transaction */
    p->next = q->next;
    q->next = NULL;
    *node = q;
    /* coap_delete_node( q ); */
    debug("*** removed transaction %u\n", id);
    return 1;
  }

  return 0;

}

coap_queue_t *
coap_find_transaction(coap_queue_t *queue, coap_tid_t id) {
  while (queue && queue->id != id)
    queue = queue->next;

  return queue;
}

coap_pdu_t *
coap_new_error_response(coap_pdu_t *request, unsigned char code, 
			coap_opt_filter_t opts) {
  coap_opt_iterator_t opt_iter;
  coap_pdu_t *response;
  size_t size = sizeof(coap_hdr_t) + request->hdr->token_length;
  int type; 
  coap_opt_t *option;

#if COAP_ERROR_PHRASE_LENGTH > 0
  char *phrase = coap_response_phrase(code);

  /* Need some more space for the error phrase and payload start marker */
  if (phrase)
    size += strlen(phrase) + 1;
#endif

  assert(request);

  /* cannot send ACK if original request was not confirmable */
  type = request->hdr->type == COAP_MESSAGE_CON 
    ? COAP_MESSAGE_ACK
    : COAP_MESSAGE_NON;

  /* Estimate how much space we need for options to copy from
   * request. We always need the Token, for 4.02 the unknown critical
   * options must be included as well. */
  coap_option_clrb(opts, COAP_OPTION_CONTENT_TYPE); /* we do not want this */

  coap_option_iterator_init(request, &opt_iter, opts);

  while((option = coap_option_next(&opt_iter)))
    size += COAP_OPT_SIZE(option);

  /* Now create the response and fill with options and payload data. */
  response = coap_pdu_init(type, code, request->hdr->id, size);
  if (response) {
    /* copy token */
    if (!coap_add_token(response, request->hdr->token_length, 
			request->hdr->token)) {
      debug("cannot add token to error response\n");
      coap_delete_pdu(response);
      return NULL;
    }

    /* copy all options */
    coap_option_iterator_init(request, &opt_iter, opts);
    while((option = coap_option_next(&opt_iter)))
      coap_add_option(response, opt_iter.type, 
		      COAP_OPT_LENGTH(option),
		      COAP_OPT_VALUE(option));

#if COAP_ERROR_PHRASE_LENGTH > 0
    /* note that diagnostic messages do not need a Content-Format option. */
    if (phrase)
      coap_add_data(response, strlen(phrase), (unsigned char *)phrase);
#endif
  }

  return response;
}

coap_pdu_t *
wellknown_response(coap_context_t *context, coap_pdu_t *request) {
  coap_pdu_t *resp;
  coap_opt_iterator_t opt_iter;
  size_t len;
  unsigned char buf[2];

  resp = coap_pdu_init(request->hdr->type == COAP_MESSAGE_CON 
		       ? COAP_MESSAGE_ACK 
		       : COAP_MESSAGE_NON,
		       COAP_RESPONSE_CODE(205),
		       request->hdr->id, COAP_MAX_PDU_SIZE);
  if (!resp) {
    debug("wellknown_response: cannot create PDU\n");
    return NULL;
  }
  
  if (!coap_add_token(resp, request->hdr->token_length, request->hdr->token)) {
    debug("wellknown_response: cannot add token\n");
    goto error;
  }

  /* Check if there is sufficient space to add Content-Format option 
   * and data. We do this before adding the Content-Format option to
   * avoid sending error responses with that option but no actual
   * content. */
  if (resp->max_size <= (size_t)resp->length + 3) {
    debug("wellknown_response: insufficient storage space\n");
    goto error;
  }

  /* Add Content-Format. As we have checked for available storage,
   * nothing should go wrong here. */
  assert(coap_encode_var_bytes(buf, 
		    COAP_MEDIATYPE_APPLICATION_LINK_FORMAT) == 1);
  coap_add_option(resp, COAP_OPTION_CONTENT_FORMAT,
		  coap_encode_var_bytes(buf, 
			COAP_MEDIATYPE_APPLICATION_LINK_FORMAT), buf);

  /* Manually set payload of response to let print_wellknown() write,
   * into our buffer without copying data. */

  resp->data = (unsigned char *)resp->hdr + resp->length;
  *resp->data = COAP_PAYLOAD_START;
  resp->data++;
  resp->length++;
  len = resp->max_size - resp->length;

  if (!print_wellknown(context, resp->data, &len,
	       coap_check_option(request, COAP_OPTION_URI_QUERY, &opt_iter))) {
    debug("print_wellknown failed\n");
    goto error;
  } 
  
  resp->length += len;
  return resp;

 error:
  /* set error code 5.03 and remove all options and data from response */
  resp->hdr->code = COAP_RESPONSE_CODE(503);
  resp->length = sizeof(coap_hdr_t) + resp->hdr->token_length;
  return resp;
}

#define WANT_WKC(Pdu,Key)					\
  (((Pdu)->hdr->code == COAP_REQUEST_GET) && is_wkc(Key))

void
handle_request(coap_context_t *context, coap_queue_t *node) {      
  coap_method_handler_t h = NULL;
  coap_pdu_t *response = NULL;
  coap_opt_filter_t opt_filter;
  coap_resource_t *resource;
  coap_key_t key;

  coap_option_filter_clear(opt_filter);
  
  /* try to find the resource from the request URI */
  coap_hash_request_uri(node->pdu, key);
  resource = coap_get_resource_from_key(context, key);
  
  if (!resource) {
    /* The resource was not found. Check if the request URI happens to
     * be the well-known URI. In that case, we generate a default
     * response, otherwise, we return 4.04 */

    switch(node->pdu->hdr->code) {

    case COAP_REQUEST_GET: 
      if (is_wkc(key)) {	/* GET request for .well-known/core */
	info("create default response for %s\n", COAP_DEFAULT_URI_WELLKNOWN);
	response = wellknown_response(context, node->pdu);

      } else { /* GET request for any another resource, return 4.04 */

	debug("GET for unknown resource 0x%02x%02x%02x%02x, return 4.04\n", 
	      key[0], key[1], key[2], key[3]);
	response = 
	  coap_new_error_response(node->pdu, COAP_RESPONSE_CODE(404), 
				  opt_filter);
      }
      break;

    default: 			/* any other request type */

      debug("unhandled request for unknown resource 0x%02x%02x%02x%02x\r\n",
	    key[0], key[1], key[2], key[3]);
      if (!coap_mcast_interface(node->local_if))
	response = coap_new_error_response(node->pdu, COAP_RESPONSE_CODE(405), 
					   opt_filter);
    }
      
    if (response && coap_send(context, node->local_if, &node->remote, response) 
	== COAP_INVALID_TID) {
      warn("cannot send response for transaction %u\n", node->id);
    }
    coap_delete_pdu(response);

    return;
  }
  
  /* the resource was found, check if there is a registered handler */
  if ((size_t)node->pdu->hdr->code - 1 <
      sizeof(resource->handler)/sizeof(coap_method_handler_t))
    h = resource->handler[node->pdu->hdr->code - 1];
  
  if (h) {
    debug("call custom handler for resource 0x%02x%02x%02x%02x\n", 
	  key[0], key[1], key[2], key[3]);
    response = coap_pdu_init(node->pdu->hdr->type == COAP_MESSAGE_CON 
			     ? COAP_MESSAGE_ACK
			     : COAP_MESSAGE_NON,
			     0, node->pdu->hdr->id, COAP_MAX_PDU_SIZE);
    
    /* Implementation detail: coap_add_token() immediately returns 0
       if response == NULL */
    if (coap_add_token(response, node->pdu->hdr->token_length,
		       node->pdu->hdr->token)) {
      str token = { node->pdu->hdr->token_length, node->pdu->hdr->token };

      h(context, resource, node->local_if, &node->remote, 
	node->pdu, &token, response);
      if (response->hdr->type != COAP_MESSAGE_NON ||
	  (response->hdr->code >= 64 
	   && !coap_mcast_interface(node->local_if))) {
	if (coap_send(context, node->local_if, &node->remote, response) 
	    == COAP_INVALID_TID) {
	  debug("cannot send response for message %d\n", node->pdu->hdr->id);
	  }
      }

      coap_delete_pdu(response);
    } else {
      warn("cannot generate response\r\n");
    }
  } else {
    if (WANT_WKC(node->pdu, key)) {
      debug("create default response for %s\n", COAP_DEFAULT_URI_WELLKNOWN);
      response = wellknown_response(context, node->pdu);
    } else
      response = coap_new_error_response(node->pdu, COAP_RESPONSE_CODE(405), 
					 opt_filter);
    
    if (!response || 
	(coap_send(context, node->local_if, &node->remote, response)
	 == COAP_INVALID_TID)) {
      debug("cannot send response for transaction %u\n", node->id);
    }
    coap_delete_pdu(response);
  }  
}

static inline void
handle_response(coap_context_t *context, 
		coap_queue_t *sent, coap_queue_t *rcvd) {
  
  /* Call application-specific reponse handler when available.  If
   * not, we must acknowledge confirmable messages. */
  if (context->response_handler) {
    context->response_handler(context, rcvd->local_if,
			      &rcvd->remote, sent ? sent->pdu : NULL, 
			      rcvd->pdu, rcvd->id);
  } else {
    /* send ACK if rcvd is confirmable (i.e. a separate response) */
    coap_send_ack(context, rcvd->local_if, &rcvd->remote, rcvd->pdu);
  }
}

static inline int
#ifdef __GNUC__
handle_locally(coap_context_t *context __attribute__ ((unused)), 
	       coap_queue_t *node __attribute__ ((unused))) {
#else /* not a GCC */
handle_locally(coap_context_t *context, coap_queue_t *node) {
#endif /* GCC */
  /* this function can be used to check if node->pdu is really for us */
  return 1;
}

void
coap_dispatch(coap_context_t *context, coap_queue_t *rcvd) {
  /* coap_queue_t *rcvd = NULL, *sent = NULL; */
  coap_queue_t *sent = NULL;
  coap_pdu_t *response;
  coap_opt_filter_t opt_filter;

  if (!context)
    return;

  memset(opt_filter, 0, sizeof(coap_opt_filter_t));

#if 0
  while ( context->recvqueue ) {
    rcvd = context->recvqueue;

    /* remove node from recvqueue */
    context->recvqueue = context->recvqueue->next;
    rcvd->next = NULL;
#endif
    if ( rcvd->pdu->hdr->version != COAP_DEFAULT_VERSION ) {
      debug("dropped packet with unknown version %u\n", rcvd->pdu->hdr->version);
      goto cleanup;
    }
    
    switch ( rcvd->pdu->hdr->type ) {
    case COAP_MESSAGE_ACK:
      /* find transaction in sendqueue to stop retransmission */
      coap_remove_from_queue(&context->sendqueue, rcvd->id, &sent);

      if (rcvd->pdu->hdr->code == 0)
	goto cleanup;

      /* FIXME: if sent code was >= 64 the message might have been a 
       * notification. Then, we must flag the observer to be alive
       * by setting obs->fail_cnt = 0. */
      break;

    case COAP_MESSAGE_RST :
      /* We have sent something the receiver disliked, so we remove
       * not only the transaction but also the subscriptions we might
       * have. */

#ifndef WITH_CONTIKI
      coap_log(LOG_ALERT, "got RST for message %u\n", ntohs(rcvd->pdu->hdr->id));
#else /* WITH_CONTIKI */
      coap_log(LOG_ALERT, "got RST for message %u\n", uip_ntohs(rcvd->pdu->hdr->id));
#endif /* WITH_CONTIKI */

      /* find transaction in sendqueue to stop retransmission */
      coap_remove_from_queue(&context->sendqueue, rcvd->id, &sent);

      /* @todo remove observer for this resource, if any 
       * get token from sent and try to find a matching resource. Uh!
       */
      break;

    case COAP_MESSAGE_NON :	/* check for unknown critical options */
      if (coap_option_check_critical(context, rcvd->pdu, opt_filter) == 0)
	goto cleanup;
      break;

    case COAP_MESSAGE_CON :	/* check for unknown critical options */
      if (coap_option_check_critical(context, rcvd->pdu, opt_filter) == 0) {

	/* FIXME: send response only if we have received a request. Otherwise, 
	 * send RST. */
	response = 
	  coap_new_error_response(rcvd->pdu, COAP_RESPONSE_CODE(402), opt_filter);

	if (!response)
	  warn("coap_dispatch: cannot create error reponse\n");
	else {
	  if (coap_send(context, rcvd->local_if, &rcvd->remote, response) 
	      == COAP_INVALID_TID) {
	    warn("coap_dispatch: error sending reponse\n");
	  }
          coap_delete_pdu(response);
	}	 
	
	goto cleanup;
      }
      break;
    }
   
    /* Pass message to upper layer if a specific handler was
     * registered for a request that should be handled locally. */
    if (handle_locally(context, rcvd)) {
      if (COAP_MESSAGE_IS_REQUEST(rcvd->pdu->hdr))
	handle_request(context, rcvd);
      else if (COAP_MESSAGE_IS_RESPONSE(rcvd->pdu->hdr))
	handle_response(context, sent, rcvd);
      else {
	debug("dropped message with invalid code\n");
	coap_send_message_type(context, rcvd->local_if, &rcvd->remote, 
			       rcvd->pdu, COAP_MESSAGE_RST);
      }
    }
    
  cleanup:
    coap_delete_node(sent);
    coap_delete_node(rcvd);
#if 0
  }
#endif
}

int
coap_can_exit( coap_context_t *context ) {
  return !context || (context->recvqueue == NULL && context->sendqueue == NULL);
}

#ifdef WITH_CONTIKI

/*---------------------------------------------------------------------------*/
/* CoAP message retransmission */
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(coap_retransmit_process, ev, data)
{
  coap_tick_t now;
  coap_queue_t *nextpdu;

  PROCESS_BEGIN();

  debug("Started retransmit process\r\n");

  while(1) {
    PROCESS_YIELD();
    if (ev == PROCESS_EVENT_TIMER) {
      if (etimer_expired(&the_coap_context.retransmit_timer)) {
	
	nextpdu = coap_peek_next(&the_coap_context);
	
	coap_ticks(&now);
	while (nextpdu && nextpdu->t <= now) {
	  coap_retransmit(&the_coap_context, coap_pop_next(&the_coap_context));
	  nextpdu = coap_peek_next(&the_coap_context);
	}

	/* need to set timer to some value even if no nextpdu is available */
	etimer_set(&the_coap_context.retransmit_timer, 
		   nextpdu ? nextpdu->t - now : 0xFFFF);
      } 
#ifndef WITHOUT_OBSERVE
      if (etimer_expired(&the_coap_context.notify_timer)) {
	coap_check_notify(&the_coap_context);
	etimer_reset(&the_coap_context.notify_timer);
      }
#endif /* WITHOUT_OBSERVE */
    }
  }
  
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/

#endif /* WITH_CONTIKI */
