/* small.c -- bare CoAP server with optional DTLS support
 *
 * Copyright (C) 2013 Olaf Bergmann <bergmann@tzi.org>
 *
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * o Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * o Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE. 
 */

#include "config.h"

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "debug.h"
#include "coap.h"

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__ ((unused))
#define UNUSED_FUNC __attribute__ ((unused))
#else /* not a GCC */
#define UNUSED_PARAM
#define UNUSED_FUNC
#endif /* GCC */

#if HAVE_LIBTINYDTLS
#define HAVE_STR
#define WITH_SHA256
#include <tinydtls/dtls.h>
#endif

#if HAVE_LIBTINYDTLS
#define MY_COAP_PORT 5684
#else /* HAVE_LIBTINYDTLS */
#define MY_COAP_PORT COAP_DEFAULT_PORT
#endif /* HAVE_LIBTINYDTLS */

typedef struct small_context_t {
  coap_context_t *coap_context;
#if HAVE_LIBTINYDTLS
  dtls_context_t *dtls_context;
#endif
  LIST_STRUCT(endpoints);
} small_context_t;

struct list_ep_t {
  struct list_ep_t *next;
  coap_endpoint_t *ep;
};

small_context_t context;

int init_resource(coap_context_t *);
void run(small_context_t *);

#if HAVE_LIBTINYDTLS
/* This function is called from libcoap to send data on the given
 * local interface to the remote peer. */
ssize_t send_to_peer(struct coap_context_t *context,
		     const coap_endpoint_t *local_interface,
		     const coap_address_t *remote, 
		     unsigned char *data, size_t len);

int
dtls_application_data(struct dtls_context_t *ctx, 
		      session_t *session, uint8 *data, size_t len) {
  /* FIXME: set small_ctx from ctx->app_data */
  small_context_t *small_ctx = &context;

  struct list_ep_t *ep_item;
  coap_endpoint_t *local_interface = NULL;

  for (ep_item = list_head(small_ctx->endpoints); ep_item;
       ep_item = list_item_next(ep_item)) {
    if (session->ifindex == ep_item->ep->handle) {
      local_interface = ep_item->ep;
      break;
    }
  }

  if (!local_interface) {
    fprintf(stderr, "dtls_send_to_peer: cannot find local interface\n");
    return -3;
  }

  return coap_handle_message(small_ctx->coap_context,
  			     local_interface, 
			     (coap_address_t *)session,
  			     (unsigned char *)data, len);
}

int
dtls_send_to_peer(struct dtls_context_t *ctx, 
	     session_t *session, uint8 *data, size_t len) {
  /* FIXME: set small_ctx from ctx->app_data */
  small_context_t *small_ctx = &context;
  struct list_ep_t *ep_item;
  coap_endpoint_t *local_interface = NULL;

  for (ep_item = list_head(small_ctx->endpoints); ep_item;
       ep_item = list_item_next(ep_item)) {
    if (session->ifindex == ep_item->ep->handle) {
      local_interface = ep_item->ep;
      break;
    }
  }

  if (!local_interface) {
    fprintf(stderr, "dtls_send_to_peer: cannot find local interface\n");
    return -3;
  }

  /* get local interface from handle */
  return coap_network_send(dtls_get_app_data(ctx),
			   local_interface, (coap_address_t *)session, 
			   data, len);
}


/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identity within this particular
 * session. */
int
get_psk_info(struct dtls_context_t *dtls_context UNUSED_PARAM,
	     const session_t *session UNUSED_PARAM,
	     dtls_credentials_type_t type,
	     const unsigned char *id, size_t id_len,
	     unsigned char *result, size_t result_length) {

  static const unsigned char *psk_id = (unsigned char *)"Client_identity";
  static const size_t psk_id_length = sizeof(psk_id) - 1;

  static const unsigned char *psk = (unsigned char *)"secretPSK";
  static const size_t psk_length = sizeof(psk) - 1;

  switch(type) {
  case DTLS_PSK_IDENTITY: {
    if (result_length < psk_id_length) {
      coap_log(LOG_WARNING, "cannot set psk_identity -- buffer too small\n");
      return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
    } else {
      if (psk_id_length > 0) {
	memcpy(result, psk_id, psk_id_length);
      }
      return psk_id_length;
    }
    break;
  }

  case DTLS_PSK_KEY: {
    if (result_length < psk_length) {
      coap_log(LOG_WARNING, "cannot set psk -- buffer too small\n");
      return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
    } else {
      if (psk_length > 0) {
	memcpy(result, psk, psk_length);
      }
      return psk_length;
    }
    break;
  }
  default:   /* nothing to do here */
    ;
  }
  return 0;
}

static dtls_handler_t cb = {
  .write = dtls_send_to_peer,
  .read  = dtls_application_data,
  .event = NULL,
  .get_psk_info = get_psk_info,
#ifdef WITH_ECC
  .get_ecdsa_key = NULL,
  .verify_ecdsa_key = NULL
#endif
};

#endif

/*---------------------------------------------------------------------------*/
int
main(int argc, char **argv) {
  coap_set_log_level(LOG_DEBUG);

  LIST_STRUCT_INIT(&context, endpoints);

#if HAVE_LIBTINYDTLS
  context.dtls_context = dtls_new_context(&context);
  if (!context.dtls_context)
    exit(EXIT_FAILURE);			/* error */

  dtls_set_handler(context.dtls_context, &cb);
#endif

  /* first, we need a coap_context to work with */
  context.coap_context = coap_new_context();
  if (!context.coap_context)
    exit(EXIT_FAILURE);			/* error */

#if HAVE_LIBTINYDTLS
  /* set small_context as application data in dtls_context so we can
   * use it in read callback to pass decrypted application data to
   * libcoap. */
  dtls_set_app_data(context.dtls_context, &context);

  /* register callback function to send data over secure channel */
  coap_set_cb(context.coap_context, send_to_peer, write);
#endif

  /* second, resources must be registered with their handlers */
  if (!init_resource(context.coap_context)) {
    coap_free_context(context.coap_context);
    exit(EXIT_FAILURE);			/* error */
  }

  run(&context);			/* main loop */

  coap_free_context(context.coap_context);
  return EXIT_SUCCESS;
}


/* Example handler for GET requests */
void 
hnd_get(coap_context_t  *ctx, struct coap_resource_t *resource, 
	const coap_endpoint_t *local_interface,
	coap_address_t *peer, coap_pdu_t *request, str *token,
	coap_pdu_t *response) {
  unsigned char buf[3];	   /* need some storage for option encoding */

  /* set the result code */
  response->hdr->code = COAP_RESPONSE_CODE(205);

  /* add a Content-Type option to describe the returned data */
  coap_add_option(response, COAP_OPTION_CONTENT_TYPE,
	  coap_encode_var_bytes(buf, COAP_MEDIATYPE_TEXT_PLAIN), buf);

  /* add some data */
  coap_add_data(response, 12, (unsigned char *)"Hello world!");
}

/* Creates a new resource in ctx. The return value is 1 on success, or
 * 0 on error . */
int
init_resource(coap_context_t *ctx) {
  coap_resource_t *resource;

  /* allocate storage for a new resource with given path name (must
   * omit leading '/') */
  resource = coap_resource_init((unsigned char *)"example", 7, 0);
  if (resource) {

    /* register a function as GET handler for this resource */
    coap_register_handler(resource, COAP_REQUEST_GET, hnd_get);

    /* set content-type to text/plain with UTF-8 encoding */
    coap_add_attr(resource, 
		  (unsigned char *)"ct", 2, 
		  (unsigned char *)"0", 1,
		  0);

    /* and finally add the resource to the current context */
    coap_add_resource(ctx, resource);
  }

  return resource != NULL;
}

int
is_secure(const coap_endpoint_t *src, const coap_address_t *dst) {
  return 1;
}

ssize_t
send_to_peer(struct coap_context_t *ctx,
	     const coap_endpoint_t *local_interface,
	     const coap_address_t *remote, 
	     unsigned char *data, size_t len) {
  int res = -2;

  if (is_secure(local_interface, remote)) {
#if HAVE_LIBTINYDTLS
    session_t session;

    /* create tinydtls session object from remote address and local
     * endpoint handle */
    dtls_session_init(&session);
    session.size = remote->size;
    session.addr.st = remote->addr.st;
    session.ifindex = local_interface->handle;

    res = dtls_write(context.dtls_context, &session, 
		     (uint8 *)data, len);
#endif /* HAVE_LIBTINYDTLS */
  } else {
    res = coap_network_send(ctx, local_interface, remote, data, len);
  }

  return res;
}

void
handle_read(small_context_t *ctx, coap_endpoint_t *local) {
  static unsigned char buf[COAP_MAX_PDU_SIZE];
  ssize_t bytes_read = -1;
  coap_address_t remote;

  coap_address_init(&remote);

  bytes_read = coap_network_read(local, &remote, buf, sizeof(buf));
  
  if (bytes_read < 0) {
    fprintf(stderr, "handle_read: recvfrom");
  } else {
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 40
#endif
    unsigned char addr[INET6_ADDRSTRLEN+8];

    if (coap_print_addr(&remote, addr, INET6_ADDRSTRLEN+8)) {
      printf("received %d bytes from %s on local interface ",
	     (int)bytes_read, addr);
      if (coap_print_addr(&local->addr, addr, INET6_ADDRSTRLEN+8))
	printf("%s", addr);
      printf("\n");
    }
    
#if HAVE_LIBTINYDTLS
    if (is_secure(local, &remote)) {
      session_t session;

      /* create tinydtls session object from remote address and local
       * endpoint handle */
      dtls_session_init(&session);
      session.size = remote.size;
      session.addr.st = remote.addr.st;
      session.ifindex = local->handle;

      dtls_handle_message(ctx->dtls_context, &session,
			  (uint8 *)buf, bytes_read);
    } else {
      coap_handle_message(ctx->coap_context, local, &remote,
			  buf, (size_t)bytes_read);
    }
#else
  coap_handle_message(ctx->coap_context, local, &remote,
    buf, (size_t)bytes_read);
#endif
  }
}

/* The server's main loop. */
void
run(small_context_t *ctx) {
  fd_set readfds;
  struct timeval tv, *timeout;
  int result;
  coap_tick_t now;
  coap_queue_t *nextpdu;

  coap_address_t listen_addr;
  coap_endpoint_t *ep;
  static struct list_ep_t ep_item;

  /* clears the entire structure */
  coap_address_init(&listen_addr);

  /* set IPv6 interface address */
  listen_addr.size = sizeof(struct sockaddr_in6);
  listen_addr.addr.sin6.sin6_family = AF_INET6;
  listen_addr.addr.sin6.sin6_port = htons(MY_COAP_PORT);
  listen_addr.addr.sin6.sin6_addr = in6addr_any;

  ep = coap_new_endpoint(&listen_addr, 0);
  if (!ep)
    return;
  
  memset(&ep_item, 0, sizeof(ep_item));
  ep_item.ep = ep;
  list_add(context.endpoints, &ep_item);
  
  while(1) {
    FD_ZERO(&readfds);
    FD_SET(ep->handle, &readfds);

    nextpdu = coap_peek_next(ctx->coap_context);

    coap_ticks(&now);
    while(nextpdu && nextpdu->t <= now) {
      coap_retransmit(ctx->coap_context, coap_pop_next(ctx->coap_context));
      nextpdu = coap_peek_next(ctx->coap_context);
    }

    /* set a timeout if there is a PDU to retransmit */
    if (nextpdu) {
      tv.tv_usec = ((nextpdu->t - now) % COAP_TICKS_PER_SECOND) * 1000000 / COAP_TICKS_PER_SECOND;
      tv.tv_sec = (nextpdu->t - now) / COAP_TICKS_PER_SECOND;
      timeout = &tv;
    } else {
      timeout = NULL;
    }

    /* wait until something happens */
    result = select(FD_SETSIZE, &readfds, 0, 0, timeout);

    if (result < 0) {		/* error */
      if (errno != EINTR)
	perror("select");
      break;			/* leave main loop */
    } else if (result > 0) {	/* read from socket */
      if (FD_ISSET(ep->handle, &readfds)) {
	handle_read(ctx, ep); /* read received data */
      }
    } else {			/* timeout */
      /* there is no need to do anything here as the retransmission
       * are triggered next in the main loop */
    }
  }

  coap_free_endpoint(ep);
}
