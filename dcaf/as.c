/* as.c -- Authorization Server Dummy
 *
 * Copyright (C) 2010--2013 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */

#include "config.h"

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "debug.h"
#include "coap.h"

#define AS_DEFAULT_PORT 7770
#define AUTH_RESOURCE   "auth"

#if HAVE_LIBTINYDTLS
/* The following definitions are required because we cannot include
 * tinydtls/debug.h at this point. */
typedef coap_log_t log_t;
extern void dtls_set_log_level(log_t level);
#endif /* HAVE_LIBTINYDTLS */

int init_resource(coap_context_t *);

/*---------------------------------------------------------------------------*/
int
main(int argc, char **argv) {
  coap_application_t *app;
  coap_endpoint_t *interface;
  coap_address_t listen_addr;
  int result = EXIT_FAILURE;
  coap_set_log_level(LOG_DEBUG);

  app = coap_new_application();

  if (app) {
    /* bind interfaces */

#if HAVE_LIBTINYDTLS
    dtls_set_log_level(LOG_DEBUG);
    coap_address_init(&listen_addr);

    /* set IPv6 interface address */
    listen_addr.size = sizeof(struct sockaddr_in6);
    listen_addr.addr.sin6.sin6_family = AF_INET6;
    listen_addr.addr.sin6.sin6_port = htons(AS_DEFAULT_PORT);
    listen_addr.addr.sin6.sin6_addr = in6addr_any;

    interface = coap_new_endpoint(&listen_addr, COAP_ENDPOINT_DTLS);
    if (!coap_application_attach(app, interface)) {
      coap_log(LOG_CRIT, "failed to create endpoint\n");
      coap_free_endpoint(interface);
      goto cleanup;
    }
#endif

    /* second, resources must be registered with their handlers */
    if (init_resource(app->coap_context)) {
      
      result = (int)coap_application_run(app);	/* main loop */

      coap_free_application(app);
    }
  }

 cleanup:
  coap_free_application(app);
  return result;  
}


/* Example handler for GET requests */
void 
hnd_post(coap_context_t  *ctx, struct coap_resource_t *resource, 
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
  resource = coap_resource_init((unsigned char *)AUTH_RESOURCE, 
				strlen(AUTH_RESOURCE), 0);
  if (resource) {

    /* register a function as GET handler for this resource */
    coap_register_handler(resource, COAP_REQUEST_POST, hnd_post);

    /* and finally add the resource to the current context */
    coap_add_resource(ctx, resource);
  }

  return resource != NULL;
}
