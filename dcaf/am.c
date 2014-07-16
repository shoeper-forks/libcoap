/* as.c -- Authorization Server Dummy
 *
 * Copyright (C) 2010--2013 Olaf Bergmann <bergmann@tzi.org>,
 *                          Stefanie Gerdes <gerdes@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */

#include "config.h"

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <json-c/json.h>

#include "debug.h"
#include "coap.h"

#define AS_DEFAULT_PORT 7770
#define AUTH_RESOURCE   "auth"

extern int coap_address_resolve(const unsigned char *addrstr, size_t length,
				unsigned short port, coap_address_t *result);

#if HAVE_LIBTINYDTLS
/* The following definitions are required because we cannot include
 * tinydtls/debug.h at this point. */
typedef coap_log_t log_t;
extern void dtls_set_log_level(log_t level);
#endif /* HAVE_LIBTINYDTLS */

/* TODO: Handle multiple async connections */
static coap_async_state_t *async = NULL;

int init_resource(coap_context_t *);


int parse_address (coap_uri_t * uri, char * json_data) {
  json_object * json_obj;
  json_object * jsonptr;
  const char * abs_uri;
  json_obj = json_tokener_parse(json_data);

  json_object_object_get_ex(json_obj, "AS", &jsonptr);
  abs_uri = json_object_get_string(jsonptr);
  printf("string: %s\n",abs_uri);
  
  return coap_split_uri((unsigned char*)abs_uri, strlen(abs_uri), uri);
}


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
  unsigned short mid;
  coap_pdu_t *tick_req_pdu;
  int result;
  size_t size = sizeof(coap_hdr_t) + 80;
  coap_address_t dst;
  int res;
  unsigned char * data;
  size_t json_data_len;
  coap_uri_t uri;
  unsigned char *json_data; 
  unsigned char segmentbuf[255];
  unsigned char* segmentbufptr=segmentbuf;
  size_t bufsize=255;

  /* set the result code */
  response->hdr->code = COAP_RESPONSE_CODE(205);

  /* register async-object because we send a separate response to the client's
  authorization request */
  /* store the ticket request token in async->data */
  mid = coap_new_message_id(ctx);
  data=coap_malloc(sizeof(mid));
  async = coap_register_async(ctx, peer, request, COAP_ASYNC_SEPARATE|COAP_ASYNC_CONFIRM|COAP_ASYNC_RELEASE_DATA, (void*) data);
  /* find out AS(RS) address */
  if (!coap_get_data(request, &json_data_len, &json_data)) {
    return;
  }

  /* Note: json_data should be zero terminated */
  if (!parse_address(&uri, (char*)json_data)) {
    return;
  }

  printf("path: %s\n",uri.path.s);

  res =
    coap_address_resolve(uri.host.s, uri.host.length, htons(uri.port), &dst);
  dst.size = res; 
  dst.addr.sin.sin_port = htons(uri.port); /* FIXME: possibly not needed anymore */

  /* build ticket request to AS(RS) */
  size+=json_data_len;
  tick_req_pdu = coap_pdu_init(COAP_MESSAGE_CON,COAP_REQUEST_POST,mid,size);
  if (tick_req_pdu) {
    /* set token so we are able to identify respective async-object */
    /* TODO: take own message id, client's message id may not be unique */
    coap_add_token(tick_req_pdu, sizeof(request->hdr->id), (unsigned char*)async->appdata);
    
    /* generate AS's uri path from request */
    result = coap_split_path(uri.path.s,uri.path.length,segmentbuf,&bufsize);
    while (result--) {
      coap_add_option(tick_req_pdu, COAP_OPTION_URI_PATH,COAP_OPT_LENGTH(segmentbufptr),COAP_OPT_VALUE(segmentbufptr));
      segmentbufptr += COAP_OPT_SIZE(segmentbufptr);
    }
    coap_add_option(tick_req_pdu, COAP_OPTION_CONTENT_FORMAT, coap_encode_var_bytes(buf, (unsigned int)777), buf);
    coap_show_pdu(tick_req_pdu);
    coap_add_data(tick_req_pdu, json_data_len, json_data);

    /* TODO: build secure channel before sending */
    /* note: we may have several interfaces */
    coap_send_confirmed(ctx, local_interface, &dst, tick_req_pdu);
  }

  /* /\* add a Content-Type option to describe the returned data *\/ */
  /* coap_add_option(response, COAP_OPTION_CONTENT_TYPE, */
  /* 	  coap_encode_var_bytes(buf, COAP_MEDIATYPE_TEXT_PLAIN), buf); */

  /* /\* add some data *\/ */
  /* coap_add_data(response, 12, (unsigned char *)"Hello world!"); */
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
