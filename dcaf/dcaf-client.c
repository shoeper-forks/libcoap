/* dcaf-client.c -- simple client for the DCAF protocol
 *                  draft-gerdes-core-dcaf-authorize-00
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
#include <unistd.h>

#include "debug.h"
#include "coap.h"

#if HAVE_LIBTINYDTLS
/* The following definitions are required because we cannot include
 * tinydtls/debug.h at this point. */
typedef coap_log_t log_t;
extern void dtls_set_log_level(log_t level);

typedef struct dcaf_context_t {
  coap_uri_t ap_uri;		/**< URI of our authentication proxy */
  coap_uri_t rs_uri;		/**< the RS to talk to */
} dcaf_context_t;

char DEFAULT_AP_URI[] = "coaps://localhost:7770/auth";

#define COAP_APPLICATION_SEND_SECURE 0x01

extern int coap_address_resolve(const unsigned char *addrstr, size_t length,
				unsigned short port, coap_address_t *result);

const unsigned short myport = 0;
const unsigned short myport_secure = 0;

void usage(const char *program, const char *version);

coap_pdu_t *
create_request(coap_application_t *application, unsigned char type, 
	       unsigned char code, coap_uri_t *r_uri,
	       size_t data_len, unsigned char *data) {
  coap_pdu_t *pdu;
#define BUFSIZE 256
  unsigned char _buf[BUFSIZE];
  unsigned char *buf = _buf;
  size_t buflen;
  int res;

  pdu = coap_pdu_init(type, code, 
		      coap_new_message_id(application->coap_context),
		      COAP_MAX_PDU_SIZE);

  if (!pdu)
    return NULL;

  if (r_uri->path.length) {
    buflen = BUFSIZE;
    res = coap_split_path(r_uri->path.s, r_uri->path.length, buf, &buflen);

    while (res--) {
      coap_add_option(pdu, COAP_OPTION_URI_PATH, 
		      coap_opt_length(buf), coap_opt_value(buf));
      
      buf += coap_opt_size(buf);      
    }
  }
  
  if (r_uri->query.length) {
    buflen = BUFSIZE;
    buf = _buf;
    res = coap_split_query(r_uri->query.s, r_uri->query.length, buf, &buflen);

    while (res--) {
      coap_add_option(pdu, COAP_OPTION_URI_QUERY, 
		      coap_opt_length(buf), coap_opt_value(buf));

      buf += coap_opt_size(buf);      
    }
  }

  if (data_len) {
    coap_add_data(pdu, data_len, data);
  }

  return pdu;
}

void
rs_response_handler(struct coap_context_t  *ctx, 
		    const coap_endpoint_t *local_interface, 
		    const coap_address_t *remote, 
		    coap_pdu_t *sent,
		    coap_pdu_t *received,
		    const coap_tid_t id) {
  
  coap_log(LOG_INFO, "received response from RS\n");
}

void
auth_reponse_handler(struct coap_context_t  *ctx, 
		     const coap_endpoint_t *local_interface, 
		     const coap_address_t *remote, 
		     coap_pdu_t *sent,
		     coap_pdu_t *received,
		     const coap_tid_t id) {
  coap_application_t *application;
  dcaf_context_t *dcaf_context; 
  coap_address_t dst;
  coap_pdu_t *pdu;

  /* we are only interested in 2.05 responses for now
   * TODO: check if token matches our request
   */
  if (received->hdr->code != COAP_RESPONSE_CODE(205)) {
    coap_log(LOG_INFO, "received response was not a 2.05 reponse\n");
    return;
  }

  application = coap_get_app_data(ctx);
  assert(application);

  dcaf_context = coap_application_get_app_data(application);
  assert(dcaf_context);

  /* FIXME: register credentials from received response */

  /* retrieve destination address from rs_uri */
  if (!coap_address_resolve(dcaf_context->rs_uri.host.s, 
			    dcaf_context->rs_uri.host.length,
			    dcaf_context->rs_uri.port, &dst)) {
    debug("cannot resolve address\n");
  }

#ifndef NDEBUG
  if (LOG_DEBUG <= coap_get_log_level()) {
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 40
#endif
    unsigned char addr[INET6_ADDRSTRLEN+8];
    
    if (coap_print_addr(&dst, addr, INET6_ADDRSTRLEN+8)) {
      debug("rs address resolved to: %s \n", addr); 
    }
  }
#endif

  pdu = create_request(application, COAP_MESSAGE_CON, 
		       COAP_REQUEST_GET, &dcaf_context->rs_uri, 0, NULL);

  if (!pdu) {
    coap_log(LOG_ALERT, "cannot create PDU for RS\n");
    return;
  }
    
  /* send message */
  coap_application_send_request(application, 
				(coap_endpoint_t *)local_interface, 
				&dst, pdu, rs_response_handler,
				COAP_APPLICATION_SEND_SECURE);
}

int
authorization_request(coap_application_t *application,
		      coap_endpoint_t *local_interface,
		      coap_uri_t *ap_uri) {
  coap_address_t dst;
  coap_pdu_t *pdu;

  /* retrieve destination address from ap_uri */
  if (!coap_address_resolve(ap_uri->host.s, ap_uri->host.length,
			    ap_uri->port, &dst)) {
    debug("cannot resolve address\n");
    return 0;
  }

#ifndef NDEBUG
  if (LOG_DEBUG <= coap_get_log_level()) {
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 40
#endif
    unsigned char addr[INET6_ADDRSTRLEN+8];
    
    if (coap_print_addr(&dst, addr, INET6_ADDRSTRLEN+8)) {
      debug("ap address resolved to: %s \n", addr); 
    }
  }
#endif
  /* create request PDU */
  pdu = create_request(application, COAP_MESSAGE_CON, 
		       COAP_REQUEST_POST, ap_uri, 0, NULL);
  if (!pdu) {
    coap_log(LOG_CRIT, "cannot create Authorization request\n");
    return 0;
  }
    
  /* send message */
  return coap_application_send_request(application, local_interface, 
				       &dst, pdu,
				       auth_reponse_handler,
				       COAP_APPLICATION_SEND_SECURE)
    >= 0;
}

int
main(int argc, char **argv) {
  coap_application_t *app;
  coap_endpoint_t *nosec_interface, *dtls_interface;
  coap_address_t listen_addr;
  coap_log_t log_level = LOG_WARNING;
  dcaf_context_t dcaf_context;
  int result = EXIT_FAILURE;
  int opt;

  while ((opt = getopt(argc, argv, "h:v:")) != -1) {
    switch (opt) {
    case 'v' :
      log_level = strtol(optarg, NULL, 10);
      break;
    case 'h' :
      result = EXIT_SUCCESS; /* usage information was explicitly requested */
    default:
      usage(argv[0], PACKAGE_VERSION);
      exit(result);
    }
  }

  coap_set_log_level(log_level);
  dtls_set_log_level(log_level);

  /* read as and rs uri */
  if (optind < argc) {
    coap_split_uri((unsigned char *)(argv[optind]), strlen(argv[optind]), 
		   &dcaf_context.rs_uri);
    optind++;
  } else {
    usage(argv[0], PACKAGE_VERSION);
    exit(result);
  }

  if (optind < argc) {
    coap_split_uri((unsigned char *)(argv[optind]), strlen(argv[optind]), 
		   &dcaf_context.ap_uri);
  } else {
    /* use default AS uri */
    coap_split_uri((unsigned char *)DEFAULT_AP_URI, strlen(DEFAULT_AP_URI), 
		   &dcaf_context.ap_uri);
  }

  app = coap_new_application();

  if (app) {
    /* we can use dcaf_context here as the command line arguments and
     * local variables live longer than app itself. */
    coap_application_set_app_data(app, &dcaf_context);

    /* coap_register_response_handler(app->coap_context, message_handler); */

    /* bind interfaces */

    /* clears the entire structure */
    coap_address_init(&listen_addr);

    /* set IPv6 interface address */
    listen_addr.size = sizeof(struct sockaddr_in6);
    listen_addr.addr.sin6.sin6_family = AF_INET6;
    listen_addr.addr.sin6.sin6_port = htons(myport);
    listen_addr.addr.sin6.sin6_addr = in6addr_any;

    nosec_interface = coap_new_endpoint(&listen_addr, 0);
    if (!coap_application_attach(app, nosec_interface)) {
      coap_log(LOG_CRIT, "failed to create endpoint\n");
      coap_free_endpoint(nosec_interface);
      goto cleanup;
    }

    coap_address_init(&listen_addr);

    /* set IPv6 interface address */
    listen_addr.size = sizeof(struct sockaddr_in6);
    listen_addr.addr.sin6.sin6_family = AF_INET6;
    listen_addr.addr.sin6.sin6_port = htons(myport_secure);
    listen_addr.addr.sin6.sin6_addr = in6addr_any;

    dtls_interface = coap_new_endpoint(&listen_addr, COAP_ENDPOINT_DTLS);
    if (!coap_application_attach(app, dtls_interface)) {
      coap_log(LOG_CRIT, "failed to create secure endpoint\n");
      coap_free_endpoint(dtls_interface);
      goto cleanup;
    }

    if (!authorization_request(app, dtls_interface, &dcaf_context.ap_uri)) {
      coap_log(LOG_CRIT, "sending authorization request failed\n");
      goto cleanup;
    }

    result = (int)coap_application_run(app);	/* main loop */
  }

 cleanup:
  coap_free_application(app);
  return result;  
}

/************************************************************************/
void
usage(const char *program, const char *version) {
  const char *p;

  p = strrchr(program, '/');
  if (p)
    program = ++p;

  fprintf( stderr, "%s v%s -- DCAF protocol client\n"
	   "(c) 2013 Olaf Bergmann <bergmann@tzi.org>\n\n"
	   "usage: %s [-h] [-v num] URI [AP]\n\n"
	   "\tURI must be an absolute coaps URI of the requested resource,\n"
	   "\tAP is the absolute URI of your authorization proxy,\n"
	   "\t-h \t\tdisplay this help screen\n"
	   "\t-v num\t\tverbosity level (default: 3)\n"
	   "\n"
	   "examples:\n"
	   "\t%s coaps://[::1]/auth coaps://rs.example.com:61616/example\n"
	   ,program, version, program, program);
}

#else /* HAVE_LIBTINYDTLS */
int
main(int argc, char **argv) {
  const char *p;

  p = strrchr(program, '/');
  if (p)
    program = ++p;
  
  fprintf(stderr, "%s was built without DTLS support.\n", program);
  return EXIT_FAILURE;
}
#endif /* HAVE_LIBTINYDTLS */
