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
char DEFAULT_AS_URI[] = "coaps://localhost:7770/auth";

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

int
authorization_request(coap_application_t *application,
		      coap_endpoint_t *local_interface,
		      coap_uri_t *as_uri) {
  coap_address_t dst;
  coap_pdu_t *pdu;

  /* retrieve destination address from as_uri */
  if (!coap_address_resolve(as_uri->host.s, as_uri->host.length,
			    as_uri->port, &dst)) {
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
      debug("address resolved to: %s \n", addr); 
    }
  }
#endif
  /* create request PDU */
  pdu = create_request(application, COAP_MESSAGE_CON, 
		       COAP_REQUEST_POST, as_uri, 0, NULL);
  if (!pdu) {
    coap_log(LOG_CRIT, "cannot create Authorization request\n");
    return 0;
  }
    
  /* send message */
  return coap_application_sendmsg(application, local_interface, 
				  &dst, pdu,
				  COAP_APPLICATION_SEND_SECURE)
    >= 0;
}

int
main(int argc, char **argv) {
  coap_application_t *app;
  coap_endpoint_t *nosec_interface, *dtls_interface;
  coap_address_t listen_addr;
  coap_log_t log_level = LOG_WARN;
  coap_uri_t as_uri, rs_uri;
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

  /* read as and rs uri */
  if (optind < argc) {
    coap_split_uri((unsigned char *)(argv[optind]), strlen(argv[optind]), 
		   &rs_uri);
    optind++;
  } else {
    usage(argv[0], PACKAGE_VERSION);
    exit(result);
  }

  if (optind < argc) {
    coap_split_uri((unsigned char *)(argv[optind]), strlen(argv[optind]), 
		   &as_uri);
  } else {
    /* use default AS uri */
    coap_split_uri((unsigned char *)DEFAULT_AS_URI, strlen(DEFAULT_AS_URI), 
		   &as_uri);
  }

  app = coap_new_application();

  if (app) {
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

    if (!authorization_request(app, dtls_interface, &as_uri)) {
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
	   "usage: %s [-h] [-v num] URI [AS]\n\n"
	   "\tURI must be an absolute coaps URI of the requested resource,\n"
	   "\tAS is the absolute URI of your authorization server,\n"
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
