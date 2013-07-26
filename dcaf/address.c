#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "config.h"
#include "address.h"

int 
coap_address_resolve(const unsigned char *address, size_t address_length,
		     unsigned short port, coap_address_t *result) {
  struct addrinfo *res, *ainfo;
  struct addrinfo hints;
  char addrstr[256];
  char service[6];
  int error, len=-1;

  /* prepareaddress and service as input for getaddrinfo */
  if (sizeof(addrstr) - 1 < address_length)
    return 0;

  memcpy(addrstr, address, address_length);
  addrstr[address_length] = '\0';

  if (port)
    snprintf(service, sizeof(service), "%hu", port);
  else
    service[0] = '\0';
  
  memset ((char *)&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_family = AF_UNSPEC;

  error = getaddrinfo(addrstr, service, &hints, &res);

  if (error != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
    return error;
  }

  memset(result, 0, sizeof(coap_address_t));
  for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) {
    switch (ainfo->ai_family) {
    case AF_INET6:
    case AF_INET:
      result->size = ainfo->ai_addrlen;
      memcpy(&result->addr.st, ainfo->ai_addr, result->size);
      goto finish;
    default:
      ;
    }
  }

 finish:
  freeaddrinfo(res);
  return len;
}
