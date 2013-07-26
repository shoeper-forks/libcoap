/* mem.h -- CoAP memory handling
 *          Currently, this is just a dummy for malloc/free
 *
 * Copyright (C) 2010--2013 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */

#ifndef _COAP_MEM_H_
#define _COAP_MEM_H_

#include <stdlib.h>

#define coap_malloc(size) malloc(size)
#define coap_free(size) free(size)

#define COAP_MALLOC_TYPE(Type) \
  ((coap_##Type##_t *)coap_malloc(sizeof(coap_##Type##_t)))
#define COAP_FREE_TYPE(Type, Object) coap_free(Object)

#endif /* _COAP_MEM_H_ */
