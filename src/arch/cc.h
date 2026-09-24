#ifndef WIREGUARD_PPP_ARCH_CC_H
#define WIREGUARD_PPP_ARCH_CC_H
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS
#define LWIP_TIMEVAL_PRIVATE 0
void pppos_diagnostic(const char *format, ...);
uint32_t pppos_random(void);
#define LWIP_RAND() pppos_random()
#define LWIP_PLATFORM_DIAG(args)                                               \
  do {                                                                         \
    pppos_diagnostic args;                                                     \
  } while (0)
#define LWIP_PLATFORM_ASSERT(message)                                          \
  do {                                                                         \
    fprintf(stderr, "lwIP assertion: %s (%s:%d)\n", message, __FILE__,         \
            __LINE__);                                                         \
    abort();                                                                   \
  } while (0)
#endif
