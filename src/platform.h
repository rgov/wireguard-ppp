#ifndef WIREGUARD_PPP_PLATFORM_H
#define WIREGUARD_PPP_PLATFORM_H

#include "config.h"
#include "lwip/ip4_addr.h"
#include "lwip/pbuf.h"

void wg_init(const struct options *options);
int wg_fd(void);
void wg_receive(void);
void wg_tick(void);
err_t wg_output(struct pbuf *packet, const ip4_addr_t *destination);
void wg_close(void);

#endif
