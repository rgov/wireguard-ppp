#ifndef WIREGUARD_PPP_CONFIG_H
#define WIREGUARD_PPP_CONFIG_H

#include <stdint.h>

struct options {
  char private_key[45];
  char public_key[45];
  char local_ip[16];
  char peer_ip[16];
  char endpoint_ip[16];
  uint16_t endpoint_port;
  uint16_t listen_port;
  uint16_t keepalive;
};

int config_read(const char *path, struct options *options);

#endif
