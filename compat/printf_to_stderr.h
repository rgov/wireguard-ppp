#ifndef PRINTF_TO_STDERR_H
#define PRINTF_TO_STDERR_H

#include <stdio.h>

// The wireguard-lwip code logs a few messages to stdout, which interferes with
// the channel with pppd.
#define printf(...) fprintf(stderr, __VA_ARGS__)

#endif
