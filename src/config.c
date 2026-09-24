// Parse the single-peer subset of WireGuard configuration used by this adapter
#include "config.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Trim surrounding whitespace in place and return the first nonspace */
static char *trim(char *text)
{
  // Skip leading whitespace and terminate before trailing whitespace
  while (isspace((unsigned char)*text))
    ++text;
  char *end = text + strlen(text);
  while (end > text && isspace((unsigned char)end[-1]))
    --end;
  *end = 0;
  return text;
}

/* Parse a bounded decimal port or keepalive interval */
static int number(const char *text, uint16_t *out, unsigned minimum)
{
  // Require decimal digits and a value representable by the option field
  if (!*text || strspn(text, "0123456789") != strlen(text))
    return 0;
  unsigned long value = strtoul(text, NULL, 10);
  if (value < minimum || value > 65535)
    return 0;
  *out = value;
  return 1;
}

/* Parse an IPv4 literal, allowing a host prefix for tunnel addresses */
static int address(char *text, char out[16], int allow_prefix)
{
  // Only host routes are supported; never silently discard a wider prefix
  char *slash = strchr(text, '/');
  if (slash) {
    if (!allow_prefix || strcmp(slash, "/32"))
      return 0;
    *slash = 0;
  }

  // Validate before copying into the fixed-size output buffer
  struct in_addr ip;
  if (strlen(text) >= 16 || inet_pton(AF_INET, text, &ip) != 1)
    return 0;
  strcpy(out, text);
  return 1;
}

/* Parse configuration into options, reporting failures without printing keys */
int config_read(const char *path, struct options *options)
{
  // Initialize defaults and open the configuration file
  memset(options, 0, sizeof(*options));
  FILE *file = fopen(path, "r");
  if (!file) {
    perror(path);
    return -1;
  }

  // Read bounded lines, removing comments and accepting either section order
  enum { NONE, INTERFACE, PEER } section = NONE;

  unsigned sections = 0, line_number = 0;
  const char *error = NULL;
  char line[512];
  while (fgets(line, sizeof(line), file)) {
    ++line_number;
    if (!strchr(line, '\n') && !feof(file)) {
      error = "line too long";
      break;
    }
    line[strcspn(line, "#")] = 0;
    char *key = trim(line);
    if (!*key)
      continue;

    // Accept exactly one interface and one peer, rejecting other sections
    if (*key == '[') {
      if (!strcmp(key, "[Interface]"))
        section = INTERFACE;
      else if (!strcmp(key, "[Peer]"))
        section = PEER;
      else {
        error = "unsupported section";
        break;
      }
      if (sections & (1U << section)) {
        error = "duplicate section; only one interface and peer are supported";
        break;
      }
      sections |= 1U << section;
      continue;
    }

    // Split at the first equals sign so base64 padding remains part of the key
    char *value = strchr(key, '=');
    if (!value) {
      error = "expected Name = value";
      break;
    }
    *value++ = 0;
    key = trim(key);
    value = trim(value);
    int valid = 0;
    error = "invalid option value";

    // Translate supported fields directly into the returned option struct
    if ((section == INTERFACE && !strcmp(key, "PrivateKey")) ||
        (section == PEER && !strcmp(key, "PublicKey"))) {
      valid = strlen(value) == 44;
      if (valid)
        strcpy(section == INTERFACE ? options->private_key
                                    : options->public_key,
               value);
    } else if (section == INTERFACE && !strcmp(key, "Address")) {
      valid = address(value, options->local_ip, 1);
    } else if (section == INTERFACE && !strcmp(key, "ListenPort")) {
      valid = number(value, &options->listen_port, 0);
    } else if (section == PEER && !strcmp(key, "AllowedIPs")) {
      valid = address(value, options->peer_ip, 1);
    } else if (section == PEER && !strcmp(key, "Endpoint")) {
      char *port = strrchr(value, ':');
      if (port) {
        *port++ = 0;
        valid = address(value, options->endpoint_ip, 0) &&
                number(port, &options->endpoint_port, 1);
      }
    } else if (section == PEER && !strcmp(key, "PersistentKeepalive")) {
      // Upstream reserves 65535 as a default sentinel, not an interval
      valid = number(value, &options->keepalive, 0) &&
              options->keepalive != UINT16_MAX;
    } else {
      error = "unsupported option";
    }
    if (!valid)
      break;
    error = NULL;
  }

  // Require the fields needed to initialize the tunnel before returning
  if (!error && ferror(file))
    error = "read error";
  if (!error &&
      (!*options->private_key || !*options->public_key || !*options->local_ip ||
       !*options->peer_ip || !*options->endpoint_ip || !options->endpoint_port))
    error = "missing PrivateKey, Address, PublicKey, AllowedIPs, or Endpoint";
  if (!error && !strcmp(options->local_ip, options->peer_ip))
    error = "tunnel addresses must differ";
  fclose(file);
  if (error) {
    fprintf(stderr, "%s:%u: %s\n", path, line_number, error);
    memset(options, 0, sizeof(*options));
    return -1;
  }
  return 0;
}
