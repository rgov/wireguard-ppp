// Native UDP sockets and platform hooks for WireGuard and lwIP
#define _POSIX_C_SOURCE 200809L
#include "platform.h"
#include "wireguard.h"
#include "wireguardif.h"
#include "crypto.h"
#include "lwip/timeouts.h"
#include <arpa/inet.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>

static struct netif iface;
static struct udp_pcb *socket_pcb;
static int random_fd = -1;
static int socket_fd = -1;
static int reported_up;
static unsigned long tx_packets, rx_packets;

// --- Internal helpers ---

/* Report an unrecoverable platform error and terminate the process */
static void fatal(const char *s)
{
  // Preserve the current errno in the diagnostic before exiting
  fprintf(stderr, "WG_FAIL: %s (errno=%d)\n", s, errno);
  exit(1);
}

// --- wireguard-lwip platform hooks ---

/* Provide wireguard-lwip with a wrapping monotonic millisecond clock */
uint32_t wireguard_sys_now(void)
{
  // Use elapsed time for protocol deadlines, independent of clock corrections
  struct timespec t;
  if (clock_gettime(CLOCK_MONOTONIC, &t))
    fatal("monotonic clock");
  return (uint32_t)((uint64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000);
}

/* Fill a WireGuard or PPP randomness request from the host entropy source */
void wireguard_random_bytes(void *out, size_t len)
{
  // Open the host cryptographic random source on first use
  if (random_fd < 0)
    random_fd = open("/dev/urandom", O_RDONLY);
  if (random_fd < 0)
    fatal("open /dev/urandom");

  // Fill the requested range, retrying interrupted and partial reads
  uint8_t *p = out;
  while (len) {
    ssize_t n = read(random_fd, p, len);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      fatal("random source");
    p += n;
    len -= n;
  }
}

/* Encode a WireGuard handshake timestamp that increases within this process */
void wireguard_tai64n_now(uint8_t *out)
{
  // Convert the wall clock to the seconds/nanoseconds fields used by WireGuard
  struct timespec t;
  if (clock_gettime(CLOCK_REALTIME, &t))
    fatal("realtime clock");
  uint64_t sec = (uint64_t)t.tv_sec + 0x400000000000000aULL;
  uint32_t ns = t.tv_nsec;

  // Preserve strict ordering across clock corrections within this process
  static uint64_t last_sec;
  static uint32_t last_nsec;
  if (sec < last_sec || (sec == last_sec && ns <= last_nsec)) {
    sec = last_sec;
    ns = last_nsec + 1;
    if (ns == 1000000000) {
      ++sec;
      ns = 0;
    }
  }
  last_sec = sec;
  last_nsec = ns;

  // Serialize the timestamp in the network byte order required by the protocol
  U64TO8_BIG(out, sec);
  U32TO8_BIG(out + 8, ns);
}

/* Tell wireguard-lwip whether handshake load protection should be enabled */
bool wireguard_is_under_load(void)
{
  // This single-peer adapter does not implement handshake load detection
  return false;
}

// --- lwIP platform hooks ---

/* Supply the monotonic milliseconds used by lwIP timeout scheduling */
uint32_t sys_now(void)
{
  // Share the millisecond clock used for WireGuard protocol deadlines
  return wireguard_sys_now();
}

/* Supply the tick value used by lwIP PPP, using millisecond granularity */
uint32_t sys_jiffies(void)
{
  // Share the millisecond clock used for WireGuard protocol deadlines
  return wireguard_sys_now();
}

/* Supply a random 32-bit value for the lwIP LWIP_RAND platform hook */
uint32_t pppos_random(void)
{
  // Draw PPP randomness from the same cryptographic source as WireGuard
  uint32_t n;
  wireguard_random_bytes(&n, sizeof(n));
  return n;
}

/* Route the lwIP diagnostic hook to stderr using printf-style arguments */
void pppos_diagnostic(const char *format, ...)
{
  // Keep lwIP diagnostics off stdout, which carries binary PPP frames
  va_list ap;
  va_start(ap, format);
  vfprintf(stderr, format, ap);
  va_end(ap);
}

// --- lwIP UDP API backed by native sockets (used by wireguard-lwip) ---

/* Satisfy lwIP UDP startup while the host kernel owns the UDP stack */
void udp_init(void)
{
  // Native UDP sockets need no global initialization
}

/* Handle lwIP address-change notifications for the native UDP transport */
void udp_netif_ip_addr_changed(const ip_addr_t *old, const ip_addr_t *new_ip)
{
  // PPP address changes do not affect the native socket bound by udp_bind
  (void)old;
  (void)new_ip;
}

/* Create the single native UDP socket and its lwIP callback control block */
struct udp_pcb *udp_new(void)
{
  // Allocate the callback state expected by the upstream UDP API
  struct udp_pcb *p = calloc(1, sizeof(*p));
  if (!p)
    return NULL;

  // This adapter supports one WireGuard interface and one UDP socket
  if (socket_pcb) {
    free(p);
    return NULL;
  }

  // Create the host transport and publish its associated callback state
  socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (socket_fd < 0) {
    free(p);
    return NULL;
  }
  socket_pcb = p;
  return p;
}

/* Bind the native UDP socket to the address requested by wireguard-lwip */
err_t udp_bind(struct udp_pcb *p, const ip_addr_t *ip, u16_t port)
{
  // Translate the lwIP address and port into a native IPv4 socket address
  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons(port);
  sa.sin_addr.s_addr = ip ? ip->addr : INADDR_ANY;

  // Bind the singleton transport and translate the host result to lwIP status
  return bind(socket_fd, (struct sockaddr *)&sa, sizeof(sa)) ? ERR_CONN
                                                             : ERR_OK;
}

/* Reject unsupported binding to a lwIP interface */
void udp_bind_netif(struct udp_pcb *p, const struct netif *n)
{
  // Fail explicitly if upstream requests an unsupported interface binding
  (void)p;
  (void)n;
  fatal("bind_netif unsupported");
}

/* Register wireguard-lwip's datagram receive callback and context */
void udp_recv(struct udp_pcb *p,
              void (*cb)(void *, struct udp_pcb *, struct pbuf *,
                         const ip_addr_t *, u16_t),
              void *arg)
{
  // Retain the callback and its context for datagrams read by wg_receive
  p->recv = cb;
  p->recv_arg = arg;
}

/* Send a lwIP packet buffer as one native UDP datagram without consuming it */
err_t udp_sendto(struct udp_pcb *p, struct pbuf *buf, const ip_addr_t *ip,
                 u16_t port)
{
  // Flatten the possibly chained packet into a bounded datagram buffer
  uint8_t data[2048];
  (void)p;
  if (buf->tot_len > sizeof(data))
    return ERR_ARG;
  pbuf_copy_partial(buf, data, buf->tot_len, 0);

  // Translate the destination for the native socket API
  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons(port);
  sa.sin_addr.s_addr = ip->addr;

  // Retry interrupted sends; count only complete datagrams as successful
  ssize_t n;
  do {
    n = sendto(socket_fd, data, buf->tot_len, 0, (struct sockaddr *)&sa,
               sizeof(sa));
  } while (n < 0 && errno == EINTR);
  if (n != buf->tot_len)
    return ERR_CONN;
  ++tx_packets;
  return ERR_OK;
}

/* Release a UDP callback control block and its associated native socket */
void udp_remove(struct udp_pcb *p)
{
  // Close the native transport when removing its registered callback state
  if (socket_pcb == p) {
    close(socket_fd);
    socket_fd = -1;
    socket_pcb = NULL;
  }
  free(p);
}

// --- Adapter API used by the event loop ---

/* Create the WireGuard endpoint and configure its single remote peer */
void wg_init(const struct options *options)
{
  // Initialize the local WireGuard interface from the parsed configuration
  struct wireguardif_init_data init;
  memset(&init, 0, sizeof(init));
  init.private_key = options->private_key;
  init.listen_port = options->listen_port;
  iface.state = &init;
  if (wireguardif_init(&iface) != ERR_OK)
    fatal("initialize WireGuard");

  // Configure the sole peer, its tunnel address, and periodic keepalives
  struct wireguardif_peer peer;
  wireguardif_peer_init(&peer);
  peer.public_key = options->public_key;
  peer.keep_alive = options->keepalive;
  inet_pton(AF_INET, options->endpoint_ip, &peer.endpoint_ip.addr);
  inet_pton(AF_INET, options->peer_ip, &peer.allowed_ip.addr);
  peer.allowed_mask.addr = 0xffffffff;
  peer.endport_port = options->endpoint_port;

  // Register the peer and request an initial handshake
  u8_t index;
  if (wireguardif_add_peer(&iface, &peer, &index) != ERR_OK ||
      wireguardif_connect(&iface, index) != ERR_OK)
    fatal("configure peer");
  fprintf(stderr, "WG_STARTED endpoint=%s:%u allowed=%s/32\n",
          options->endpoint_ip, (unsigned)options->endpoint_port,
          options->peer_ip);
}

/* Return the UDP descriptor for the event loop */
int wg_fd(void)
{
  // Expose the transport descriptor to the adapter event loop
  return socket_fd;
}

/* Service library timers and report WireGuard link-state transitions */
void wg_tick(void)
{
  // Run the shared timeout scheduler for PPP and WireGuard
  sys_check_timeouts();

  // Report changes in WireGuard link state once per transition
  int up = netif_is_link_up(&iface) != 0;
  if (up != reported_up)
    fprintf(stderr, "WG_LINK_%s\n", up ? "UP" : "DOWN");
  reported_up = up;
}

/* Read one native UDP datagram and transfer it to wireguard-lwip */
void wg_receive(void)
{
  // Read one datagram and retain the sender address for endpoint roaming
  struct sockaddr_in sa;
  socklen_t len = sizeof(sa);
  uint8_t bytes[2048];
  ssize_t count = recvfrom(socket_fd, bytes, sizeof(bytes), 0,
                           (struct sockaddr *)&sa, &len);
  if (count < 0) {
    if (errno != EINTR)
      perror("WireGuard recvfrom");
    return;
  }

  // Our MTU is 1400. Larger UDP datagrams cannot be useful here.
  if (count > 1480 || count < 4)
    return;

  // Copy accepted input into a packet buffer owned by the receive callback
  struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, count, PBUF_RAM);
  if (!p)
    return;
  pbuf_take(p, bytes, count);

  // Hand the encrypted packet and sender address to wireguard-lwip
  ip_addr_t ip;
  ip.addr = sa.sin_addr.s_addr;
  ++rx_packets;
  socket_pcb->recv(socket_pcb->recv_arg, socket_pcb, p, &ip,
                   ntohs(sa.sin_port));
}

/* Send plaintext through WireGuard without consuming the buffer */
err_t wg_output(struct pbuf *packet, const ip4_addr_t *destination)
{
  // Delegate encryption and peer lookup without taking packet ownership
  return iface.output(&iface, packet, destination);
}

/* Release native resources and erase the WireGuard interface state */
void wg_close(void)
{
  // Report transport totals and release the native UDP socket
  fprintf(stderr, "WG_STOP udp_sent=%lu udp_received=%lu\n", tx_packets,
          rx_packets);
  if (socket_pcb)
    udp_remove(socket_pcb);

  // Erase protocol secrets and release the remaining native resources
  if (iface.state) {
    crypto_zero(iface.state, sizeof(struct wireguard_device));
    free(iface.state);
  }
  close(random_fd);
}
