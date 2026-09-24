// PPP-to-WireGuard packet adapter; lwIP owns framing and negotiation
#define _POSIX_C_SOURCE 200809L
#include "platform.h"
#include "crypto.h"
#include "lwip/init.h"
#include "lwip/ip4.h"
#include "lwip/inet_chksum.h"
#include "lwip/sys.h"
#include "netif/ppp/pppos.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

static struct netif ppp_if;
static ppp_pcb *ppp;
static ip4_addr_t host_ip, peer_ip;
static volatile sig_atomic_t stopping;
static int ready, ever_ready, disconnected, output_failed;
static unsigned sessions;

// --- Process helpers ---

/* Report an unrecoverable adapter error and terminate the process */
static void die(const char *message)
{
  // Report the failure on the diagnostic channel and stop the process
  fprintf(stderr, "PPP_FAIL: %s\n", message);
  exit(1);
}

/* Request shutdown without doing non-signal-safe work in the handler */
static void on_signal(int sig)
{
  // Let the event loop perform shutdown outside the signal handler
  (void)sig;
  stopping = 1;
}

// --- lwIP PPP callbacks ---

/* Write lwIP PPP frames to stdout and return the number of bytes sent */
static u32_t serial_output(ppp_pcb *pcb, const void *data, u32_t len, void *ctx)
{
  // Write the complete frame, retrying interrupted and partial writes
  (void)pcb;
  (void)ctx;
  const uint8_t *p = data;
  u32_t sent = 0;
  while (sent < len) {
    ssize_t n = write(STDOUT_FILENO, p + sent, len - sent);
    if (n < 0 && errno == EINTR)
      continue;
    // Defer output failure handling to the event loop
    if (n <= 0) {
      output_failed = 1;
      break;
    }
    sent += n;
  }
  return sent;
}

/* Update forwarding state when lwIP reports PPP link success or failure */
static void status_changed(ppp_pcb *pcb, int code, void *ctx)
{
  // Record whether IPCP opened successfully or the link terminated
  (void)pcb;
  (void)ctx;
  ready = code == PPPERR_NONE;
  if (ready) {
    ever_ready = 1;
    ++sessions;
    fprintf(stderr, "PPP_READY backend=lwip session=%u\n", sessions);
  } else {
    fprintf(stderr, "PPP_DOWN reason=%d\n", code);
    disconnected = 1;
  }
}

/* Suspend forwarding during PPP negotiation and report phase changes */
static void phase_changed(ppp_pcb *pcb, u8_t phase, void *ctx)
{
  // During renegotiation, stop forwarding until IPCP is open again
  (void)pcb;
  (void)ctx;
  if (phase != PPP_PHASE_RUNNING)
    ready = 0;
  fprintf(stderr, "PPP_PHASE %u\n", phase);
}

// --- Packet validation and lwIP IPv4 input hook ---

/* Validate IPv4 headers and addresses, then trim tunnel padding */
static int valid_packet(struct pbuf *p, const ip4_addr_t *src,
                        const ip4_addr_t *dst)
{
  // Read the fixed header, including when it spans chained buffers
  uint8_t header[60];
  if (p->tot_len < 20 || pbuf_copy_partial(p, header, 20, 0) != 20)
    return 0;

  // Check packet size and the configured source/destination address pair
  size_t hlen = (header[0] & 15) * 4;
  size_t len = ((unsigned)header[2] << 8) | header[3];
  if ((header[0] >> 4) != 4 || hlen < 20 || len < hlen || len > PPP_MRU ||
      len > p->tot_len || memcmp(header + 12, &src->addr, 4) ||
      memcmp(header + 16, &dst->addr, 4))
    return 0;

  // Verify the full header checksum before discarding tunnel padding
  if (pbuf_copy_partial(p, header, hlen, 0) != hlen ||
      inet_chksum(header, hlen))
    return 0;
  pbuf_realloc(p, len);
  return 1;
}

/* Forward plaintext between PPP and WireGuard, consuming the buffer */
err_t ip4_input(struct pbuf *p, struct netif *input)
{
  // Forward validated plaintext only while PPP is open, without an IP hop
  if (ready) {
    if (input == &ppp_if) {
      if (valid_packet(p, &host_ip, &peer_ip))
        wg_output(p, &peer_ip);
    } else {
      if (valid_packet(p, &peer_ip, &host_ip))
        ppp_if.output(&ppp_if, p, &host_ip);
    }
  }

  // Both upstream libraries transfer ownership of the input buffer here
  pbuf_free(p);
  return ERR_OK;
}

// --- Process lifecycle and event loop ---

/* Configure the endpoints and run the event loop until PPP shuts down */
int main(int argc, char **argv)
{
  // Load the configuration and the two ends of the local PPP link
  if (argc != 2)
    die("usage: wg-ppp wireguard.conf");
  struct options options;
  if (config_read(argv[1], &options))
    return 1;
  ip4addr_aton(options.local_ip, &host_ip);
  ip4addr_aton(options.peer_ip, &peer_ip);

  // Keep diagnostics separate from PPP and defer signals to the event loop
  setvbuf(stderr, NULL, _IONBF, 0);
  signal(SIGTERM, on_signal);
  signal(SIGINT, on_signal);
  signal(SIGHUP, on_signal);
  signal(SIGPIPE, SIG_IGN);

  // Initialize WireGuard and register the PPP serial/status callbacks
  lwip_init();
  wg_init(&options);
  crypto_zero(options.private_key, sizeof(options.private_key));
  ppp = pppos_create(&ppp_if, serial_output, status_changed, NULL);
  if (!ppp)
    die("pppos_create");
  ppp_set_notify_phase_callback(ppp, phase_changed);

  // From the adapter's end of the PTY, 'our' address is the remote tunnel
  // peer; 'his' address belongs to the host's pppd interface.
  ppp_set_ipcp_ouraddr(ppp, &peer_ip);
  ppp_set_ipcp_hisaddr(ppp, &host_ip);
  ppp->ipcp_wantoptions.accept_local = 0;
  ppp->ipcp_wantoptions.accept_remote = 0;

  // Start PPP negotiation and track startup and shutdown deadlines
  if (ppp_listen(ppp) != ERR_OK)
    die("ppp_listen");
  fprintf(stderr, "PPP_BACKEND lwip\n");
  uint32_t started = sys_now();
  uint32_t close_started = 0;
  int closing = 0, eof = 0;
  for (;;) {
    // Enforce startup limits and allow a bounded graceful PPP shutdown
    uint32_t now = sys_now();
    if (!ever_ready && !closing && now - started > 30000)
      die("PPP negotiation timed out");
    if ((stopping || eof || output_failed) && !closing) {
      closing = 1;
      close_started = now;
      ppp_close(ppp, eof || output_failed);
    }
    if (disconnected || (closing && now - close_started > 4000))
      break;

    // Service library timers, then wait briefly for either input transport
    wg_tick();
    fd_set fds;
    FD_ZERO(&fds);
    if (!eof)
      FD_SET(STDIN_FILENO, &fds);
    FD_SET(wg_fd(), &fds);
    struct timeval timeout = {0, 100000};
    int r = select(wg_fd() + 1, &fds, NULL, NULL, &timeout);
    if (r < 0) {
      if (errno == EINTR)
        continue;
      die("select");
    }

    // Deliver encrypted datagrams to WireGuard and serial frames to PPP
    if (r > 0 && FD_ISSET(wg_fd(), &fds))
      wg_receive();
    if (r > 0 && !eof && FD_ISSET(STDIN_FILENO, &fds)) {
      uint8_t bytes[2048];
      ssize_t n = read(STDIN_FILENO, bytes, sizeof(bytes));
      if (n < 0 && errno == EINTR)
        continue;
      if (n <= 0)
        eof = 1;
      else
        pppos_input(ppp, bytes, n);
    }
  }

  // Release both endpoints, forcing carrier loss if graceful close expired
  if (ppp->phase != PPP_PHASE_DEAD)
    ppp_close(ppp, 1);
  if (ppp_free(ppp) != ERR_OK)
    die("ppp_free");
  wg_close();
  fprintf(stderr, "PPP_STOP backend=lwip sessions=%u\n", sessions);
  return ever_ready ? 0 : 1;
}
