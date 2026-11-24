// libFuzzer harness for the bundled slirp user-mode TCP/IP stack
// (iodev/network/slirp, a port of libslirp), the stack behind the eth_slirp
// netmod. Every frame the emulated NIC transmits goes to slirp_input(), so the
// input here is what a guest can send: a sequence of Ethernet frames, each
// prefixed by a 16-bit little-endian length (the same format as the vnet
// target), fed to slirp_input() in order. Replies go to send_packet and are
// dropped.
//
// Configured like iodev/network/eth_slirp.cc (10.0.2.0/24, host 10.0.2.2, DNS
// 10.0.2.3, DHCP from 10.0.2.15, IPv6 on), except:
//  * restricted = 1 (the eth_slirp `restricted` option): slirp opens no host
//    sockets for guest UDP/TCP/ICMP traffic (udp.cc, tcp_input.cc, ip_icmp.cc
//    drop it), so no host network is touched;
//  * no TFTP root (tftp_path = NULL, eth_slirp's default with no netif), so
//    no host files are read;
//  * a virtual clock that starts at 0 for every input, so timers and TCP
//    timestamps depend only on the input.
//
// State: a fresh Slirp instance per input (slirp_new ... slirp_cleanup), so
// no ARP/NDP table, DHCP lease or TCP connection carries between inputs.
// slirp's logger pointer (slirp.cc slirplog) is never set, as eth_slirp does
// only with a `pktlog` option; the stubs below satisfy the linker.
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <arpa/inet.h>
#include "bochs.h"
#include "iodev/network/slirp/libslirp.h"

// Only referenced from slirplog_error()/slirplog_debug() through a pointer
// that stays NULL (the slirp objects are built without UBSan vptr, which would
// otherwise also need logfunctions' typeinfo from the emulator's logio.cc).
void logfunctions::error(const char *fmt, ...) {}
void logfunctions::ldebug(const char *fmt, ...) {}

static int64_t vclock_ns;

static slirp_ssize_t send_packet(const void *buf, size_t len, void *opaque)
{
  return (slirp_ssize_t)len;
}
static void guest_error(const char *msg, void *opaque) {}
static int64_t clock_get_ns(void *opaque) { return vclock_ns; }
static void *timer_new_opaque(SlirpTimerId id, void *cb_opaque, void *opaque)
{
  return new int(0);
}
static void timer_free(void *timer, void *opaque) { delete (int *)timer; }
static void timer_mod(void *timer, int64_t expire_time, void *opaque) {}
static void register_poll_socket(slirp_os_socket fd, void *opaque) {}
static void unregister_poll_socket(slirp_os_socket fd, void *opaque) {}
static void notify(void *opaque) {}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  SlirpCb cb;
  memset(&cb, 0, sizeof(cb));
  cb.send_packet = send_packet;
  cb.guest_error = guest_error;
  cb.clock_get_ns = clock_get_ns;
  cb.timer_free = timer_free;
  cb.timer_mod = timer_mod;
  cb.notify = notify;
  cb.timer_new_opaque = timer_new_opaque;
  cb.register_poll_socket = register_poll_socket;
  cb.unregister_poll_socket = unregister_poll_socket;

  SlirpConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.version = SLIRP_CONFIG_VERSION_MAX;
  cfg.restricted = 1;
  cfg.in_enabled = true;
  cfg.vnetwork.s_addr = htonl(0x0a000200);    /* 10.0.2.0 */
  cfg.vnetmask.s_addr = htonl(0xffffff00);    /* 255.255.255.0 */
  cfg.vhost.s_addr = htonl(0x0a000202);       /* 10.0.2.2 */
  cfg.vdhcp_start.s_addr = htonl(0x0a00020f); /* 10.0.2.15 */
  cfg.vnameserver.s_addr = htonl(0x0a000203); /* 10.0.2.3 */
  cfg.tftp_path = NULL;
  cfg.bootfile = "pxelinux.0";
  cfg.vdomainname = "local";
  cfg.in6_enabled = true;
  inet_pton(AF_INET6, "fec0::", &cfg.vprefix_addr6);
  cfg.vprefix_len = 64;
  inet_pton(AF_INET6, "fec0::2", &cfg.vhost6);
  inet_pton(AF_INET6, "fec0::3", &cfg.vnameserver6);

  vclock_ns = 0;
  Slirp *s = slirp_new(&cfg, &cb, NULL);
  if (s == NULL) return 0;

  size_t pos = 0;
  while (pos + 2 <= size) {
    unsigned len = data[pos] | (data[pos + 1] << 8);
    pos += 2;
    if (len > size - pos) len = (unsigned)(size - pos);
    // slirp_input() reads the frame in place: hand it an exact-size copy so
    // ASan sees any read past the frame end.
    uint8_t *pkt = new uint8_t[len ? len : 1];
    memcpy(pkt, data + pos, len);
    slirp_input(s, pkt, (int)len);
    delete[] pkt;
    pos += len;
    vclock_ns += 1000000;  // 1 ms of virtual time per frame
  }
  slirp_cleanup(s);
  return 0;
}
