// libFuzzer harness for the Bochs built-in virtual network server
// (iodev/network/netutil.cc vnet_server_c), the packet handler behind the
// bxhub UDP hub and the eth_vnet netmod. Set up exactly like misc/bxhub.cc
// main(): default 10.0.2.x addresses, one client. The input is a sequence of
// Ethernet frames, each prefixed by a 16-bit little-endian length; every frame
// goes to handle_packet() and the replies are drained with get_packet(), as
// bxhub does.
//
// State: a fresh vnet_server_c per input (TCP connections, DHCP leases and
// FTP sessions live in it). The TFTP/FTP root is left empty, as bxhub does
// without -tftp=, so no host files are read or written.
#ifndef BXHUB
#define BXHUB
#endif
#include <stdint.h>
#include <stddef.h>
#include "config.h"
#include "misc/bxcompat.h"
#include "osdep.h"
#include "iodev/network/netmod.h"
#include "iodev/network/netutil.h"

int bx_loglev = 0;

static const Bit8u host_mac[6]   = {0xb0, 0xc4, 0x20, 0x00, 0x00, 0x0f};
static const Bit8u client_mac[6] = {0xb0, 0xc4, 0x20, 0x00, 0x00, 0x01};
static const Bit8u net_ip[4] = {10, 0, 2, 0};
static const Bit8u host_ip[4] = {10, 0, 2, 2};
static const Bit8u dns_ip[4] = {10, 0, 2, 3};
static const Bit8u ftp_ip[4] = {10, 0, 2, 4};
static const Bit8u base_ip[4] = {10, 0, 2, 15};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  static Bit8u reply[BX_PACKET_BUFSIZE];
  static Bit8u frame[BX_PACKET_BUFSIZE];
  dhcp_cfg_t dhcp;
  memset(&dhcp, 0, sizeof(dhcp));
  memcpy(dhcp.host_macaddr, host_mac, 6);
  memcpy(dhcp.net_ipv4addr, net_ip, 4);
  memcpy(dhcp.srv_ipv4addr[VNET_SRV], host_ip, 4);
  memcpy(dhcp.srv_ipv4addr[VNET_DNS], dns_ip, 4);
  memcpy(dhcp.srv_ipv4addr[VNET_MISC], ftp_ip, 4);
  memcpy(dhcp.client_base_ipv4addr, base_ip, 4);
  strcpy(dhcp.bootfile, "pxelinux.0");

  vnet_server_c *srv = new vnet_server_c();
  srv->init(NULL, &dhcp, "");
  srv->init_client(0, client_mac, NULL);

  size_t pos = 0;
  while (pos + 2 <= size) {
    unsigned len = data[pos] | (data[pos + 1] << 8);
    pos += 2;
    if (len > size - pos) len = (unsigned)(size - pos);
    if (len > BX_PACKET_BUFSIZE) len = BX_PACKET_BUFSIZE;
    // handle_packet() works on a guest-sized frame buffer, like bxhub's
    // recvfrom() buffer of BX_PACKET_BUFSIZE bytes.
    memcpy(frame, data + pos, len);
    pos += len;
    srv->handle_packet(frame, len);
    while (srv->get_packet(reply) > 0) {}
  }
  delete srv;
  return 0;
}
