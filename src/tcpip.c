#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#ifndef __USE_BSD
#define __USE_BSD
#endif

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <pcap.h>

#include "tcpflow.h"

/* This is called when we receive an IP datagram.  We make sure that
 * it's valid and contains a TCP segment; if so, we pass it to
 * process_tcp() for further processing.
 *
 * Note: we currently don't know how to handle IP fragments. */
void process_ip(const char *packet, int caplen)
{
  const struct ip *ip_header = (struct ip *) packet;
  u_int ip_header_len;
  u_int ip_total_len;

  /* make sure that the packet is at least as long as the min IP header */
  if (caplen < sizeof(struct ip)) {
    debug(5, "received truncated IP datagram!");
    return;
  }

  /* for now we're only looking for TCP; throw away everything else */
  if (ip_header->ip_p != IPPROTO_TCP)
    return;

  /* check and see if we got everything.  NOTE: we must use
   * ip_total_len after this, because we may have captured bytes
   * beyond the end of the packet (e.g. ethernet padding). */
  ip_total_len = ntohs(ip_header->ip_len);
  if (caplen < ip_total_len) {
    debug(5, "warning: captured only %d bytes of %d-byte IP datagram",
	 caplen, ip_total_len);
  }

  /* XXX - throw away everything but fragment 0; this version doesn't
   * know how to do fragment reassembly. */
  if (ntohs(ip_header->ip_off) & 0x1fff) {
    debug(1, "warning: throwing away IP fragment from X to X");
    return;
  }

  /* figure out where the IP header ends */
  ip_header_len = ip_header->ip_hl * 4;

  /* make sure there's some data */
  if (ip_header_len > ip_total_len) {
    debug(5, "received truncated IP datagram!");
    return;
  }

  /* do TCP processing */
  process_tcp(packet + ip_header_len, ip_total_len - ip_header_len,
	      ntohl(ip_header->ip_src.s_addr),
	      ntohl(ip_header->ip_dst.s_addr));
}


void process_tcp(const char *packet, int length, u_int32_t src, u_int32_t dst)
{
  struct tcphdr *tcp_header = (struct tcphdr *) packet;
  flow_t this_flow;
  u_int tcp_header_len;

  u_int32_t seq;

  if (length < sizeof(struct tcphdr)) {
    debug(5, "received truncated TCP segment!");
    return;
  }

  /* calculate the total length of the TCP header including options */
  tcp_header_len = tcp_header->th_off * 4;

  /* return if this packet doesn't have any data (e.g., just an ACK) */
  if (length <= tcp_header_len)
    return;


  this_flow.src = src;
  this_flow.dst = dst;
  this_flow.sport = ntohs(tcp_header->th_sport);
  this_flow.dport = ntohs(tcp_header->th_dport);
  seq = ntohl(tcp_header->th_seq);

  packet += tcp_header_len;
  length -= tcp_header_len;

  printf("%s: %d\n", socket_filename(this_flow), HASH_FLOW(this_flow));
#if 0
  printf("%s: ", socket_filename(this_flow));
  while (length) {
    if (isprint(*packet) || *packet == '\n' || *packet == '\r')
      putchar(*packet);
    else
      putchar('.');
    length--;
    packet++;
  }
  putchar('\n');
#endif

}
