/*
 * This file is part of tcpflow by Jeremy Elson <jelson@circlemud.org>
 * Initial Release: 7 April 1999.
 *
 * This source code is under the GNU Public License (GPL).  See
 * LICENSE for details.
 *
 * $Id$
 *
 * $Log$
 * Revision 1.8  1999/04/14 17:59:59  jelson
 * now correctly checking the return value of fwrite
 *
 * Revision 1.7  1999/04/14 03:02:39  jelson
 * added typecasts for portability
 *
 * Revision 1.6  1999/04/13 23:17:56  jelson
 * More portability fixes.  All system header files now conditionally
 * included from sysdep.h.
 *
 * Integrated patch from Johnny Tevessen <j.tevessen@gmx.net> for Linux
 * systems still using libc5.
 *
 * Revision 1.5  1999/04/13 01:38:15  jelson
 * Added portability features with 'automake' and 'autoconf'.  Added AUTHORS,
 * NEWS, README, etc files (currently empty) to conform to GNU standards.
 *
 * Various portability fixes, including the FGETPOS/FSETPOS macros; detection
 * of header files using autoconf; restructuring of debugging code to not
 * need vsnprintf.
 *
 */

static char *cvsid = "$Id$";

#include "tcpflow.h"

extern int console_only;
extern int bytes_per_flow;
extern int strip_nonprint;

/*************************************************************************/


/* This is called when we receive an IP datagram.  We make sure that
 * it's valid and contains a TCP segment; if so, we pass it to
 * process_tcp() for further processing.
 *
 * Note: we currently don't know how to handle IP fragments. */
void process_ip(const char *data, u_int32_t caplen)
{
  const struct ip *ip_header = (struct ip *) data;
  u_int ip_header_len;
  u_int ip_total_len;

  /* make sure that the packet is at least as long as the min IP header */
  if (caplen < sizeof(struct ip)) {
    DEBUG(6) ("received truncated IP datagram!");
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
    DEBUG(6) ("warning: captured only %ld bytes of %ld-byte IP datagram",
	 (long) caplen, (long) ip_total_len);
  }

  /* XXX - throw away everything but fragment 0; this version doesn't
   * know how to do fragment reassembly. */
  if (ntohs(ip_header->ip_off) & 0x1fff) {
    DEBUG(2) ("warning: throwing away IP fragment from X to X");
    return;
  }

  /* figure out where the IP header ends */
  ip_header_len = ip_header->ip_hl * 4;

  /* make sure there's some data */
  if (ip_header_len > ip_total_len) {
    DEBUG(6) ("received truncated IP datagram!");
    return;
  }

  /* do TCP processing */
  process_tcp(data + ip_header_len, ip_total_len - ip_header_len,
	      ntohl(ip_header->ip_src.s_addr),
	      ntohl(ip_header->ip_dst.s_addr));
}


void process_tcp(const char *data, u_int32_t length, u_int32_t src,
		 u_int32_t dst)
{
  struct tcphdr *tcp_header = (struct tcphdr *) data;
  flow_t this_flow;
  u_int tcp_header_len;
  tcp_seq seq;

  if (length < sizeof(struct tcphdr)) {
    DEBUG(6) ("received truncated TCP segment!");
    return;
  }

  /* calculate the total length of the TCP header including options */
  tcp_header_len = tcp_header->th_off * 4;

  /* return if this packet doesn't have any data (e.g., just an ACK) */
  if (length <= tcp_header_len)
    return;

  /* fill in the flow_t structure with info that identifies this flow */
  this_flow.src = src;
  this_flow.dst = dst;
  this_flow.sport = ntohs(tcp_header->th_sport);
  this_flow.dport = ntohs(tcp_header->th_dport);
  seq = ntohl(tcp_header->th_seq);

  /* recalculate the beginning of data and its length, moving past the
   * TCP header */
  data += tcp_header_len;
  length -= tcp_header_len;

  /* strip nonprintable characters if necessary */
  if (strip_nonprint)
    data = do_strip_nonprint(data, length);

  /* store or print the output */
  if (console_only) {
    print_packet(this_flow, data, length);
  } else {
    store_packet(this_flow, data, length, seq);
  }
}


/* convert all non-printable characters to '.' (period).  not
 * thread-safe, obviously, but neither is most of the rest of this. */
char *do_strip_nonprint(const char *data, u_int32_t length)
{
  static char buf[SNAPLEN];
  char *write_ptr;

  write_ptr = buf;
  while (length) {
    if (isprint(*data) || (*data == '\n') || (*data == '\r'))
      *write_ptr = *data;
    else
      *write_ptr = '.';
    write_ptr++;
    data++;
    length--;
  }

  return buf;
}


/* print the contents of this packet to the console */
void print_packet(flow_t flow, const char *data, u_int32_t length)
{
  printf("%s: ", flow_filename(flow));
  fwrite(data, length, 1, stdout);
  putchar('\n');
}


/* store the contents of this packet to its place in its file */
void store_packet(flow_t flow, const char *data, u_int32_t length,
		  u_int32_t seq)
{
  flow_state_t *state;
  tcp_seq offset;
  fpos_t fpos;

  /* see if we have state about this flow; if not, create it */
  if ((state = find_flow_state(flow)) == NULL) {
    state = create_flow_state(flow, seq);
  }

  /* if we're done collecting for this flow, return now */
  if (IS_SET(state->flags, FLOW_FINISHED))
    return;

  /* calculate the offset into this flow -- should handle seq num
   * wrapping correctly because tcp_seq is the right size */
  offset = seq - state->isn;

  /* I want to guard against receiving a packet with a sequence number
   * slightly less than what we consider the ISN to be; the max
   * (though admittedly non-scaled) window of 64K should be enough */
  if (offset >= 0xffff0000) {
    DEBUG(2) ("dropped packet with seq < isn on %s", flow_filename(flow));
    return;
  }

  /* reject this packet if it falls entirely outside of the range of
   * bytes we want to receive for the flow */
  if (bytes_per_flow && (offset > bytes_per_flow))
    return;

  /* if we don't have a file open for this flow, try to open it.
   * return if the open fails.  Note that we don't have to explicitly
   * save the return value because open_file() puts the file pointer
   * into the structure for us. */
  if (state->fp == NULL) {
    if (open_file(state) == NULL) {
      return;
    }
  }

  /* We are go for launch!  Everything's ready for us to do a write. */

  /* reduce length if it goes beyond the number of bytes per flow */
  if (bytes_per_flow && (offset + length > bytes_per_flow)) {
    SET_BIT(state->flags, FLOW_FINISHED);
    length = bytes_per_flow - offset;
  }

  /* if we're not at the correct point in the file, seek there */
  if (offset != state->pos) {
    fpos = offset;
    FSETPOS(state->fp, &fpos);
  }

  /* write the data into the file */
  DEBUG(11) ("%s: writing %ld bytes @%ld", flow_filename(state->flow),
	  (long) length, (long) offset);

  if (fwrite(data, length, 1, state->fp) < length) {
    /* sigh... this should be a nice, plain DEBUG statement that
     * passes strerrror() as an argument, but SunOS 4.1.3 doesn't seem
     * to have strerror. */
    if (debug_level >= 1) {
      DEBUG(1) ("write to %s failed: ", flow_filename(state->flow));
      perror("");
    }
  }
  fflush(state->fp);

  /* remember the position for next time */
  state->pos = offset + length;

  if (IS_SET(state->flags, FLOW_FINISHED)) {
    DEBUG(5) ("%s: stopping capture", flow_filename(state->flow));
    close_file(state);
  }
}
