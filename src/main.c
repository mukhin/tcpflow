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
 * Revision 1.11  1999/04/20 19:39:18  jelson
 * changes to fix broken localhost (DLT_NULL) handling
 *
 * Revision 1.10  1999/04/14 22:19:56  jelson
 * cosmetic change to help screen
 *
 * Revision 1.9  1999/04/14 00:20:45  jelson
 * documentation updates, and added -h option to print usage information
 *
 * Revision 1.8  1999/04/13 23:17:55  jelson
 * More portability fixes.  All system header files now conditionally
 * included from sysdep.h.
 *
 * Integrated patch from Johnny Tevessen <j.tevessen@gmx.net> for Linux
 * systems still using libc5.
 *
 * Revision 1.7  1999/04/13 03:17:45  jelson
 * documentation updates
 *
 * Revision 1.6  1999/04/13 01:38:12  jelson
 * Added portability features with 'automake' and 'autoconf'.  Added AUTHORS,
 * NEWS, README, etc files (currently empty) to conform to GNU standards.
 *
 * Various portability fixes, including the FGETPOS/FSETPOS macros; detection
 * of header files using autoconf; restructuring of debugging code to not
 * need vsnprintf.
 *
 */

static char *cvsid = "$Id$";

#define __MAIN_C__

#include "tcpflow.h"


int debug_level = DEFAULT_DEBUG_LEVEL;
int no_promisc = 0;
int bytes_per_flow = 0;
int max_flows = 0;
int max_desired_fds = 0;
int console_only = 0;
int strip_nonprint = 0;

char error[PCAP_ERRBUF_SIZE];


void print_usage(char *progname)
{
  fprintf(stderr, "%s version %s by Jeremy Elson <jelson@circlemud.org>\n\n",
		 PACKAGE, VERSION);
  fprintf(stderr, "usage: %s [-chpsv] [-b max_bytes] [-d debug_level] [-f max_fds]\n", progname);
  fprintf(stderr, "          [-i iface] [expression]\n\n");
  fprintf(stderr, "        -b: max number of bytes per flow to save\n");
  fprintf(stderr, "        -c: console print only (don't create files)\n");
  fprintf(stderr, "        -d: debug level; default is %d\n", DEFAULT_DEBUG_LEVEL);
  fprintf(stderr, "        -f: maximum number of file descriptors to use\n");
  fprintf(stderr, "        -h: print this help message\n");
  fprintf(stderr, "        -i: network interface on which to listen\n");
  fprintf(stderr, "            (type \"ifconfig -a\" for a list of interfaces)\n");
  fprintf(stderr, "        -p: don't use promiscuous mode\n");
  fprintf(stderr, "        -s: strip non-printable characters (change to '.')\n");
  fprintf(stderr, "        -v: verbose operation equivalent to -d 10\n");
  fprintf(stderr, "expression: tcpdump-like filtering expression\n");
  fprintf(stderr, "\nSee the man page for additional information.\n\n");
}


int main(int argc, char *argv[])
{
  extern int optind;
  extern int opterr;
  extern int optopt;
  extern char *optarg;
  int arg, dlt;
  int need_usage = 0;

  char *device = NULL;
  char *expression = NULL;
  pcap_t *pd;
  struct bpf_program fcode;
  pcap_handler handler;

  init_debug(argv);

  opterr = 0;

  while ((arg = getopt(argc, argv, "b:cd:f:hi:psv")) != EOF) {
    switch (arg) {
    case 'b':
      if ((bytes_per_flow = atoi(optarg)) < 0) {
	DEBUG(1) ("warning: invalid value '%s' used with -b ignored", optarg);
	bytes_per_flow = 0;
      } else {
	DEBUG(10) ("capturing max of %d bytes per flow", bytes_per_flow);
      }
      break;
    case 'c':
      console_only = 1;
      DEBUG(10) ("printing packets to console only");
      /* fall through */
    case 's':
      strip_nonprint = 1;
      DEBUG(10) ("converting non-printable characters to '.'");
      break;
    case 'd':
      if ((debug_level = atoi(optarg)) < 0) {
	debug_level = DEFAULT_DEBUG_LEVEL;
	DEBUG(1) ("warning: -d flag with 0 debug level '%s'", optarg);
      }
      break;
    case 'f':
      if ((max_desired_fds = atoi(optarg)) < (NUM_RESERVED_FDS + 2)) {
	DEBUG(1) ("warning: -f flag must be used with argument >= %d",
		  NUM_RESERVED_FDS + 2);
	max_desired_fds = 0;
      }
      break;
    case 'h':
      print_usage(argv[0]);
      exit(0);
      break;
    case 'i':
      device = optarg;
      break;
    case 'p':
      no_promisc = 1;
      DEBUG(10) ("NOT turning on promiscuous mode");
      break;
    case 'v':
      debug_level = 10;
      DEBUG(10) ("%s version %s by Jeremy Elson <jelson@circlemud.org>",
		 PACKAGE, VERSION);
      break;
    default:
      DEBUG(1) ("error: unrecognized switch '%c'", optopt);
      need_usage = 1;
      break;
    }
  }

  /* print help and exit if there was an error in the arguments */
  if (need_usage) {
    print_usage(argv[0]);
    exit(1);
  }

  /* if the user didn't specify a device, try to find a reasonable one */
  if (device == NULL)
    if ((device = pcap_lookupdev(error)) == NULL)
      die(error);

  /* make sure we can open the device */
  if ((pd = pcap_open_live(device, SNAPLEN, !no_promisc, 1000, error)) == NULL)
    die(error);

  /* drop root privileges - we don't need them any more */
  setuid(getuid());

  /* remember what datalink type the selected network interface is */
  dlt = pcap_datalink(pd);

  /* get the handler for this network interface */
  handler = find_handler(dlt, device);

  /* get the user's expression out of argv */
  expression = copy_argv(&argv[optind]);

  /*
   * add to it that we only want IP datagrams
   *
   * fixed 20 april 1999: adding 'ip' to interfaces of type DLT_NULL *
   * seems to prevent any packets from getting matched.  -JE
   */
  if (dlt != DLT_NULL) {
    if (expression == NULL) {
      expression = "ip";
    } else {
      char *new_expression = MALLOC(char, strlen(expression) + 30);
      sprintf(new_expression, "(ip) and (%s)", expression);
      free(expression);
      expression = new_expression;
    }
  }

  DEBUG(20) ("filter expression: '%s'",
	     expression == NULL ? "<NULL>" : expression);

  /* install the filter expression in libpcap */
  if (pcap_compile(pd, &fcode, expression, 1, 0) < 0)
    die(pcap_geterr(pd));

  if (pcap_setfilter(pd, &fcode) < 0)
    die(pcap_geterr(pd));

  /* initialize our flow state structures */
  init_flow_state();

  /* start listening! */
  DEBUG(1) ("listening on %s", device);
  if (pcap_loop(pd, -1, handler, NULL) < 0)
    die(pcap_geterr(pd));

  /* NOTREACHED */
  return 0;
}
