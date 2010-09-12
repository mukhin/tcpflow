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
 * Revision 1.15  2003/08/07 07:35:24  jelson
 * fixed format string attack
 *
 * Revision 1.14  2001/08/08 19:39:40  jelson
 * ARGH!  These are changes that made up tcpflow 0.20, which for some reason I
 * did not check into the repository until now.  (Which of couse means
 * I never tagged v0.20.... argh.)
 *
 * Changes include:
 *
 *   -- portable signal handlers now used to do proper termination
 *
 *   -- patch to allow tcpflow to read from tcpdump stored captures
 *
 * Revision 1.13  2001/02/26 23:01:30  jelson
 * Added patch for -r option
 *
 * Revision 1.12  1999/04/21 01:40:14  jelson
 * DLT_NULL fixes, u_char fixes, additions to configure.in, man page update
 *
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
int print_time_per_line = 0;
int print_datetime_per_line = 0;
int strip_nr = 0;

char error[PCAP_ERRBUF_SIZE];


void print_usage(char *progname)
{
  fprintf(stderr, "%s version %s by Jeremy Elson <jelson@circlemud.org> "
	"(patched by Andrey Mukhin <a.mukhin77@gmail.com>)\n\n",
	PACKAGE, VERSION);
  fprintf(stderr, "usage: %s [-chpsvto] [-b max_bytes] [-d debug_level] [-f max_fds]\n", progname);
  fprintf(stderr, "          [-i iface] [-w file] [expression]\n\n");
  fprintf(stderr, "        -b: max number of bytes per flow to save\n");
  fprintf(stderr, "        -c: console print only (don't create files)\n");
  fprintf(stderr, "        -d: debug level; default is %d\n", DEFAULT_DEBUG_LEVEL);
  fprintf(stderr, "        -f: maximum number of file descriptors to use\n");
  fprintf(stderr, "        -h: print this help message\n");
  fprintf(stderr, "        -i: network interface on which to listen\n");
  fprintf(stderr, "            (type \"ifconfig -a\" for a list of interfaces)\n");
  fprintf(stderr, "        -p: don't use promiscuous mode\n");
  fprintf(stderr, "        -r: read packets from tcpdump output file\n");
  fprintf(stderr, "        -s: strip non-printable characters (change to '.')\n");
  fprintf(stderr, "        -v: verbose operation equivalent to -d 10\n");
  fprintf(stderr, "        -t: add time to the output\n");
  fprintf(stderr, "        -x: add date & time to the output\n");
  fprintf(stderr, "        -o: strip end-of-line characters (change to '.')\n");
  fprintf(stderr, "expression: tcpdump-like filtering expression\n");
  fprintf(stderr, "\nSee the man page for additional information.\n\n");
}


RETSIGTYPE terminate(int sig)
{
  DEBUG(1) ("terminating");
  exit(0); /* libpcap uses onexit to clean up */
}


int main(int argc, char *argv[])
{
  extern int optind;
  extern int opterr;
  extern int optopt;
  extern char *optarg;
  int arg, dlt, user_expression = 0;
  int need_usage = 0;

  char *device = NULL;
  char *infile = NULL;
  char *expression = NULL;
  pcap_t *pd;
  struct bpf_program fcode;
  pcap_handler handler;

  init_debug(argv);

  opterr = 0;

  while ((arg = getopt(argc, argv, "b:cd:f:hi:pr:svtxo")) != EOF) {
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
    case 't':
      print_time_per_line = 1;
      DEBUG(10) ("add the time to the output");
      break;
    case 'x':
      print_datetime_per_line = 1;
      DEBUG(10) ("add date & time to the output");
      break;
    case 'o':
        strip_nr = 1;
        DEBUG(10) ("converting  end-of-line  characters to '.'");
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
    case 'r':
      infile = optarg;
      break;
    case 'v':
      debug_level = 10;
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

  /* hello, world */
  DEBUG(10) ("%s version %s by Jeremy Elson <jelson@circlemud.org> "
	"(patched by Andrey Mukhin <a.mukhin77@gmail.com>)",
	PACKAGE, VERSION);

  if (infile != NULL) {
    /* Since we don't need network access, drop root privileges */
    setuid(getuid());

    /* open the capture file */
    if ((pd = pcap_open_offline(infile, error)) == NULL)
      die("%s", error);

    /* get the handler for this kind of packets */
    dlt = pcap_datalink(pd);
    handler = find_handler(dlt, infile);
  } else {
    /* if the user didn't specify a device, try to find a reasonable one */
    if (device == NULL)
      if ((device = pcap_lookupdev(error)) == NULL)
	die("%s", error);

    /* make sure we can open the device */
    if ((pd = pcap_open_live(device, SNAPLEN, !no_promisc, 1000, error)) == NULL)
      die("%s", error);

    /* drop root privileges - we don't need them any more */
    setuid(getuid());

    /* get the handler for this kind of packets */
    dlt = pcap_datalink(pd);
    handler = find_handler(dlt, device);
  }

  /* get the user's expression out of argv */
  expression = copy_argv(&argv[optind]);

  /* add 'ip' to the user-specified filtering expression (if any) to
   * prevent non-ip packets from being delivered. */
  if (expression == NULL) {
    expression = "ip";
    user_expression = 0;
  } else {
    char *new_expression = MALLOC(char, strlen(expression) + 30);
    sprintf(new_expression, "(ip) and (%s)", expression);
    free(expression);
    expression = new_expression;
    user_expression = 1;
  }

  /* If DLT_NULL is "broken", giving *any* expression to the pcap
   * library when we are using a device of type DLT_NULL causes no
   * packets to be delivered.  In this case, we use no expression, and
   * print a warning message if there is a user-specified expression */
#ifdef DLT_NULL_BROKEN
  if (dlt == DLT_NULL && expression != NULL) {
    free(expression);
    expression = NULL;
    if (user_expression) {
      DEBUG(1)("warning: DLT_NULL (loopback device) is broken on your system;");
      DEBUG(1)("         filtering does not work.  Recording *all* packets.");
    }
  }
#endif /* DLT_NULL_BROKEN */

  DEBUG(20) ("filter expression: '%s'",
	     expression == NULL ? "<NULL>" : expression);

  /* install the filter expression in libpcap */
  if (pcap_compile(pd, &fcode, expression, 1, 0) < 0)
    die("%s", pcap_geterr(pd));

  if (pcap_setfilter(pd, &fcode) < 0)
    die("%s", pcap_geterr(pd));

  /* initialize our flow state structures */
  init_flow_state();

  /* set up signal handlers for graceful exit (pcap uses onexit to put
     interface back into non-promiscuous mode */
  portable_signal(SIGTERM, terminate);
  portable_signal(SIGINT, terminate);
  portable_signal(SIGHUP, terminate);

  /* start listening! */
  if (infile == NULL)
    DEBUG(1) ("listening on %s", device);
  if (pcap_loop(pd, -1, handler, NULL) < 0)
    die("%s", pcap_geterr(pd));

  /* NOTREACHED */
  return 0;
}
