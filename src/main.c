#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/time.h>

#include <pcap.h>

#include "tcpflow.h"

int debug_level = DEFAULT_DEBUG_LEVEL;
int no_promisc = 0;
char error[PCAP_ERRBUF_SIZE];



int main(int argc, char *argv[])
{
  extern int optind;
  extern int opterr;
  extern int optopt;
  extern char *optarg;
  int arg;

  char *device = NULL;
  char *expression = NULL;
  pcap_t *pd;
  struct bpf_program fcode;
  pcap_handler handler;

  init_debug(argv);

  opterr = 0;

  while ((arg = getopt(argc, argv, "pi:d:v")) != EOF) {
    switch (arg) {
    case 'p':
      no_promisc = 1;
      break;
    case 'i':
      device = optarg;
      break;
    case 'd':
      if ((debug_level = atoi(optarg)) <= 0) {
	debug_level = 0;
	debug(0, "warning: -d flag with 0 debug level '%s'", optarg);
      }
      break;
    case 'v':
      debug_level = 5;
      break;
    default:
      debug(1, "warning: unrecognized switch '%c'", optopt);
      break;
    }
  }

  /* if the user didn't specify a device, try to find a reasonable one */
  if (device == NULL)
    if ((device = pcap_lookupdev(error)) == NULL)
      die(error);

  /* make sure we can open the device */
  if ((pd = pcap_open_live(device, SNAPLEN, !no_promisc, 5000, error)) == NULL)
    die(error);

  /* drop root privileges - we don't need them any more */
  setuid(getuid());

  /* get the handler for this network interface */
  handler = find_handler(pcap_datalink(pd), device);

  /* get the user's expression out of argv */
  expression = copy_argv(&argv[optind]);

  /* add to it that we only want IP datagrams */
  if (expression == NULL) {
    expression = "ip";
  } else {
    char *new_expression = MALLOC(char, strlen(expression) + 30);
    sprintf(new_expression, "(ip) and (%s)", expression);
    free(expression);
    expression = new_expression;
  }

  debug(10, "filter expression: '%s'", expression);

  /* install the filter expression in BPF */
  if (pcap_compile(pd, &fcode, expression, 1, 0) < 0)
    die(pcap_geterr(pd));

  if (pcap_setfilter(pd, &fcode) < 0)
    die(pcap_geterr(pd));

  /* start listening! */
  debug(1, "listening on %s", device);
  if (pcap_loop(pd, -1, handler, NULL) < 0)
    die(pcap_geterr(pd));

  /* NOTREACHED */
  return 0;
}
