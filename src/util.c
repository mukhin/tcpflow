#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include <pcap.h>

#include "tcpflow.h"

extern int debug_level;

static char *debug_prefix = NULL;

#define BUFSIZE 1024


/*************************************************************************/


/* Simple wrapper around the malloc() function */
void *check_malloc(int size)
{
  void *ptr;

  if ((ptr = malloc(size)) == NULL) {
    debug(0, "Malloc failed - out of memory?");
    exit(1);
  }
  return ptr;
}


/*
 * Remember our program name and process ID so we can use them later
 * for printing debug messages
 */
void init_debug(char *argv[])
{
  debug_prefix = MALLOC(char, strlen(argv[0]) + 16);
  sprintf(debug_prefix, "%s[%d]", argv[0], getpid());
}


/*
 * Print a debugging or informational message
 */
void debug(int message_level, char *fmt, ...)
{
  va_list ap;
  char message[BUFSIZE];

  if (message_level > debug_level)
    return;

  /* resolve var-arg buffer */
  va_start(ap, fmt);
  vsnprintf(message, BUFSIZE-1, fmt, ap);
  message[BUFSIZE-1] = '\0';

  /* put it together and print */
  fprintf(stderr, "%s: %s\n", debug_prefix, message);
  (void) fflush(stderr);

  va_end(ap);
}
  

/* Print an error message and then exit */
void die(char *fmt, ...)
{
  va_list ap;
  char message[BUFSIZE];
  
  /* resolve var-arg buffer */
  va_start(ap, fmt);
  vsnprintf(message, BUFSIZE-1, fmt, ap);
  message[BUFSIZE-1] = '\0';

  /* put it together and print */
  fprintf(stderr, "%s: %s\n", debug_prefix, message);
  (void) fflush(stderr);

  exit(1);
}


/* Copy argv into a newly malloced buffer.  Arguments are concatenated
 * with spaces in between each argument. */
char *copy_argv(char *argv[])
{
  char **arg;
  char *buf;
  int total_length = 0;

  for (arg = argv; *arg != NULL; arg++)
    total_length += (strlen(*arg) + 1); /* length of arg plus space */

  if (total_length == 0)
    return NULL;

  total_length++; /* add room for a null */

  buf = MALLOC(char, total_length);

  *buf = 0;
  for (arg = argv; *arg != NULL; arg++) {
    strcat(buf, *arg);
    strcat(buf, " ");
  }

  return buf;
}


char *socket_filename(u_int32_t src, u_int16_t sport, u_int32_t dst,
		      u_int16_t dport)
{
#define RING_SIZE 6

  static char ring_buffer[RING_SIZE][32];
  static int ring_pos = 0;

  ring_pos = (ring_pos + 1) % RING_SIZE;

  sprintf(ring_buffer[ring_pos],
	  "%03d.%03d.%03d.%03d.%05d-%03d.%03d.%03d.%03d.%05d",
	  (u_int8_t) ((src & 0xff000000) >> 24),
	  (u_int8_t) ((src & 0x00ff0000) >> 16),
	  (u_int8_t) ((src & 0x0000ff00) >> 8),
	  (u_int8_t)  (src & 0x000000ff),
	  sport,
	  (u_int8_t) ((dst & 0xff000000) >> 24),
	  (u_int8_t) ((dst & 0x00ff0000) >> 16),
	  (u_int8_t) ((dst & 0x0000ff00) >> 8),
	  (u_int8_t)  (dst & 0x000000ff),
	  dport);

  return ring_buffer[ring_pos];
}

  
