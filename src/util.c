#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>

#include "tcpflow.h"

static char *debug_prefix = NULL;

#define BUFSIZE 1024


/*************************************************************************/


/* Simple wrapper around the malloc() function */
void *check_malloc(size_t size)
{
  void *ptr;

  if ((ptr = malloc(size)) == NULL) {
    DEBUG(0) ("Malloc failed - out of memory?");
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
void debug_real(char *fmt, ...)
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


#define RING_SIZE 6

char *flow_filename(flow_t flow)
{
  static char ring_buffer[RING_SIZE][32];
  static int ring_pos = 0;

  ring_pos = (ring_pos + 1) % RING_SIZE;

  sprintf(ring_buffer[ring_pos],
	  "%03d.%03d.%03d.%03d.%05d-%03d.%03d.%03d.%03d.%05d",
	  (u_int8_t) ((flow.src & 0xff000000) >> 24),
	  (u_int8_t) ((flow.src & 0x00ff0000) >> 16),
	  (u_int8_t) ((flow.src & 0x0000ff00) >> 8),
	  (u_int8_t)  (flow.src & 0x000000ff),
	  flow.sport,
	  (u_int8_t) ((flow.dst & 0xff000000) >> 24),
	  (u_int8_t) ((flow.dst & 0x00ff0000) >> 16),
	  (u_int8_t) ((flow.dst & 0x0000ff00) >> 8),
	  (u_int8_t)  (flow.dst & 0x000000ff),
	  flow.dport);

  return ring_buffer[ring_pos];
}


/* Try to find the maximum number of FDs this system can have open */
int get_max_fds(void)
{
  int max_descs = 0;
  const char *method;

  /* First, we'll try using getrlimit/setrlimit.  This will probably
   * work on most systems.  HAS_RLIMIT is defined in sysdep.h.  */
#ifdef RLIMIT_NOFILE
  {
    struct rlimit limit;

    method = "rlimit";
    if (getrlimit(RLIMIT_NOFILE, &limit) < 0) {
      perror("calling getrlimit");
      exit(1);
    }

    /* set the current to the maximum */
    limit.rlim_cur = limit.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &limit) < 0) {
      perror("calling setrlimit");
      exit(1);
    }

#ifdef RLIM_INFINITY
    if (limit.rlim_max == RLIM_INFINITY)
      max_descs = MAX_FD_GUESS * 4;
    else
#endif
      max_descs = limit.rlim_max;
  }


  /* rlimit didn't work, but you have OPEN_MAX */
#elif defined (OPEN_MAX)
  method = "OPEN_MAX";
  max_descs = OPEN_MAX;


  /* Okay, you don't have getrlimit() and you don't have OPEN_MAX.
   * Time to try the POSIX sysconf() function.  (See Stevens'
   * _Advanced Programming in the UNIX Environment_).  */
#elif defined (_SC_OPEN_MAX)
  method = "POSIX sysconf";
  errno = 0;
  if ((max_descs = sysconf(_SC_OPEN_MAX)) < 0) {
    if (errno == 0)
      max_descs = MAX_FD_GUESS * 4;
    else {
      perror("calling sysconf");
      exit(1);
    }
  }

  /* if everything has failed, we'll just take a guess */
#else
  method = "random guess";
  max_descs = MAX_FD_GUESS;
#endif

  DEBUG(2) ("found max FDs to be %d using %s", max_descs, method);
  return max_descs;
}
