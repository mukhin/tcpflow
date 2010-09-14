/*
 * This file is part of tcpflow by Jeremy Elson <jelson@circlemud.org>
 * Initial Release: 7 April 1999.
 *
 * This source code is under the GNU Public License (GPL).  See
 * LICENSE for details.
 *
 * Revision 1.9  2001/08/08 19:39:40  jelson
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
 * Revision 1.8  1999/04/14 03:02:39  jelson
 * added typecasts for portability
 *
 * Revision 1.7  1999/04/13 01:38:16  jelson
 * Added portability features with 'automake' and 'autoconf'.  Added AUTHORS,
 * NEWS, README, etc files (currently empty) to conform to GNU standards.
 *
 * Various portability fixes, including the FGETPOS/FSETPOS macros; detection
 * of header files using autoconf; restructuring of debugging code to not
 * need vsnprintf.
 *
 */

#include "tcpflow.h"


static const char* tm_format_string = "%02d:%02d:%02d.%06d ";
static const char* tm_dateformat_string = "%Y-%m-%d %X ";

static char *debug_prefix = NULL;
extern int max_desired_fds;
extern int print_time_per_line;
extern int print_datetime_per_line;

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
  sprintf(debug_prefix, "%s[%d]", argv[0], (int) getpid());
}


/*
 * Print a debugging message, given a va_list
 */
void print_debug_message(char *fmt, va_list ap)
{
  /* print debug prefix */
  fprintf(stderr, "%s: ", debug_prefix);

  /* print the var-arg buffer passed to us */
  vfprintf(stderr, fmt, ap);

  /* add newline */
  fprintf(stderr, "\n");
  (void) fflush(stderr);
}

/* Print a debugging or informational message */
void debug_real(char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  print_debug_message(fmt, ap);
  va_end(ap);
}
  

/* Print a debugging or informatioal message, then exit  */
void die(char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  print_debug_message(fmt, ap);
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
  static char ring_buffer[RING_SIZE][48];
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

#undef RING_SIZE


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

#if defined(__APPLE__)
	if (limit.rlim_max > OPEN_MAX) {
		limit.rlim_max = OPEN_MAX;
	}
#endif

    /* set the current to the maximum or specified value */
    if (max_desired_fds)
      limit.rlim_cur = max_desired_fds;
    else
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

  /* this must go here, after rlimit code */
  if (max_desired_fds) {
    DEBUG(10) ("using only %d FDs", max_desired_fds);
    return max_desired_fds;
  }

  DEBUG(10) ("found max FDs to be %d using %s", max_descs, method);
  return max_descs;
}


/* An attempt at making signal() portable.
 *
 * If we detect sigaction, use that; 
 * otherwise if we have setsig, use that;
 * otherwise, cross our fingers and hope for the best using plain old signal().
 *
 * Our first choice is sigaction (sigaction() is POSIX; signal() is
 * not.)  Taken from Stevens' _Advanced Programming in the UNIX
 * Environment_.
 */
RETSIGTYPE (*portable_signal(int signo, RETSIGTYPE (*func)(int)))(int)
{
#if defined(HAVE_SIGACTION)
  struct sigaction act, oact;

  memset(&act, 0, sizeof(act));
  memset(&oact, 0, sizeof(oact));
  act.sa_handler = func;
  sigemptyset(&act.sa_mask);
  act.sa_flags = 0;

  if (sigaction(signo, &act, &oact) < 0)
    return (SIG_ERR);

  return (oact.sa_handler);
#elif defined(HAVE_SIGSET)
  return sigset(signo, func);
#else
  return signal(signo, func);
#endif /* HAVE_SIGACTION, HAVE_SIGSET */
}

void format_timestamp(char* tm_buffer, int tm_buffer_length, struct timeval* tv, int f_datetime) {
  if (tv->tv_sec == 0 && tv->tv_usec == 0) {
    gettimeofday(tv, NULL);
  }
  struct tm time_ = *localtime(&tv->tv_sec);
  if (f_datetime) {
    strftime(tm_buffer, tm_buffer_length, tm_dateformat_string, &time_);
  }
  else {
    sprintf(tm_buffer, tm_format_string, time_.tm_hour, time_.tm_min, time_.tm_sec, (int)tv->tv_usec);
  }
}


