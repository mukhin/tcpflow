#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif

#ifndef __USE_BSD
#define __USE_BSD
#endif

#include <sys/types.h>
#include <netinet/tcp.h>
#include <pcap.h>


/****************** Ugly System Dependencies ******************************/

/* We always want to refer to RLIMIT_NOFILE, even if what you actually
 * have is RLIMIT_OFILE */
#ifdef RLIMIT_OFILE
# ifndef RLIMIT_NOFILE
#  define RLIMIT_NOFILE RLIMIT_OFILE
# endif
#endif

/* We always want to refer to OPEN_MAX, even if what you actually have
 * is FOPEN_MAX. */
#ifdef FOPEN_MAX
# ifndef OPEN_MAX
#  define OPEN_MAX FOPEN_MAX
# endif
#endif


/**************************** Constants ***********************************/

#define DEFAULT_DEBUG_LEVEL 1
#define MAX_FD_GUESS        64
#define HASH_SIZE           1009  /* prime number near 1000 */
#define SNAPLEN             65536 /* largest possible MTU we'll see */


/**************************** Structures **********************************/

typedef struct {
  u_int32_t src;		/* Source IP address */
  u_int32_t dst;		/* Destination IP address */
  u_int16_t sport;		/* Source port number */
  u_int16_t dport;		/* Destination port number */
} flow_t;


typedef struct flow_state_struct {
  struct flow_state_struct *next; /* Link to next one */
  flow_t flow;			/* Description of this flow */
  tcp_seq isn;			/* Initial sequence number we've seen */
  FILE *fp;			/* Pointer to file storing this flow's data */
  fpos_t pos;			/* Current write position in fp */
  int flags;			/* Don't save any more data from this flow */
  int last_access;		/* "Time" of last access */
} flow_state_struct;

#define FLOW_FINISHED		(1 << 0)
#define FLOW_FILE_EXISTS	(1 << 1)

typedef struct flow_state_struct flow_state_t;

  
/***************************** Macros *************************************/

#define MALLOC(type, num)  (type *) check_malloc((num) * sizeof(type))

#ifndef __MAIN_C__
extern int debug_level;
#endif

#define DEBUG(message_level) if (debug_level >= message_level) debug_real

#define HASH_FLOW(flow) ( \
( (flow.sport & 0xff) | ((flow.dport & 0xff) << 8) | \
  ((flow.src & 0xff) << 16) | ((flow.dst & 0xff) << 24) \
) % HASH_SIZE)

#define IS_SET(vector, flag) ((vector) & (flag))
#define SET_BIT(vector, flag) ((vector) |= (flag))


/************************* Function prototypes ****************************/

/* util.c */
char *copy_argv(char *argv[]);
void init_debug(char *argv[]);
void *check_malloc(size_t size);
char *flow_filename(flow_t flow);
int get_max_fds(void);
void debug_real(char *fmt, ...)
                __attribute__ ((format (printf, 1, 2)));
void die(char *fmt, ...)
                __attribute__ ((format (printf, 1, 2)));

/* datalink.c */
pcap_handler find_handler(int datalink_type, char *device);

/* tcpip.c */
void process_ip(const char *data, u_int32_t length);
void process_tcp(const char *data, u_int32_t length, u_int32_t src,
		 u_int32_t dst);
void print_packet(flow_t flow, const char *data, u_int32_t length);
void store_packet(flow_t flow, const char *data, u_int32_t length,
		  u_int32_t seq);

/* flow.c */
void init_flow_state();
flow_state_t *find_flow_state(flow_t flow);
flow_state_t *create_flow_state(flow_t flow, tcp_seq isn);
FILE *open_file(flow_state_t *flow_state);
int close_file(flow_state_t *flow_state);
void sort_fds();
void contract_fd_ring();
