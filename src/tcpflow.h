/**************************** Constants ***********************************/

#define DEFAULT_DEBUG_LEVEL 1
#define MAX_FD_GUESS        64
#define HASH_SIZE           919
#define SNAPLEN             65536


/**************************** Structures **********************************/

typedef struct {
  u_int32_t src;		/* Source IP address */
  u_int32_t dst;		/* Destination IP address */
  u_int8_t sport;		/* Source port number */
  u_int8_t dport;		/* Destination port number */
} flow_t;


typedef struct {
  flow_t flow;			/* Description of this flow */
  u_int32_t isn;		/* Initial sequence number we've seen */
  FILE *fp;			/* Pointer to file storing this flow's data */
  fpos_t pos;			/* Current write position in fp */
} flow_state_t;

  
/***************************** Macros *************************************/

#define MALLOC(type, num)  (type *) check_malloc((num) * sizeof(type))

#define HASH_FLOW(flow) ( \
( (flow.sport & 0xff) | ((flow.dport & 0xff) << 8) | \
  ((flow.src & 0xff) << 16) | ((flow.dst & 0xff) << 24) \
) % HASH_SIZE)



/************************* Function prototypes ****************************/

/* util.c */

char *copy_argv(char *argv[]);
void init_debug(char *argv[]);
void *check_malloc(int size);
char *socket_filename(flow_t flow);
void debug(int message_level, char *fmt, ...)
                __attribute__ ((format (printf, 2, 3)));
void die(char *fmt, ...)
                __attribute__ ((format (printf, 1, 2)));

/* datalink.c */
pcap_handler find_handler(int datalink_type, char *device);

/* tcpip.c */
void process_ip(const char *packet, int length);
void process_tcp(const char *packet, int length, u_int32_t src, u_int32_t dst);
