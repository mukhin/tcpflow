#define DEFAULT_DEBUG_LEVEL 1
#define SNAPLEN             65536
#define MALLOC(type, num)  (type *) check_malloc((num) * sizeof(type))

/***************************************************************************/


/********************* Function prototypes ********************************/

/* util.c */

char *copy_argv(char *argv[]);
void init_debug(char *argv[]);
void *check_malloc(int size);
char *socket_filename(u_int32_t src, u_int16_t sport, u_int32_t dst,
		      u_int16_t dport);
void debug(int message_level, char *fmt, ...)
                __attribute__ ((format (printf, 2, 3)));
void die(char *fmt, ...)
                __attribute__ ((format (printf, 1, 2)));

/* datalink.c */
pcap_handler find_handler(int datalink_type, char *device);

/* tcpip.c */
void process_ip(const char *packet, int length);
void process_tcp(const char *packet, int length, u_int32_t src, u_int32_t dst);
