
static int max_fds;
static int curr_fds;
static int next_slot;
static flow_state_t *fd_ring;
static flow_state_t *flow_hash[HASH_SIZE];

void init_fd_ring()
{
  int i;

  /* Find out how many files we can have open safely...subtract 3 for
   * stdin, stdout, stderr */
  max_fds = get_max_fds() - 3;

  fd_ring = MALLOC(fd_ring, max_fds);

  for (i = 0; i < max_fds; i++)
    fd_ring[i] = NULL;

  for (i = 0; i < HASH_SIZE; i++)
    flow_hash[i] = NULL;

  curr_fds = 0;
  next_slot = 0;
}



