#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "tcpflow.h"

static int max_fds;
static int next_slot;
static int current_time;
static flow_state_t **fd_ring;
static flow_state_t *flow_hash[HASH_SIZE];


/* Initialize our structures */
void init_flow_state()
{
  int i;

  /* Find out how many files we can have open safely...subtract 4 for
   * stdin, stdout, stderr, and the packet filter; one for breathing
   * room (we open new files before closing old ones), and one more to
   * be safe. */
  max_fds = get_max_fds() - 5;

  fd_ring = MALLOC(flow_state_t *, max_fds);

  for (i = 0; i < max_fds; i++)
    fd_ring[i] = NULL;

  for (i = 0; i < HASH_SIZE; i++)
    flow_hash[i] = NULL;

  next_slot = -1;
  current_time = 0;
}



/* Create a new flow state structure, initialize its contents, and add
 * it to its hash bucket.  It is prepended to the hash bucket because
 * 1) doing so is fast (requiring constant time regardless of bucket
 * size; and 2) it'll tend to make lookups faster for more recently
 * added state, which will probably be more often used state.
 *
 * Returns a pointer to the new state. */
flow_state_t *create_flow_state(flow_t flow, tcp_seq isn)
{
  /* create space for the new state */
  flow_state_t *new_flow = MALLOC(flow_state_t, 1);

  /* determine where in the hash this goes */
  int index = HASH_FLOW(flow);

  /* link it in to the hash bucket at the beginning */
  new_flow->next = flow_hash[index];
  flow_hash[index] = new_flow;

  /* initialize contents of the state structure */
  new_flow->flow = flow;
  new_flow->isn = isn;
  new_flow->fp = NULL;
  new_flow->pos = 0;
  new_flow->flags = 0;
  new_flow->last_access = current_time++;

  DEBUG(5) ("%s: new flow", flow_filename(flow));

  return new_flow;
}


/* Find previously a previously created flow state structure by
 * jumping to its hash bucket, and linearly searching everything in
 * the bucket.  Returns NULL if the state is not found. */
flow_state_t *find_flow_state(flow_t flow)
{
  flow_state_t *ptr;
  int index = HASH_FLOW(flow);

  for (ptr = flow_hash[index]; ptr != NULL; ptr = ptr->next)
    if (!memcmp((char *) &flow, (char *) &(ptr->flow), sizeof(flow))) {
      ptr->last_access = current_time++;
      return ptr;
    }

  return NULL;
}



FILE *attempt_fopen(flow_state_t *flow_state, char *filename)
{
  /* If we've opened this file already, reopen it.  Otherwise create a
   * new file.  We purposefully overwrite files from previous runs of
   * the program. */
  if (IS_SET(flow_state->flags, FLOW_FILE_EXISTS)) {
    DEBUG(5) ("%s: re-opening output file", filename);
    flow_state->fp = fopen(filename, "r+");
  } else {
    DEBUG(5) ("%s: opening new output file", filename);
    flow_state->fp = fopen(filename, "w");
  }

  return flow_state->fp;
}


FILE *open_file(flow_state_t *flow_state)
{
  char *filename = flow_filename(flow_state->flow);
  int done;

  /* This shouldn't be called if the file is already open */
  if (flow_state->fp) {
    DEBUG(20) ("huh -- trying to open already open file!");
    return flow_state->fp;
  }

  /* Now try and open the file */
  do {
    if (attempt_fopen(flow_state, filename) != NULL) {
      /* open succeeded... great */
      done = 1;
    } else {
      if (errno == ENFILE || errno == EMFILE) {
	/* open failed because too many files are open... close one
           and try again */
	contract_fd_ring();
	DEBUG(5) ("too many open files -- contracting FD ring to %d", max_fds);
	done = 0;
      } else {
	/* open failed for some other reason... give up */
	done = 1;
      }
    }
  } while (!done);

  /* If the file isn't open at this point, there's a problem */
  if (flow_state->fp == NULL) {
    /* we had some problem opening the file -- set FINISHED so we
     * don't keep trying over and over again to reopen it */
    SET_BIT(flow_state->flags, FLOW_FINISHED);
    perror(filename);
    return NULL;
  }

  /* Decide which FD slot we get, and close the file that's there if
   * any.  Note that even if flow_state is not NULL, its associated
   * file pointer may already be closed.  Note well that we DO NOT
   * free the state that we find in our slot; the state stays around
   * forever (pointed to by the hash table).  This table only keeps a
   * pointer to state structures that have open files so that we can
   * close them later.
   *
   * We are putting the close after the open so that we don't bother
   * closing files if the open fails.  (For this, we pay a price of
   * needing to keep a spare, idle FD around.) */
  if (++next_slot == max_fds) {
    /* sort to sort of do LRU every time we get to the end */
    sort_fds();
    next_slot = 0;
  }

  /* close the next one in line */
  if (fd_ring[next_slot] != NULL)
    close_file(fd_ring[next_slot]);

  /* put ourslves in its place */
  fd_ring[next_slot] = flow_state;
  DEBUG(5) ("....slot %d", next_slot);

  /* set flags and remember where in the file we are */
  SET_BIT(flow_state->flags, FLOW_FILE_EXISTS);
  fgetpos(flow_state->fp, &(flow_state->pos));

  return flow_state->fp;
}



/* Closes the file belonging to a flow -- returns 1 if a file was
 * actually closed, 0 otherwise (if it was already closed) */
int close_file(flow_state_t *flow_state)
{
  if (flow_state->fp == NULL)
    return 0;

  DEBUG(5) ("%s: closing file", flow_filename(flow_state->flow));
  /* close the file and remember that it's closed */
  fclose(flow_state->fp);
  flow_state->fp = NULL;
  flow_state->pos = 0;
  return 1;
}



/* This comparison function puts flows first in the array, and nulls
 * last.  Within the flows, they are ordered from least recently
 * accessed at the front, and most recently accessed at the end. */
int flow_state_compare(const void *a, const void *b)
{
  flow_state_t **x = (flow_state_t **)a;
  flow_state_t **y = (flow_state_t **)b;

  if (*x == NULL && *y == NULL)
    return 0;
  if (*x == NULL)
    return 1;
  if (*y == NULL)
    return -1;
  return ((*x)->last_access - (*y)->last_access);
}


/* Sort FDs in the fd_table according to the comparison function (see
 * comment above) */
void sort_fds()
{
  qsort(fd_ring, max_fds, sizeof(struct flow_state_t *), flow_state_compare);

#if 0
  /* code to dump the table - for debugging */
  {
    int i;

    for(i = 0; i < max_fds; i++) {
      if (fd_ring[i] == NULL)
	continue;
      else
	fprintf(stderr, "fd_slot %d: %s (lasttime=%d)\n", i,
		flow_filename(fd_ring[i]->flow), fd_ring[i]->last_access);
    }
  }
#endif
}


/* We need to reduce the size of the fd ring by one FD.  We will
 * sort the FD ring, close the oldest (i.e. first) file descriptor,
 * shift everything down by one, and set max_fds to reflect the new
 * size. */
void contract_fd_ring()
{
  int i;

  /* sort */
  sort_fds();

  /* make sure we're sane */
  if (fd_ring[0] == NULL) {
    die("we seem to be completely out of file descriptors");
  }

  /* close the oldest FD */
  close_file(fd_ring[0]);

  /* shift everything forward by one and count */
  for (i = 1; i < max_fds && fd_ring[i] != NULL; i++)
    fd_ring[i-1] = fd_ring[i];

  /* remember that the ring is smaller now */
  max_fds = i-1;

  /* start at 0 (by setting to -1, since we're going to increment it) */
  next_slot = -1;
}


