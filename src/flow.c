#include <stdio.h>
#include <stdlib.h>

#include "tcpflow.h"

static int max_fds;
static int curr_fds;
static int next_slot;
static flow_state_t **fd_ring;
static flow_state_t *flow_hash[HASH_SIZE];


/* Initialize our structures */
void init_flow_state()
{
  int i;

  /* Find out how many files we can have open safely...subtract 3 for
   * stdin, stdout, stderr */
  max_fds = get_max_fds() - 3;

  fd_ring = MALLOC(flow_state_t *, max_fds);

  for (i = 0; i < max_fds; i++)
    fd_ring[i] = NULL;

  for (i = 0; i < HASH_SIZE; i++)
    flow_hash[i] = NULL;

  curr_fds = 0;
  next_slot = 0;
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
    if (!memcmp((char *) &flow, (char *) &(ptr->flow), sizeof(flow)))
      return ptr;

  return NULL;
}



FILE *open_file(flow_state_t *flow_state)
{
  char *filename = flow_filename(flow_state->flow);

  /* This shouldn't be called if the file is already open */
  if (flow_state->fp) {
    DEBUG(20) ("huh -- trying to open already open file!");
    return flow_state->fp;
  }

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

  /* Now if the file isn't open, there's a problem. */
  if (flow_state->fp == NULL) {
    /* we had some problem opening the file -- set FINISHED so we
     * don't keep trying over and over again to reopen it */
    SET_BIT(flow_state->flags, FLOW_FINISHED);
    perror(filename);
    return NULL;
  } else {
    SET_BIT(flow_state->flags, FLOW_FILE_EXISTS);
    fgetpos(flow_state->fp, &(flow_state->pos));
    return flow_state->fp;
  }
}



void close_file(flow_state_t *flow_state)
{
  if (flow_state->fp == NULL)
    return;

  /* close the file and remember that it's closed */
  fclose(flow_state->fp);
  flow_state->fp = NULL;
  flow_state->pos = 0;
}


