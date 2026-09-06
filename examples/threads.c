/*
 * One process, two threads: the first reads, the second writes.
 *
 * This is the shape rustc's codegen threads have, and it used to defeat the
 * tracer: pthread_create goes through clone3, which was not among the syscalls
 * that recorded a child, so every thread arrived as a tracee with no parent and
 * got a subject of its own.  The read then belonged to one node and the write
 * to another, with nothing tying them together, so the object came out with no
 * lineage at all: 81 objects in the fd ground-truth build, and 1286 of its 5916
 * process nodes had no parent.
 *
 * A trace of this program must show the read and the write under one process.
 */

#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>

static char buf[64];

static void *
reader(void *arg)
{
    (void) arg;

    FILE *in = fopen("threads-input.txt", "r");

    if (in != NULL) {
	if (fgets(buf, sizeof buf, in) == NULL)
	    buf[0] = '\0';
	fclose(in);
    }
    return NULL;
}

static void *
writer(void *arg)
{
    (void) arg;

    FILE *out = fopen("threads-output.o", "w");

    if (out != NULL) {
	fputs(buf, out);
	fclose(out);
    }
    return NULL;
}

int
main(void)
{
    pthread_t r, w;

    pthread_create(&r, NULL, reader, NULL);
    pthread_join(r, NULL);
    pthread_create(&w, NULL, writer, NULL);
    pthread_join(w, NULL);
    return 0;
}
