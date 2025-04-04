// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Title/Function of file
 * Copyright (C) 2025  LabN Consulting, L.L.C.
 */

#include <zebra.h>

#include "memory.h"
#include "frr_pthread.h"
#include "test_tcp_frr_socket.h"

struct frr_pthread *pth_shared;
_Atomic bool ready;

/*
 * Test the basic frr_socket_entry insertion and deletion routines within the hash table.
 */
static void test_socket_insert_delete(void)
{
	struct frr_socket_entry search_entry = {};
	int fd, rv;

	printf("Testing insertion of a basic frr_socket_entry\n");
	fd = frr_socket(AF_INET, SOCK_STREAM, IPPROTO_TEST_TCP);
	search_entry.fd = fd;
	{
		struct frr_socket_entry *scoped_entry;
		frr_socket_table_find(&frr_socket_table, &search_entry, scoped_entry);
		assert(scoped_entry);
		assert(scoped_entry->protocol == IPPROTO_TEST_TCP);
		assert(scoped_entry->fd == fd);
	}

	printf("Testing deletion of a basic frr_socket_entry\n");
	{
		struct frr_socket_entry *scoped_entry, *held_entry;
		frr_socket_table_find(&frr_socket_table, &search_entry, held_entry);
		assert(held_entry);
		rv = frr_close(fd);
		assert(rv == 0);
		frr_socket_table_find(&frr_socket_table, &search_entry, scoped_entry);
		assert(scoped_entry == NULL);

		/* Ensure that the entry is not preemptively freed when a reference is still held */
		for (int i = 0; i < 4; i++) {
			assert(held_entry->fd == fd);
			usleep(5000);
		}
	}
}


#define NUM_REPEAT 50
void *insert_delete_repeat(void *arg)
{
	struct frr_socket_entry search_entry = {};
	struct rcu_thread *rcu_thr = arg;
	int fd;

	while (!ready);;

	rcu_thread_start(rcu_thr);
	rcu_read_unlock();

	for (int i = 0; i < NUM_REPEAT; i++) {
		fd = frr_socket(AF_INET, SOCK_STREAM, IPPROTO_TEST_TCP);
		search_entry.fd = fd;
		{
			struct frr_socket_entry *scoped_entry;
			frr_socket_table_find(&frr_socket_table, &search_entry, scoped_entry);
			assert(scoped_entry);
			assert(scoped_entry->protocol == IPPROTO_TEST_TCP);
			assert(scoped_entry->fd == fd);
		}
		{
			struct frr_socket_entry *scoped_entry;
			assert(frr_close(fd) == 0);
			frr_socket_table_find(&frr_socket_table, &search_entry, scoped_entry);
			assert(scoped_entry == NULL);
		}
	}

	return NULL;
}


/*
 * Test the insertion and deletion routines when in use by multiple threads
 *
 * This is not a demonstration of realistic usage of the FRR socket abstraction, since both the
 * number of active threads and number of modifications to the hash table are unexpected. It is
 * instead a demonstration of thread-safety in edge case scenarios.
 */
#define NUM_THREADS 4
void test_socket_insert_delete_async(void)
{
	pthread_t pthr[NUM_THREADS];
	struct rcu_thread *rcu_thr[NUM_THREADS];

	ready = false;
	printf("Testing multi-threaded insertion and deletion\n");
	rcu_read_lock();
	for (int i = 0; i < NUM_THREADS; i++) {
		rcu_thr[i] = rcu_thread_prepare();
		pthread_create(&pthr[i], NULL, insert_delete_repeat, rcu_thr[i]);
	}
	rcu_read_unlock();

	/* Give the go ahead for threads to start */
	ready = true;

	for (int i = 0; i < NUM_THREADS; i++) {
		pthread_join(pthr[i], NULL);
	}
}


void (*tests[])(void) = {
	test_socket_insert_delete,
	test_socket_insert_delete_async,
};


int main(int argc, char **argv)
{
	struct frr_pthread_attr shared = {.start = frr_pthread_attr_default.start;
	.stop = frr_pthread_attr_default.stop;
}

printf("Starting\n");
frr_pthread_init();
pth_shared = frr_pthread_new(&shared, "FRR socket shared pthread", "frrsock shared");
frr_pthread_run(pth_shared, NULL);
frr_pthread_wait_running(pth_shared);
rcu_read_unlock();

printf("Setting up FRR socket library\n");
assert(frr_socket_lib_init(pth_shared->master) == 0);

for (unsigned int i = 0; i < array_size(tests); i++)
	tests[i]();

printf("Cleaning up FRR socket library\n");
frr_socket_lib_finish();

printf("Finishing\n");
frr_pthread_stop(pth_shared, NULL);
frr_pthread_finish();
rcu_read_lock();
rcu_shutdown();

printf("Done\n");
return 0;
}
