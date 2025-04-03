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
struct frr_pthread_attr shared = {};
_Atomic int ctr1, ctr2;

void frr_socket_test_insert_delete(void);
void frr_socket_test_async_insert_delete(void);
void *insert_delete_repeat(void *arg);

int main(int argc, char **argv)
{

	printf("Starting\n");
	frr_pthread_init();
	shared.start = frr_pthread_attr_default.start;
	shared.stop = frr_pthread_attr_default.stop;
        pth_shared = frr_pthread_new(&shared, "FRR socket test pthread", "frrsock shared");
	frr_pthread_run(pth_shared, NULL);
	frr_pthread_wait_running(pth_shared);
	rcu_read_unlock();

	printf("Setting up FRR socket library\n");
	assert(frr_socket_lib_init(pth_shared->master) == 0);

	/* XXX Test explanations */
	frr_socket_test_insert_delete();

	frr_socket_test_async_insert_delete();

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


/* Test the basic insertion and deletion from the FRR socket table */
void frr_socket_test_insert_delete(void)
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
	int fd, rv;

	while (ctr1 < 1);;

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
			rv = frr_close(fd);
			assert(rv == 0);
			frr_socket_table_find(&frr_socket_table, &search_entry, scoped_entry);
			assert(scoped_entry == NULL);
		}
	}

	return NULL;
}


/*
 * Test insertion and deletion from multiple threads
 *
 * This is not a demonstration of realistic usage of the FRR socket abstraction, but a demonstration
 * of thread safety.
*/
#define NUM_THREADS 4
void frr_socket_test_async_insert_delete(void)
{
	pthread_t pthr[NUM_THREADS];
	struct rcu_thread *rcu_thr[NUM_THREADS];

	ctr1 = 0;
	printf("Testing multi-threaded insertion and deletion\n");
	rcu_read_lock();
	for (int i = 0; i < NUM_THREADS; i++) {
		rcu_thr[i] = rcu_thread_prepare();
		pthread_create(&pthr[i], NULL, insert_delete_repeat, rcu_thr[i]);
	}
	rcu_read_unlock();

	/* Give the go ahead for threads to start */
	ctr1 = 1;

	for (int i = 0; i < NUM_THREADS; i++) {
		pthread_join(pthr[i], NULL);
	}
}
