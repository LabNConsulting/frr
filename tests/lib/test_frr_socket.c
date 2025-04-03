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
void insert_delete_repeat(void);
void *insert_delete_repeat_start(void *arg);
int basic_pthread_stop(struct frr_pthread *fpt, void **result);

int main(int argc, char **argv)
{

	printf("Starting\n");
	frr_pthread_init();
	shared.start = frr_pthread_attr_default.start;
	shared.stop = frr_pthread_attr_default.stop;
        pth_shared = frr_pthread_new(&shared, "FRR socket test pthread", "test_frr_socket");
	frr_pthread_run(pth_shared, NULL);
	frr_pthread_wait_running(pth_shared);

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


void insert_delete_repeat(void)
{
	struct frr_socket_entry search_entry = {};
	int fd, rv;

	for (int i = 0; i < 50; i++) {
		printf("%d\n", ctr2++);
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

	sleep(1000);
	ctr1++;
}

void *insert_delete_repeat_start(void *arg)
{
        struct frr_pthread *fpt = arg;
        fpt->master->owner = pthread_self();

	rcu_read_unlock();

	frr_pthread_set_name(fpt);
        frr_pthread_notify_running(fpt);

	insert_delete_repeat();

	return NULL;
}

int basic_pthread_stop(struct frr_pthread *fpt, void **result)
{
        assert(fpt->running);

	atomic_store_explicit(&fpt->running, false, memory_order_relaxed);

	pthread_join(fpt->thread, result);
        return 0;
}

/* Test insertion and deletion from multiple threads */
#define NUM_THREADS 1
void frr_socket_test_async_insert_delete(void)
{
	struct frr_pthread *pthr[NUM_THREADS];
	struct frr_pthread_attr shared = {
		.start = insert_delete_repeat_start,
		.stop = basic_pthread_stop,
	};
	ctr1 = 0;

	printf("Testing multi-threaded insertion and deletion\n");
	for (int i = 0; i < NUM_THREADS; i++) {
		pthr[i] = frr_pthread_new(&shared, "FRR socket insert/delete pthread",
					  "test_frr_socket");
		frr_pthread_run(pthr[i], NULL);
	}

	for (int i = 0; i < NUM_THREADS; i++) {
		frr_pthread_wait_running(pthr[i]);
	}

	/*
	for (int i = 0; i < NUM_THREADS; i++) {
		event_add_timer_msec((pthr[i])->master, insert_delete_repeat, NULL, 0, NULL);
	}
	*/

	while (ctr1 < NUM_THREADS);;

	/*
	for (int i = 0; i < NUM_THREADS; i++) {
		frr_pthread_stop(pthr[i], NULL);
		frr_pthread_destroy(pthr[i]);
	}
	*/

	/* Allow for all cleanup events to finish */
	usleep(5000000);
}
