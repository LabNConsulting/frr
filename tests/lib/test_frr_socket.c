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

void frr_socket_test_insert_delete(void);

int main(int argc, char **argv)
{

	printf("Starting\n");
	frr_pthread_init();
        struct frr_pthread_attr shared = {
                .start = frr_pthread_attr_default.start,
                .stop = frr_pthread_attr_default.stop,
        };
        pth_shared = frr_pthread_new(&shared, "FRR socket test pthread", "test_frr_socket");
	frr_pthread_run(pth_shared, NULL);
	frr_pthread_wait_running(pth_shared);

	printf("Setting up FRR socket library\n");
	assert(frr_socket_lib_init(pth_shared->master) == 0);

	frr_socket_test_insert_delete();


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
	rv = frr_close(fd);
	assert(rv == 0);
	{
		struct frr_socket_entry *scoped_entry;
		frr_socket_table_find(&frr_socket_table, &search_entry, scoped_entry);
		assert(!scoped_entry);
	}
}
