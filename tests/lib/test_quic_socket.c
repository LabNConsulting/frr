// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Title/Function of file
 * Copyright (C) 2025  LabN Consulting, L.L.C.
 */

#include <zebra.h>
#include <string.h>

#include "memory.h"
#include "frr_pthread.h"
#include "frr_socket.h"

struct frr_pthread *pth_shared;
static struct sockaddr_in addr_server = {};
static socklen_t addrlen_server = 0;
static const char *msg_client = "test frr socket client";
static const char *msg_server = "test frr socket server";
static ssize_t msg_size = sizeof(msg_client); /* Should also be equal to msg_server */

/*
 * Starting point test. Just make a socket and then close it without any further action.
 */
static void test_socket_then_close(void)
{
	struct frr_socket_entry search_entry = {};
	int fd, rv;

	printf("Testing up until frr_socket(), then frr_close()\n");
	fd = frr_socket(AF_INET, SOCK_STREAM, IPPROTO_QUIC);
	assert(fd > 0);
	search_entry.fd = fd;
	{
		frr_socket_table_find(&search_entry, scoped_entry);
		assert(scoped_entry);
		assert(scoped_entry->protocol == IPPROTO_QUIC);
		assert(scoped_entry->fd == fd);
	}

	rv = frr_close(fd);
	assert(rv == 0);
}


/*
 * Socket calls up until frr_connect(), then close()
 */
static void test_listen_then_close(void)
{
	int fd;
	struct addrinfo *ainfo, *ainfo_save;
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_QUIC,
	};

	printf("Testing up until frr_listen(), then frr_close()\n");

	/* Acquire a socket via frr_getaddrinfo and listen on it */
	if (frr_getaddrinfo("127.0.0.1", NULL, &hints, &ainfo_save)) {
		perror("test_listen_then_close: Failed to call getaddrinfo");
		assert(0);
	}

	for (ainfo = ainfo_save; ainfo != NULL; ainfo = ainfo->ai_next) {
		if (ainfo->ai_protocol != IPPROTO_QUIC)
			continue;
		if ((fd = frr_socket(ainfo->ai_family, ainfo->ai_socktype, ainfo->ai_protocol)) < 0)
			continue;
		if (frr_bind(fd, ainfo->ai_addr, ainfo->ai_addrlen) == 0)
			break;
		frr_close(fd);
	}

	if (fd <= 0) {
		printf("test_listen_then_close: Failed to find a good socket address with getaddrinfo\n");
		assert(0);
	}
	addrlen_server = sizeof(addr_server);
	assert(frr_getsockname(fd, (struct sockaddr *)&addr_server, &addrlen_server) == 0);

	if (frr_listen(fd, 1) != 0) {
		perror("test_listen_then_close: frr_listen failed\n");
		assert(0);
	}

	assert(frr_close(fd) == 0);
	frr_freeaddrinfo(ainfo_save);

	/* Reset global resources for latter tests */
	memset(&addr_server, 0, sizeof(addr_server));
	addrlen_server = 0;
}


void (*tests[])(void) = {
	test_socket_then_close,
	test_listen_then_close,
};


int main(int argc, char **argv)
{
	struct frr_pthread_attr shared = {
		.start = frr_pthread_attr_default.start,
		.stop = frr_pthread_attr_default.stop,
	};

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
