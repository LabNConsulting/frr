// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Title/Function of file
 * Copyright (C) 2025  LabN Consulting, L.L.C.
 */

#include <zebra.h>
#include <string.h>
#include <stdio.h>

#include "memory.h"
#include "frr_pthread.h"
#include "frr_socket.h"
#include "tcp_frr_socket.h"

struct frr_pthread *pth_shared;

/*
 * Test the basic frr_socket_entry insertion and deletion routines within the hash table.
 */
static void test_socket_insert_delete(void)
{
	struct frr_socket_entry search_entry = {};
	int fd;

	printf("Testing insertion of a basic frr_socket_entry\n");
	fd = frr_socket(AF_INET, SOCK_STREAM, IPPROTO_FRR_TCP);
	assert(fd > 0);
	search_entry.fd = fd;
	{
		frr_socket_table_find(&search_entry, scoped_entry);
		assert(scoped_entry);
		assert(scoped_entry->protocol == IPPROTO_FRR_TCP);
		assert(scoped_entry->fd == fd);
	}

	printf("Testing deletion of a basic frr_socket_entry\n");
	{
		frr_socket_table_find(&search_entry, held_entry);
		assert(held_entry);

		/* We hold the locked reference to held_entry. frr_close will need it instead, so we
		 * release control for a short time. No user should ever need to do this, since a
		 * user should never hold the reference directly.
		 */
		pthread_mutex_unlock(&held_entry->lock);
		assert(frr_close(fd) == 0);
		pthread_mutex_lock(&held_entry->lock);

		/* Ensure that the entry is not preemptively freed when a reference is still held */
		for (int i = 0; i < 4; i++) {
			assert(held_entry->fd == fd);
			usleep(5000);
		}
	}

	frr_socket_table_find(&search_entry, none_entry);
	assert(none_entry == NULL);
}


_Atomic int num_go = 0;
#define NUM_REPEAT 50
static void *pthread_socket_insert_delete_async(void *arg)
{
	struct frr_socket_entry search_entry = {};
	struct rcu_thread *rcu_thr = arg;
	int fd, id = 0;
	char run_msg[8];
	size_t msg_size = 0;

	while (num_go < 1)
		;
	;
	id = num_go--;

	rcu_thread_start(rcu_thr);
	rcu_read_unlock();

	for (int i = 0; i < NUM_REPEAT; i++) {
		fd = frr_socket(AF_INET, SOCK_STREAM, IPPROTO_FRR_TCP);
		assert(fd > 0);
		search_entry.fd = fd;

		/* RCU protected scope */
		{
			frr_socket_table_find(&search_entry, scoped_entry);
			assert(scoped_entry);
			assert(scoped_entry->protocol == IPPROTO_FRR_TCP);
			assert(scoped_entry->fd == fd);

			struct tcp_socket_entry *tcp_entry = (struct tcp_socket_entry *)scoped_entry;
			snprintf(run_msg, sizeof(run_msg), "T%d;R%d", id, i);
			msg_size = MIN(sizeof(run_msg), sizeof(tcp_entry->dummy));
			strncpy(tcp_entry->dummy, run_msg, msg_size);
		}

		assert(frr_close(fd) == 0);

		/* RCU protected scope */
		{
			frr_socket_table_find(&search_entry, scoped_entry);
			if (scoped_entry != NULL) {
				/*
				 * May accidentally grab an entry from another thread if the
				 * kernel immediately reused the file descriptor. This is caught
				 * by double checking the run id for (non)equality.
				 */
				struct tcp_socket_entry *tcp_entry =
					(struct tcp_socket_entry *)scoped_entry;
				assert(strncmp(tcp_entry->dummy, run_msg, msg_size) != 0);
			}
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
static void test_socket_insert_delete_async(void)
{
	pthread_t pthr[NUM_THREADS];
	struct rcu_thread *rcu_thr[NUM_THREADS];

	num_go = 0;
	printf("Testing multi-threaded insertion and deletion\n");
	rcu_read_lock();
	for (int i = 0; i < NUM_THREADS; i++) {
		rcu_thr[i] = rcu_thread_prepare();
		pthread_create(&pthr[i], NULL, pthread_socket_insert_delete_async, rcu_thr[i]);
	}
	rcu_read_unlock();

	/* Give the go ahead for threads to start */
	num_go = NUM_THREADS;

	for (int i = 0; i < NUM_THREADS; i++) {
		pthread_join(pthr[i], NULL);
	}
}


static struct sockaddr_in addr_server = {};
static socklen_t addrlen_server = 0;
static const char *msg_client = "test frr socket client";
static const char *msg_server = "test frr socket server";
static ssize_t msg_size = 22; /* Should also be equal to msg_server */

static void *pthread_frr_tcp_connection(void *arg)
{
	int fd_c = -1; /* Connected FD */
	struct rcu_thread *rcu_thr = arg;
	struct addrinfo *ainfo, *ainfo_save;
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_FRR_TCP,
	};

	/* pthread setup */
	rcu_thread_start(rcu_thr);
	rcu_read_unlock();

	/* Acquire a socket via frr_getaddrinfo and connect to the listener using it */
	if (frr_getaddrinfo("127.0.0.1", NULL, &hints, &ainfo_save)) {
		perror("Failed to call getaddrinfo");
		assert(0);
	}

	for (ainfo = ainfo_save; ainfo != NULL; ainfo = ainfo->ai_next) {
		if (ainfo->ai_protocol != IPPROTO_FRR_TCP)
			continue;
		if ((fd_c = frr_socket(ainfo->ai_family, ainfo->ai_socktype, ainfo->ai_protocol)) <
		    0)
			continue;
		if (frr_bind(fd_c, ainfo->ai_addr, ainfo->ai_addrlen) == 0)
			break;
		frr_close(fd_c);
	}

	if (fd_c < 0) {
		printf("Client failed to find a good socket address with getaddrinfo\n");
		assert(0);
	}

	if (frr_connect(fd_c, (struct sockaddr *)&addr_server, addrlen_server)) {
		perror("Failed to connect client socket");
		assert(0);
	}

	/* Extremely simplistic bidirectional data transfer */
	char buf[msg_size];
	assert(frr_write(fd_c, msg_client, msg_size) == msg_size);
	assert(frr_read(fd_c, buf, msg_size) == msg_size);
	assert(strncmp(buf, msg_server, msg_size) == 0);

	/* Cleanup of pthread */
	frr_freeaddrinfo(ainfo_save);
	assert(frr_close(fd_c) == 0);

	return NULL;
}


/*
 * Ensure that the FRR socket abstraction can call socket handlers correctly.
 */
static void test_frr_tcp_connection(void)
{
	int fd_l = -1; /* Listener FD */
	int fd_a = -1; /* Accepted FD */
	pthread_t pthr;
	struct rcu_thread *rcu_thr;
	struct addrinfo *ainfo, *ainfo_save;
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_FRR_TCP,
	};

	printf("Testing simple FRR TCP connection\n");

	/* Acquire a socket via frr_getaddrinfo and listen on it */
	if (frr_getaddrinfo("127.0.0.1", NULL, &hints, &ainfo_save)) {
		perror("Failed to call getaddrinfo");
		assert(0);
	}

	for (ainfo = ainfo_save; ainfo != NULL; ainfo = ainfo->ai_next) {
		if (ainfo->ai_protocol != IPPROTO_FRR_TCP)
			continue;
		if ((fd_l = frr_socket(ainfo->ai_family, ainfo->ai_socktype, ainfo->ai_protocol)) <
		    0)
			continue;
		if (frr_bind(fd_l, ainfo->ai_addr, ainfo->ai_addrlen) == 0)
			break;
		frr_close(fd_l);
	}

	if (fd_l < 0) {
		printf("Server failed to find a good socket address with getaddrinfo\n");
		assert(0);
	}
	addrlen_server = sizeof(addr_server);
	assert(!frr_getsockname(fd_l, (struct sockaddr *)&addr_server, &addrlen_server));

	/* Start the tcp client pthread. It will connect to the listening socket and exchange data */
	rcu_read_lock();
	rcu_thr = rcu_thread_prepare();
	pthread_create(&pthr, NULL, pthread_frr_tcp_connection, rcu_thr);
	rcu_read_unlock();

	/* Listen for a single connection, and then exchange basic data */
	if (frr_listen(fd_l, 1)) {
		perror("Failed to listen on server socket");
		assert(0);
	}

	struct pollfd fd_poll = {
		.fd = fd_l,
		.events = POLLIN,
	};
	int poll_rv, t_poll_rv;
	if ((poll_rv = poll(&fd_poll, 1, 5000)) != 1) {
		printf("Unexpected result of poll\n");
		assert(0);
	}
	/*
	 * Technically there is no need for this poll to be hooked since TCP FRR sockets do not
	 * override the revents. However, this is where frr_poll_hook would normally be called.
	 */
	t_poll_rv = poll_rv;
	assert((poll_rv = frr_poll_hook(&fd_poll, 1)) == t_poll_rv);
	assert(fd_poll.revents & POLLIN);

	if ((fd_a = frr_accept(fd_l, NULL, NULL)) < 0) {
		perror("Server failed to accept socket");
		assert(0);
	}

	/* Extremely simplistic bidirectional data transfer */
	char buf[msg_size];
	assert(frr_read(fd_a, buf, msg_size) == msg_size);
	assert(strncmp(buf, msg_client, msg_size) == 0);
	assert(frr_write(fd_a, msg_server, msg_size) == msg_size);

	/* Cleanup for this test */
	pthread_join(pthr, NULL);
	frr_freeaddrinfo(ainfo_save);
	assert(frr_close(fd_l) == 0);
	assert(frr_close(fd_a) == 0);
}

void (*tests[])(void) = {
	test_socket_insert_delete,
	test_socket_insert_delete_async,
	test_frr_tcp_connection,
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
