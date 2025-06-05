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

#define ONESEC2MICRO 1000000
#define TIMEOUT (30 * ONESEC2MICRO)
#define POLL_SLEEP (ONESEC2MICRO / 4)
#define POLL_ATTEMPTS (TIMEOUT / POLL_SLEEP)

enum finish_point {
	SOCKET,
	LISTEN,
	ACCEPT,
	CONNECT,
	GETSOCKOPT,
	IO,
	FINISH_MAX,
};

struct socket_test_arg {
	struct rcu_thread *rcu_thr;
	const char *desc;  /* Up to test writer to ensure is nul-terminated */
	enum finish_point stop_at;
	const char *addr;  /* e.g. "127.0.0.1" */
};

static struct frr_pthread *pth_shared;
static struct sockaddr_in addr_server = {};
static socklen_t addrlen_server = 0;
static int server_ready = 0;
static const char *msg_client = "test frr socket client";
static const char *msg_server = "test frr socket server";
static ssize_t msg_size = 22; /* Should also be equal to msg_server */

static void *pthread_quic_server(void *arg)
{
	int poll_rv, attempts, fd_l = -1, fd = -1;
	char buf[msg_size];
	struct socket_test_arg *params = arg;
	struct addrinfo *ainfo, *ainfo_save;
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_QUIC,
	};

	/* pthread setup */
	rcu_thread_start(params->rcu_thr);
	rcu_read_unlock();

	printf("Running server thread for: %s\n", params->desc);

	/* Acquire a socket via frr_getaddrinfo and listen on it */
	if (frr_getaddrinfo(params->addr, NULL, &hints, &ainfo_save)) {
		printf("%s: frr_getaddrinfo failed: %s\n", params->desc, strerror(errno));
		assert(0);
	}

	for (ainfo = ainfo_save; ainfo != NULL; ainfo = ainfo->ai_next) {
		if (ainfo->ai_protocol != IPPROTO_QUIC)
			continue;
		if ((fd_l = frr_socket(ainfo->ai_family, ainfo->ai_socktype, ainfo->ai_protocol)) < 0)
			continue;
		if (frr_bind(fd_l, ainfo->ai_addr, ainfo->ai_addrlen) == 0)
			break;
		frr_close(fd_l);
	}

	if (fd_l <= 0) {
		printf("%s: Failed to find a good socket address with frr_getaddrinfo\n",
		       params->desc);
		assert(0);
	}

	if (params->stop_at == SOCKET)
		goto finish;

	addrlen_server = sizeof(addr_server);
	assert(frr_getsockname(fd_l, (struct sockaddr *)&addr_server, &addrlen_server) == 0);

	if (frr_listen(fd_l, 1) != 0) {
		printf("%s: frr_listen failed: %s\n", params->desc, strerror(errno));
		assert(0);
	}

	/* Give the client the co-ahead to connect */
	server_ready = 1;

	if (params->stop_at == LISTEN)
		goto finish;

	/* poll for accept */
	struct pollfd fd_poll_accept = {
		.fd = fd_l,
		.events = POLLIN,
	};
	attempts = POLL_ATTEMPTS;
	while (attempts-- > 0) {
		if ((poll_rv = poll(&fd_poll_accept, 1, 0)) < 0) {
			printf("%s: Unexpected result of poll: %s\n", params->desc,
			       strerror(errno));
			assert(0);
		}

		poll_rv = frr_poll_hook(&fd_poll_accept, 1);

		if (poll_rv > 0)
			break;

		usleep(POLL_SLEEP);
	}

	if (!(fd_poll_accept.revents & POLLIN)) {
		printf("%s: Poll failed to find a new incoming connection\n", params->desc);
		assert(0);
	}

	/* accept the socket. XXX verify that the address is set correctly! */
	fd = frr_accept(fd_l, NULL, NULL);
	assert(fd != -1);

	if (params->stop_at == ACCEPT)
		goto finish;

	/* Wait to receive the client's message */
	struct pollfd fd_poll_rx = {
		.fd = fd,
		.events = POLLIN,
	};
	attempts = POLL_ATTEMPTS;
	while (attempts-- > 0) {
		if ((poll_rv = poll(&fd_poll_rx, 1, 0)) < 0) {
			printf("%s: Unexpected result of poll: %s\n", params->desc,
			       strerror(errno));
			assert(0);
		}

		poll_rv = frr_poll_hook(&fd_poll_rx, 1);

		if (poll_rv > 0)
			break;

		usleep(POLL_SLEEP);
	}

	if (!(fd_poll_rx.revents & POLLIN)) {
		printf("%s: poll failed to find rx data\n",
		       params->desc);
		assert(0);
	}

	frr_read(fd, &buf, msg_size);
	assert(strncmp(buf, msg_client, msg_size) == 0);

	/* Respond with the server message */
	frr_write(fd, msg_server, msg_size);

finish:
	assert(frr_close(fd_l) == 0);
	if (fd != -1)
		assert(frr_close(fd) == 0);
	frr_freeaddrinfo(ainfo_save);
	return NULL;
}


static void *pthread_quic_client(void *arg)
{
	char buf[msg_size];
	int fd, poll_rv, attempts, status;
	socklen_t slen;
	struct socket_test_arg *params = arg;
	struct addrinfo *ainfo, *ainfo_save;
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_QUIC,
	};

	/* pthread setup */
	rcu_thread_start(params->rcu_thr);
	rcu_read_unlock();

	printf("Running client thread for: %s\n", params->desc);

	/* Acquire a socket via frr_getaddrinfo and listen on it */
	if (frr_getaddrinfo(params->addr, NULL, &hints, &ainfo_save)) {
		printf("%s: frr_getaddrinfo failed: %s\n", params->desc, strerror(errno));
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
		printf("%s: Failed to find a good socket address with frr_getaddrinfo\n", params->desc);
		assert(0);
	}

	if (params->stop_at == SOCKET)
		goto finish;

	while (!server_ready);;

	errno = 0;
	/* Should always fail with EINPROGRESS while the background processes start */
	if (frr_connect(fd, (struct sockaddr *)&addr_server, addrlen_server) != -1 ||
	    errno != EINPROGRESS) {
		printf("%s: frr_connect failed, %s\n", params->desc, strerror(errno));
		assert(0);
	}

	if (params->stop_at == CONNECT)
		goto finish;

	/* poll until writable */
	struct pollfd fd_poll_connect = {
		.fd = fd,
		.events = POLLOUT,
	};
	attempts = POLL_ATTEMPTS;
	while (attempts-- > 0) {
		if ((poll_rv = poll(&fd_poll_connect, 1, 0)) < 0) {
			printf("%s: Unexpected result of poll: %s\n", params->desc,
			       strerror(errno));
			assert(0);
		}

		poll_rv = frr_poll_hook(&fd_poll_connect, 1);

		if (poll_rv > 0)
			break;

		usleep(POLL_SLEEP);
	}

	if (!(fd_poll_connect.revents & POLLOUT)) {
		printf("%s: poll failed to find a possibly complete connection\n",
		       params->desc);
		assert(0);
	}

	/* Check getsockopt for good state */
	slen = sizeof(status);
	if (frr_getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *)&status, &slen) == -1) {
		printf("%s: frr_getsockopt found an error with SO_ERROR: %s\n", params->desc,
		       strerror(status));
		assert(0);
	}

	if (params->stop_at == GETSOCKOPT) {
		usleep(1000);  /* Give the server time to accept the connection before we close it. */
		goto finish;
	}

	/* Write the client message */
	frr_write(fd, msg_client, msg_size);

	/* Wait to receive the server message */
	struct pollfd fd_poll_rx = {
		.fd = fd,
		.events = POLLIN,
	};
	attempts = POLL_ATTEMPTS;
	while (attempts-- > 0) {
		if ((poll_rv = poll(&fd_poll_rx, 1, 0)) < 0) {
			printf("%s: Unexpected result of poll: %s\n", params->desc,
			       strerror(errno));
			assert(0);
		}

		poll_rv = frr_poll_hook(&fd_poll_rx, 1);

		if (poll_rv > 0)
			break;

		usleep(POLL_SLEEP);
	}

	if (!(fd_poll_rx.revents & POLLIN)) {
		printf("%s: poll failed to find rx data\n",
		       params->desc);
		assert(0);
	}

	frr_read(fd, &buf, msg_size);
	assert(strncmp(buf, msg_server, msg_size) == 0);

finish:
	assert(frr_close(fd) == 0);
	frr_freeaddrinfo(ainfo_save);
	return NULL;
}


/*
 * Starting point test. Just make a socket and then close it without any further action.
 */
static void test_socket_then_close(void)
{
	struct frr_socket_entry search_entry = {};
	int fd, rv;

	printf("Running test_socket_then_close\n");
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


static void reset_global_resources(void) {
	memset(&addr_server, 0, sizeof(addr_server));
	addrlen_server = 0;
	server_ready = 0;
}


/*
 * Socket calls up until frr_listen(), then close()
 */
static void test_listen_then_close(void)
{
	struct socket_test_arg params = {};
	pthread_t pthr_s;

	params.desc = "test_listen_then_close";
	params.addr = "127.0.1.1";
	params.stop_at = LISTEN;

	rcu_read_lock();
	params.rcu_thr = rcu_thread_prepare();
	pthread_create(&pthr_s, NULL, pthread_quic_server, &params);
	rcu_read_unlock();

	pthread_join(pthr_s, NULL);
	reset_global_resources();
}


/*
 * Socket calls up until frr_connect(), then close()
 */
static void test_connect_then_close(void)
{
	struct socket_test_arg params = {};
	pthread_t pthr_c;
	const char *desc = "test_connect_then_close";
	struct addrinfo *ainfo;
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_QUIC,
	};

	/* Use an address that is not listening so the connection guarenteed fails */
	if (frr_getaddrinfo("127.0.2.1", NULL, &hints, &ainfo)) {
		printf("%s: frr_getaddrinfo failed ahead of run: %s\n", desc, strerror(errno));
		assert(0);
	}
	if (ainfo == NULL) {
		printf("%s: Failed to find a second good address with getaddrinfo ahead of run\n",
		       desc);
		assert(0);
	}

	memcpy(&addr_server, ainfo->ai_addr, ainfo->ai_addrlen);
	addrlen_server = ainfo->ai_addrlen;
	server_ready = 1;
	frr_freeaddrinfo(ainfo);

	params.desc = desc;
	params.stop_at = CONNECT;
	params.addr = "127.0.2.2";

	rcu_read_lock();
	params.rcu_thr = rcu_thread_prepare();
	pthread_create(&pthr_c, NULL, pthread_quic_client, &params);
	rcu_read_unlock();

	pthread_join(pthr_c, NULL);
	reset_global_resources();
}


/*
 * Socket calls up until frr_accept() and frr_getsockopt(), then close()
 */
static void test_accept_then_close(void)
{
	struct socket_test_arg params_s = {}, params_c = {};
	pthread_t pthr_s, pthr_c;

	params_s.desc = "test_accept_then_close (server)";
	params_s.stop_at = ACCEPT;
	params_s.addr = "127.0.3.1";
	params_c.desc = "test_accept_then_close (client)";
	params_c.stop_at = GETSOCKOPT;
	params_c.addr = "127.0.3.2";

	rcu_read_lock();
	params_s.rcu_thr = rcu_thread_prepare();
	params_c.rcu_thr = rcu_thread_prepare();
	pthread_create(&pthr_s, NULL, pthread_quic_server, &params_s);
	pthread_create(&pthr_c, NULL, pthread_quic_client, &params_c);
	rcu_read_unlock();

	pthread_join(pthr_s, NULL);
	pthread_join(pthr_c, NULL);
	reset_global_resources();
}


/*
 * Socket calls up until frr_write() and frr_read(), then close()
 */
static void test_io_then_close(void)
{
	struct socket_test_arg params_s = {}, params_c = {};
	pthread_t pthr_s, pthr_c;

	params_s.desc = "test_io_then_close (server)";
	params_s.stop_at = IO;
	params_s.addr = "127.0.4.1";
	params_c.desc = "test_io_then_close (client)";
	params_c.stop_at = IO;
	params_c.addr = "127.0.4.2";

	rcu_read_lock();
	params_s.rcu_thr = rcu_thread_prepare();
	params_c.rcu_thr = rcu_thread_prepare();
	pthread_create(&pthr_s, NULL, pthread_quic_server, &params_s);
	pthread_create(&pthr_c, NULL, pthread_quic_client, &params_c);
	rcu_read_unlock();

	pthread_join(pthr_s, NULL);
	pthread_join(pthr_c, NULL);
	reset_global_resources();
}


void (*tests[])(void) = {
	test_socket_then_close,
	test_listen_then_close,
	test_connect_then_close,
	test_accept_then_close,
	test_io_then_close,
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
