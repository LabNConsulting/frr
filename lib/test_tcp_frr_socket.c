// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Title/Function of file
 * Copyright (C) 2025  LabN Consulting, L.L.C.
 */

#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>

#include "frr_socket.h"
#include "test_tcp_frr_socket.h"

/* Simple wrappers to test the FRR socket abstraction */
int test_tcp_socket(int domain, int type)
{
	int fd;
	struct frr_socket_entry *test_tcp_entry;

	fd = socket(domain, type, IPPROTO_TCP);
	if (fd < 0)
		return -1;

	test_tcp_entry = XMALLOC(MTYPE_FRR_SOCKET, sizeof(*test_tcp_entry));
	if (!test_tcp_entry) {
		close(fd);
		errno = ENOMEM;
		return -1;
	}

	memset(test_tcp_entry, 0x00, sizeof(*test_tcp_entry));
	frr_socket_init(test_tcp_entry);
	test_tcp_entry->protocol = IPPROTO_TEST_TCP;
	test_tcp_entry->fd = fd;
	frr_socket_table_add(&frr_socket_table, test_tcp_entry);

	return fd;
}


int test_tcp_bind(struct frr_socket_entry *entry, const struct sockaddr *addr,
			 socklen_t addrlen)
{
	return bind(entry->fd, addr, addrlen);
}


int test_tcp_connect(struct frr_socket_entry *entry, const struct sockaddr *addr, socklen_t addrlen)
{
	return connect(entry->fd, addr, addrlen);
}


int test_tcp_listen(struct frr_socket_entry *entry, int backlog)
{
	return listen(entry->fd, backlog);
}


int test_tcp_accept(struct frr_socket_entry *entry, struct sockaddr *addr, socklen_t *addrlen)
{
	int fd;
	struct frr_socket_entry *test_tcp_entry;

	fd = accept(entry->fd, addr, addrlen);
	if (fd < 0)
		return -1;

	test_tcp_entry = XMALLOC(MTYPE_FRR_SOCKET, sizeof(*test_tcp_entry));
	if (!test_tcp_entry) {
		close(fd);
		errno = ENOMEM;
		return -1;
	}

	memset(test_tcp_entry, 0x00, sizeof(*test_tcp_entry));
	frr_socket_init(test_tcp_entry);
	test_tcp_entry->protocol = IPPROTO_TEST_TCP;
	test_tcp_entry->fd = fd;
	frr_socket_table_add(&frr_socket_table, test_tcp_entry);

	return fd;
}


int test_tcp_close(struct frr_socket_entry *entry)
{
	/* Immediately removes the entry from the table. Then schedules test_tcp_destroy_entry() for
	 * the event of no other threads holding active references to the entry.
	 */
	return frr_socket_table_delete_async(&frr_socket_table, entry);
}


ssize_t test_tcp_writev(struct frr_socket_entry *entry, const struct iovec *iov, int iovcnt)
{
	return writev(entry->fd, iov, iovcnt);
}


ssize_t test_tcp_read(struct frr_socket_entry *entry, void *buf, size_t count)
{
	return read(entry->fd, buf, count);
}


ssize_t test_tcp_write(struct frr_socket_entry *entry, const void *buf, size_t count)
{
	return write(entry->fd, buf, count);
}


int test_tcp_setsockopt(struct frr_socket_entry *entry, int level, int option_name,
			const void *option_value, socklen_t option_len)
{
	return setsockopt(entry->fd, level, option_name, option_value, option_len);
}


int test_tcp_getsockopt(struct frr_socket_entry *entry, int level, int optname, void *optval,
			socklen_t *optlen)
{
	return getsockopt(entry->fd, level, optname, optval, optlen);
}


int test_tcp_getpeername(struct frr_socket_entry *entry, struct sockaddr *addr, socklen_t *addrlen)
{
	return getpeername(entry->fd, addr, addrlen);
}


int test_tcp_getsockname(struct frr_socket_entry *entry, struct sockaddr *addr, socklen_t *addrlen)
{
	return getsockname(entry->fd, addr, addrlen);
}


int test_tcp_destroy_entry(struct frr_socket_entry *entry)
{
	/* Not much needs to be done for a TCP Test FRR socket. This may
	 * not be the case for other transport protocols!
	 */

	close(entry->fd);
	entry->fd = -1;
	frr_socket_cleanup(entry);
	XFREE(MTYPE_FRR_SOCKET, entry);

	return 0;
}
