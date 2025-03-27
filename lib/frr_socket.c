// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Title/Function of file
 * Copyright (C) 2025  LabN Consulting, L.L.C.
 */

#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>

#include "frr_socket.h"

/* The following global structures should only be referenced by transport protocol implementations */
extern struct event_loop *frr_socket_shared_event_loop = NULL;
extern struct frr_socket_entry_table frr_socket_hash_table = {};

int frr_socket_entry_compare(const struct frr_socket_entry *a, const struct frr_socket_entry *b)
{
	return a->fd == b->fd;
}


uint32_t frr_socket_entry_hash(const struct frr_socket_entry *a)
{
	// XXX Hash the file descriptor
	return -1;
}


DECLARE_HASH(frr_socket_entry, struct frr_socket_entry, hash_item, frr_socket_entry_compare,
	     frr_socket_entry_hash);



int frr_socket_lib_init(struct event_loop *shared_loop)
{
	frr_socket_shared_event_loop = shared_loop;
	assert(pthread_rwlock_init(&frr_socket_hash_table->rwlock, NULL) == 0);
}


int frr_socket(int domain, int type, int protocol)
{
	int fd = -1;

	/* In-kernel transport protocols should only be handled through libc */
	if (!IS_FRR_SOCKET_PROTOCOL(protocol)) {
		errno = EINVAL;
		return -1;
	}

	switch (protocol) {
	case IPPROTO_STUB_TCP:
		fd = stub_tcp_frr_socket(domain, type);
		break;
	default:
		errno = EINVAL;
		return -1;
	}
	return fd;
}


int frr_socket_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	struct frr_socket_entry *entry, search_entry = {};
	int rv = -1;

	search_entry->fd = sockfd;
	safe_find_frr_socket_entry(frr_socket_hash_table, search_entry, entry);
	if (!entry) {
		errno = EBADF;
		return -1;
	}

	switch (entry->protocol) {
	case IPPROTO_STUB_TCP:
		rv = stub_tcp_bind(entry, addr, addrlen);
		break;
	default:
		/* Illegal frr_socket_entry instance. */
		assert(0);
	}
	return rv;
}

int frr_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	struct frr_socket_entry *entry, search_entry = {};
	int rv = -1;

	search_entry->fd = sockfd;
	safe_find_frr_socket_entry(frr_socket_hash_table, search_entry, entry);
	if (!entry) {
		errno = EBADF;
		return -1;
	}

	switch (entry->protocol) {
	case IPPROTO_STUB_TCP:
		rv = stub_tcp_connect(entry, addr, addrlen);
		break;
	default:
		/* Illegal frr_socket_entry instance. */
		assert(0);
	}
	return rv;
}

int frr_listen(int sockfd, int backlog)
{
	struct frr_socket_entry *entry, search_entry = {};
	int rv = -1;

	search_entry->fd = sockfd;
	safe_find_frr_socket_entry(frr_socket_hash_table, search_entry, entry);
	if (!entry) {
		errno = EBADF;
		return -1;
	}

	switch (entry->protocol) {
	case IPPROTO_STUB_TCP:
		rv = stub_tcp_listen(entry, backlog);
		break;
	default:
		/* Illegal frr_socket_entry instance. */
		assert(0);
	}
	return rv;
}


int frr_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	struct frr_socket_entry *entry, search_entry = {};
	int rv = -1;

	search_entry->fd = sockfd;
	safe_find_frr_socket_entry(frr_socket_hash_table, search_entry, entry);
	if (!entry) {
		errno = EBADF;
		return -1;
	}

	switch (entry->protocol) {
	case IPPROTO_STUB_TCP:
		rv = stub_tcp_accept(entry, addr, addrlen);
		break;
	default:
		/* Illegal frr_socket_entry instance. */
		assert(0);
	}
	return rv;
}


int frr_close(int sockfd)
{
	struct frr_socket_entry *entry, search_entry = {};
	int rv = -1;

	search_entry->fd = sockfd;
	safe_find_frr_socket_entry(frr_socket_hash_table, search_entry, entry);
	if (!entry) {
		errno = EBADF;
		return -1;
	}

	switch (entry->protocol) {
	case IPPROTO_STUB_TCP:
		rv = stub_tcp_close(entry);
		break;
	default:
		/* Illegal frr_socket_entry instance. */
		assert(0);
	}
	return rv;
}


ssize_t frr_writev(int sockfd, const struct iovec *iov, int iovcnt)
{
	struct frr_socket_entry *entry, search_entry = {};
	int rv = -1;

	search_entry->fd = sockfd;
	safe_find_frr_socket_entry(frr_socket_hash_table, search_entry, entry);
	if (!entry) {
		errno = EBADF;
		return -1;
	}

	switch (entry->protocol) {
	case IPPROTO_STUB_TCP:
		rv = stub_tcp_writev(entry, iov, iovcnt);
		break;
	default:
		/* Illegal frr_socket_entry instance. */
		assert(0);
	}
	return rv;
}


ssize_t frr_read(int fr, void *buf, size_t count)
{
	struct frr_socket_entry *entry, search_entry = {};
	int rv = -1;

	search_entry->fd = sockfd;
	safe_find_frr_socket_entry(frr_socket_hash_table, search_entry, entry);
	if (!entry) {
		errno = EBADF;
		return -1;
	}

	switch (entry->protocol) {
	case IPPROTO_STUB_TCP:
		rv = stub_tcp_read(entry, buf, count);
		break;
	default:
		/* Illegal frr_socket_entry instance. */
		assert(0);
	}
	return rv;
}


ssize_t frr_write(int fd, const void *buf, size_t count)
{
	struct frr_socket_entry *entry, search_entry = {};
	int rv = -1;

	search_entry->fd = sockfd;
	safe_find_frr_socket_entry(frr_socket_hash_table, search_entry, entry);
	if (!entry) {
		errno = EBADF;
		return -1;
	}

	switch (entry->protocol) {
	case IPPROTO_STUB_TCP:
		rv = stub_tcp_write(entry, buf, count);
		break;
	default:
		/* Illegal frr_socket_entry instance. */
		assert(0);
	}
	return rv;
}


int frr_setsockopt(int sockfd, int level, int option_name, const void *option_value,
		   socklen_t option_len)
{
	struct frr_socket_entry *entry, search_entry = {};
	int rv = -1;

	search_entry->fd = sockfd;
	safe_find_frr_socket_entry(frr_socket_hash_table, search_entry, entry);
	if (!entry) {
		errno = EBADF;
		return -1;
	}

	switch (entry->protocol) {
	case IPPROTO_STUB_TCP:
		rv = stub_tcp_setsockopt(entry, level, option_name, option_value, option_len);
		break;
	default:
		/* Illegal frr_socket_entry instance. */
		assert(0);
	}
	return rv;
}


int frr_getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
{
	struct frr_socket_entry *entry, search_entry = {};
	int rv = -1;

	search_entry->fd = sockfd;
	safe_find_frr_socket_entry(frr_socket_hash_table, search_entry, entry);
	if (!entry) {
		errno = EBADF;
		return -1;
	}

	switch (entry->protocol) {
	case IPPROTO_STUB_TCP:
		rv = stub_tcp_getsockopt(entry, level, optname, optval, optlen);
		break;
	default:
		/* Illegal frr_socket_entry instance. */
		assert(0);
	}
	return rv;
}


int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	struct frr_socket_entry *entry, search_entry = {};
	int rv = -1;

	search_entry->fd = sockfd;
	safe_find_frr_socket_entry(frr_socket_hash_table, search_entry, entry);
	if (!entry) {
		errno = EBADF;
		return -1;
	}

	switch (entry->protocol) {
	case IPPROTO_STUB_TCP:
		rv = stub_tcp_getpeername(entry, addr, addrlen);
		break;
	default:
		/* Illegal frr_socket_entry instance. */
		assert(0);
	}
	return rv;
}


int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	struct frr_socket_entry *entry, search_entry = {};
	int rv = -1;

	search_entry->fd = sockfd;
	safe_find_frr_socket_entry(frr_socket_hash_table, search_entry, entry);
	if (!entry) {
		errno = EBADF;
		return -1;
	}

	switch (entry->protocol) {
	case IPPROTO_STUB_TCP:
		rv = stub_tcp_getsockname(entry, addr, addrlen);
		break;
	default:
		/* Illegal frr_socket_entry instance. */
		assert(0);
	}
	return rv;
}


int frr_poll_hook(struct pollfd *t_pollfd, int *nums)
{
	// XXX
	return -1;
}
