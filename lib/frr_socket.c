// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Title/Function of file
 * Copyright (C) 2025  LabN Consulting, L.L.C.
 */

#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>

#include "frr_socket.h"
#include "jhash.h"
#include "test_tcp_frr_socket.h"

int frr_socket_entry_compare(const struct frr_socket_entry *a, const struct frr_socket_entry *b);
uint32_t frr_socket_entry_hash(const struct frr_socket_entry *a);
void _frr_socket_destroy_event(struct event *thread);
static void _frr_socket_destroy(struct frr_socket_entry *entry);

/* The following global structures should only be referenced by transport protocol implementations */
struct event_loop *frr_socket_shared_event_loop = NULL;
struct frr_socket_entry_table frr_socket_table = {};

DEFINE_MTYPE(LIB, FRR_SOCKET, "FRR socket entry state");

int frr_socket_entry_compare(const struct frr_socket_entry *a, const struct frr_socket_entry *b)
{
	return numcmp(a->fd, b->fd);
}


uint32_t frr_socket_entry_hash(const struct frr_socket_entry *a)
{
	return jhash_1word(a->fd, 0x8ae55ea8);
}


DECLARE_HASH(frr_socket_entry, struct frr_socket_entry, hash_item, frr_socket_entry_compare,
	     frr_socket_entry_hash);


int frr_socket_lib_init(struct event_loop *shared_loop)
{
	frr_socket_shared_event_loop = shared_loop;
	assert(pthread_rwlock_init(&frr_socket_table.rwlock, NULL) == 0);

	return 0;
}


int frr_socket_lib_finish(void)
{
	struct frr_socket_entry *entry;

	frr_socket_shared_event_loop = NULL;
	pthread_rwlock_wrlock(&frr_socket_table.rwlock);

	while ((entry = frr_socket_entry_pop(&frr_socket_table.table)))
		_frr_socket_destroy(entry);

	pthread_rwlock_destroy(&frr_socket_table.rwlock);

	return 0;
}


int frr_socket_init(struct frr_socket_entry *entry)
{
	return pthread_mutex_init(&entry->lock, NULL);
}

// XXX explanation
int frr_socket_cleanup(struct frr_socket_entry *entry)
{
	return pthread_mutex_destroy(&entry->lock);
}


int frr_socket(int domain, int type, int protocol)
{
	struct frr_socket_entry search_entry = {};
	int fd = -1;

	switch (protocol) {
	case IPPROTO_TEST_TCP:
		fd = test_tcp_socket(domain, type);
		break;
	default:
		/* It is assumed that unrecognized protocols are in-kernel */
		return socket(domain, type, protocol);
	}

	/* Sanity check: transport protocol inserted an frr_socket_entry */
	if (fd > 0) {
		struct frr_socket_entry *rv_entry;
		search_entry.fd = fd;
		frr_socket_table_find(&frr_socket_table, &search_entry, rv_entry);
		assert(rv_entry);
		assert(rv_entry->protocol == protocol);
	}

	return fd;
}


int frr_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	struct frr_socket_entry *entry, search_entry = {};
	int rv = -1;

	search_entry.fd = sockfd;
	frr_socket_table_find(&frr_socket_table, &search_entry, entry);
	if (!entry)
		return bind(sockfd, addr, addrlen);

	switch (entry->protocol) {
	case IPPROTO_TEST_TCP:
		rv = test_tcp_bind(entry, addr, addrlen);
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

	search_entry.fd = sockfd;
	frr_socket_table_find(&frr_socket_table, &search_entry, entry);
	if (!entry)
		return connect(sockfd, addr, addrlen);

	switch (entry->protocol) {
	case IPPROTO_TEST_TCP:
		rv = test_tcp_connect(entry, addr, addrlen);
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

	search_entry.fd = sockfd;
	frr_socket_table_find(&frr_socket_table, &search_entry, entry);
	if (!entry)
		return listen(sockfd, backlog);

	switch (entry->protocol) {
	case IPPROTO_TEST_TCP:
		rv = test_tcp_listen(entry, backlog);
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
	int fd = -1;

	search_entry.fd = sockfd;
	frr_socket_table_find(&frr_socket_table, &search_entry, entry);
	if (!entry)
		return accept(sockfd, addr, addrlen);

	switch (entry->protocol) {
	case IPPROTO_TEST_TCP:
		fd = test_tcp_accept(entry, addr, addrlen);
		break;
	default:
		/* Illegal frr_socket_entry instance. */
		assert(0);
	}

	/* Sanity check: transport protocol inserted an frr_socket_entry */
	if (fd > 0) {
		struct frr_socket_entry *rv_entry;
		search_entry.fd = fd;
		frr_socket_table_find(&frr_socket_table, &search_entry, rv_entry);
		assert(rv_entry);
		assert(rv_entry->protocol == entry->protocol);
	}

	return fd;
}


int frr_close(int sockfd)
{
	struct frr_socket_entry *entry, search_entry = {};
	int rv = -1;

	search_entry.fd = sockfd;
	frr_socket_table_find(&frr_socket_table, &search_entry, entry);
	if (!entry)
		return close(sockfd);

	switch (entry->protocol) {
	case IPPROTO_TEST_TCP:
		rv = test_tcp_close(entry);
		break;
	default:
		/* Illegal frr_socket_entry instance. */
		assert(0);
	}
	return rv;
}


ssize_t frr_writev(int fd, const struct iovec *iov, int iovcnt)
{
	struct frr_socket_entry *entry, search_entry = {};
	int rv = -1;

	search_entry.fd = fd;
	frr_socket_table_find(&frr_socket_table, &search_entry, entry);
	if (!entry)
		return writev(fd, iov, iovcnt);

	switch (entry->protocol) {
	case IPPROTO_TEST_TCP:
		rv = test_tcp_writev(entry, iov, iovcnt);
		break;
	default:
		/* Illegal frr_socket_entry instance. */
		assert(0);
	}
	return rv;
}


ssize_t frr_read(int fd, void *buf, size_t count)
{
	struct frr_socket_entry *entry, search_entry = {};
	int rv = -1;

	search_entry.fd = fd;
	frr_socket_table_find(&frr_socket_table, &search_entry, entry);
	if (!entry)
		return read(fd, buf, count);

	switch (entry->protocol) {
	case IPPROTO_TEST_TCP:
		rv = test_tcp_read(entry, buf, count);
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

	search_entry.fd = fd;
	frr_socket_table_find(&frr_socket_table, &search_entry, entry);
	if (!entry)
		return write(fd, buf, count);

	switch (entry->protocol) {
	case IPPROTO_TEST_TCP:
		rv = test_tcp_write(entry, buf, count);
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

	search_entry.fd = sockfd;
	frr_socket_table_find(&frr_socket_table, &search_entry, entry);
	if (!entry)
		return setsockopt(sockfd, level, option_name, option_value, option_len);

	switch (entry->protocol) {
	case IPPROTO_TEST_TCP:
		rv = test_tcp_setsockopt(entry, level, option_name, option_value, option_len);
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

	search_entry.fd = sockfd;
	frr_socket_table_find(&frr_socket_table, &search_entry, entry);
	if (!entry)
		return getsockopt(sockfd, level, optname, optval, optlen);

	switch (entry->protocol) {
	case IPPROTO_TEST_TCP:
		rv = test_tcp_getsockopt(entry, level, optname, optval, optlen);
		break;
	default:
		/* Illegal frr_socket_entry instance. */
		assert(0);
	}
	return rv;
}


int frr_getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	struct frr_socket_entry *entry, search_entry = {};
	int rv = -1;

	search_entry.fd = sockfd;
	frr_socket_table_find(&frr_socket_table, &search_entry, entry);
	if (!entry)
		return getpeername(sockfd, addr, addrlen);

	switch (entry->protocol) {
	case IPPROTO_TEST_TCP:
		rv = test_tcp_getpeername(entry, addr, addrlen);
		break;
	default:
		/* Illegal frr_socket_entry instance. */
		assert(0);
	}
	return rv;
}


int frr_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	struct frr_socket_entry *entry, search_entry = {};
	int rv = -1;

	search_entry.fd = sockfd;
	frr_socket_table_find(&frr_socket_table, &search_entry, entry);
	if (!entry)
		return getsockname(sockfd, addr, addrlen);

	switch (entry->protocol) {
	case IPPROTO_TEST_TCP:
		rv = test_tcp_getsockname(entry, addr, addrlen);
		break;
	default:
		/* Illegal frr_socket_entry instance. */
		assert(0);
	}
	return rv;
}


int frr_poll_hook(struct pollfd *t_pollfd, int *nums)
{
	struct frr_socket_entry *entry, search_entry = {};
	int rv = -1;

	search_entry.fd = t_pollfd->fd;
	frr_socket_table_find(&frr_socket_table, &search_entry, entry);
	if (!entry)
		return 0;

	switch (entry->protocol) {
	case IPPROTO_TEST_TCP:
		/* This protocol never overwrites results */
		rv = 0;
		break;
	default:
		/* Illegal frr_socket_entry instance. */
		assert(0);
	}
	return rv;
}


struct frr_socket_entry *_frr_socket_table_find(struct frr_socket_entry_head *hash_table,
						struct frr_socket_entry *search_entry)
{
	return frr_socket_entry_find(hash_table, search_entry);
}


int frr_socket_table_add(struct frr_socket_entry_table *entry_table, struct frr_socket_entry *entry)
{
	pthread_rwlock_wrlock(&entry_table->rwlock);
	/* If we ended up removing an entry, then something is going very wrong */
	assert(frr_socket_entry_add(&(entry_table)->table, entry) == NULL);
	entry->ref_count++;
	pthread_rwlock_unlock(&(entry_table)->rwlock);

	return 0;
}


int frr_socket_table_delete_async(struct frr_socket_entry_table *entry_table,
				  struct frr_socket_entry *entry)
{
	struct frr_socket_entry *rv_entry, search_entry = {};
	search_entry.fd = entry->fd;

	if (!entry) {
		errno = EBADF;
		return -1;
	}

	/* To be safe, first verify that the expected entry is in the table before removal */
	pthread_rwlock_wrlock(&entry_table->rwlock);
	rv_entry = frr_socket_entry_find(&entry_table->table, &search_entry);
	if (entry == rv_entry) {
		rv_entry = frr_socket_entry_del(&entry_table->table, entry);
		assert(entry == rv_entry);
	}
	pthread_rwlock_unlock(&entry_table->rwlock);

	if (!entry) {
		//XXX Some other error?
		errno = EBADF;
		return -1;
	}

	/* At this point, the entry is no longer in the table. However, it may still be in-scope
	 * within another thread. Deallocation only completes when a single reference is held.
	 */
	if (!entry->destroy_event)
		event_add_timer_msec(frr_socket_shared_event_loop, _frr_socket_destroy_event, entry,
				     0, &entry->destroy_event);

	return 0;
}


void _frr_socket_destroy_event(struct event *thread)
{
	struct frr_socket_entry *entry = EVENT_ARG(thread);

	/* We should hold the only remaining reference */
	if (entry->ref_count > 1) {
		event_add_timer_msec(frr_socket_shared_event_loop, _frr_socket_destroy_event, entry,
				     1000, &entry->destroy_event);
		return;
	}

	_frr_socket_destroy(entry);
}


static void _frr_socket_destroy(struct frr_socket_entry *entry)
{
	switch (entry->protocol) {
	case IPPROTO_TEST_TCP:
		test_tcp_destroy_entry(entry);
		break;
	default:
		/* Unknown transport protocol. Illegal entry */
		assert(0);
	}
}
