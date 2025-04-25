// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Title/Function of file
 * Copyright (C) 2025  LabN Consulting, L.L.C.
 */

#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>

#include "frr_socket.h"
#include "tcp_frr_socket.h"
#include "ngtcp2_frr_socket.h"  /* XXX Make conditional */

int frr_socket_entry_compare(const struct frr_socket_entry *a, const struct frr_socket_entry *b);
uint32_t frr_socket_entry_hash(const struct frr_socket_entry *a);
static void _frr_socket_destroy(struct frr_socket_entry *entry);

/* The following global structures should only be referenced by transport protocol implementations */
struct event_loop *frr_socket_threadmaster = NULL;
struct frr_socket_entry_table frr_socket_table = {};

DEFINE_MTYPE(LIB, FRR_SOCKET, "FRR socket entry state");

int frr_socket_lib_init(struct event_loop *shared_threadmaster)
{
	frr_socket_threadmaster = shared_threadmaster;
	assert(pthread_rwlock_init(&frr_socket_table.rwlock, NULL) == 0);

	return 0;
}


int frr_socket_lib_finish(void)
{
	struct frr_socket_entry *entry;

	/* The library should have been initialized */
	assert(frr_socket_threadmaster);

	frr_socket_threadmaster = NULL;
	pthread_rwlock_wrlock(&frr_socket_table.rwlock);

	rcu_read_lock();
	while ((entry = frr_socket_entry_pop(&frr_socket_table.table))) {
		rcu_call(_frr_socket_destroy, entry, rcu_head);
	}
	rcu_read_unlock();

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

	if (!IS_SOCKET_LIB_READY)
		return socket(domain, type, protocol);

	switch (protocol) {
	case IPPROTO_FRR_TCP:
		fd = tcp_socket(domain, type);
		break;
	case IPPROTO_QUIC:
		fd = quic_socket(domain, type);
		break;
	default:
		/* It is assumed that unrecognized protocols are in-kernel */
		return socket(domain, type, protocol);
	}

	/* Sanity check: transport protocol inserted an frr_socket_entry */
	if (fd > 0) {
		search_entry.fd = fd;
		frr_socket_table_find(&search_entry, check_entry);
		assert(check_entry);
		assert(check_entry->protocol == protocol);
	}

	return fd;
}


int frr_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	struct frr_socket_entry search_entry = {};
	int rv = -1;

	if (!IS_SOCKET_LIB_READY)
		return bind(sockfd, addr, addrlen);

	search_entry.fd = sockfd;
	frr_socket_table_find(&search_entry, found_entry);
	if (!found_entry)
		return bind(sockfd, addr, addrlen);

	switch (found_entry->protocol) {
	case IPPROTO_FRR_TCP:
		rv = tcp_bind(found_entry, addr, addrlen);
		break;
	case IPPROTO_QUIC:
		rv = quic_bind(found_entry, addr, addrlen);
		break;
	default:
		/* Illegal frr_socket_entry instance. */
		assert(0);
	}
	return rv;
}

int frr_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	struct frr_socket_entry search_entry = {};
	int rv = -1;

	if (!IS_SOCKET_LIB_READY)
		return connect(sockfd, addr, addrlen);

	search_entry.fd = sockfd;
	frr_socket_table_find(&search_entry, found_entry);
	if (!found_entry)
		return connect(sockfd, addr, addrlen);

	switch (found_entry->protocol) {
	case IPPROTO_FRR_TCP:
		rv = tcp_connect(found_entry, addr, addrlen);
		break;
	case IPPROTO_QUIC:
		rv = quic_connect(found_entry, addr, addrlen);
		break;
	default:
		/* Illegal frr_socket_entry instance. */
		assert(0);
	}
	return rv;
}

int frr_listen(int sockfd, int backlog)
{
	struct frr_socket_entry search_entry = {};
	int rv = -1;

	if (!IS_SOCKET_LIB_READY)
		return listen(sockfd, backlog);

	search_entry.fd = sockfd;
	frr_socket_table_find(&search_entry, found_entry);
	if (!found_entry)
		return listen(sockfd, backlog);

	switch (found_entry->protocol) {
	case IPPROTO_FRR_TCP:
		rv = tcp_listen(found_entry, backlog);
		break;
	case IPPROTO_QUIC:
		rv = quic_listen(found_entry, backlog);
		break;
	default:
		/* Illegal frr_socket_entry instance. */
		assert(0);
	}
	return rv;
}


int frr_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	struct frr_socket_entry search_entry = {};
	int fd = -1;

	if (!IS_SOCKET_LIB_READY)
		return accept(sockfd, addr, addrlen);

	search_entry.fd = sockfd;
	frr_socket_table_find(&search_entry, found_entry);
	if (!found_entry)
		return accept(sockfd, addr, addrlen);

	switch (found_entry->protocol) {
	case IPPROTO_FRR_TCP:
		fd = tcp_accept(found_entry, addr, addrlen);
		break;
	case IPPROTO_QUIC:
		fd = quic_accept(found_entry, addr, addrlen);
		break;
	default:
		/* Illegal frr_socket_entry instance. */
		assert(0);
	}

	/* Sanity check: transport protocol inserted an frr_socket_entry */
	if (fd > 0) {
		search_entry.fd = fd;
		frr_socket_table_find(&search_entry, check_entry);
		assert(check_entry);
		assert(check_entry->protocol == found_entry->protocol);
	}

	return fd;
}


int frr_close(int sockfd)
{
	struct frr_socket_entry search_entry = {};
	int rv = -1;

	if (!IS_SOCKET_LIB_READY)
		return close(sockfd);

	search_entry.fd = sockfd;
	frr_socket_table_find(&search_entry, found_entry);
	if (!found_entry)
		return close(sockfd);

	switch (found_entry->protocol) {
	case IPPROTO_FRR_TCP:
		rv = tcp_close(found_entry);
		break;
	case IPPROTO_QUIC:
		rv = quic_close(found_entry);
		break;
	default:
		/* Illegal frr_socket_entry instance. */
		assert(0);
	}
	return rv;
}


ssize_t frr_writev(int fd, const struct iovec *iov, int iovcnt)
{
	struct frr_socket_entry search_entry = {};
	int rv = -1;

	if (!IS_SOCKET_LIB_READY)
		return writev(fd, iov, iovcnt);

	search_entry.fd = fd;
	frr_socket_table_find(&search_entry, found_entry);
	if (!found_entry)
		return writev(fd, iov, iovcnt);

	switch (found_entry->protocol) {
	case IPPROTO_FRR_TCP:
		rv = tcp_writev(found_entry, iov, iovcnt);
		break;
	case IPPROTO_QUIC:
		rv = quic_writev(found_entry, iov, iovcnt);
		break;
	default:
		/* Illegal frr_socket_entry instance. */
		assert(0);
	}
	return rv;
}


ssize_t frr_read(int fd, void *buf, size_t count)
{
	struct frr_socket_entry search_entry = {};
	int rv = -1;

	if (!IS_SOCKET_LIB_READY)
		return read(fd, buf, count);

	search_entry.fd = fd;
	frr_socket_table_find(&search_entry, found_entry);
	if (!found_entry)
		return read(fd, buf, count);

	switch (found_entry->protocol) {
	case IPPROTO_FRR_TCP:
		rv = tcp_read(found_entry, buf, count);
		break;
	case IPPROTO_QUIC:
		rv = quic_read(found_entry, buf, count);
		break;
	default:
		/* Illegal frr_socket_entry instance. */
		assert(0);
	}
	return rv;
}


ssize_t frr_write(int fd, const void *buf, size_t count)
{
	struct frr_socket_entry search_entry = {};
	int rv = -1;

	if (!IS_SOCKET_LIB_READY)
		return write(fd, buf, count);

	search_entry.fd = fd;
	frr_socket_table_find(&search_entry, found_entry);
	if (!found_entry)
		return write(fd, buf, count);

	switch (found_entry->protocol) {
	case IPPROTO_FRR_TCP:
		rv = tcp_write(found_entry, buf, count);
		break;
	case IPPROTO_QUIC:
		rv = quic_write(found_entry, buf, count);
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
	struct frr_socket_entry search_entry = {};
	int rv = -1;

	if (!IS_SOCKET_LIB_READY)
		return setsockopt(sockfd, level, option_name, option_value, option_len);

	search_entry.fd = sockfd;
	frr_socket_table_find(&search_entry, found_entry);
	if (!found_entry)
		return setsockopt(sockfd, level, option_name, option_value, option_len);

	switch (found_entry->protocol) {
	case IPPROTO_FRR_TCP:
		rv = tcp_setsockopt(found_entry, level, option_name, option_value, option_len);
		break;
	case IPPROTO_QUIC:
		rv = quic_setsockopt(found_entry, level, option_name, option_value, option_len);
		break;
	default:
		/* Illegal frr_socket_entry instance. */
		assert(0);
	}
	return rv;
}


int frr_getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
{
	struct frr_socket_entry search_entry = {};
	int rv = -1;

	if (!IS_SOCKET_LIB_READY)
		return getsockopt(sockfd, level, optname, optval, optlen);

	search_entry.fd = sockfd;
	frr_socket_table_find(&search_entry, found_entry);
	if (!found_entry)
		return getsockopt(sockfd, level, optname, optval, optlen);

	switch (found_entry->protocol) {
	case IPPROTO_FRR_TCP:
		rv = tcp_getsockopt(found_entry, level, optname, optval, optlen);
		break;
	case IPPROTO_QUIC:
		rv = quic_getsockopt(found_entry, level, optname, optval, optlen);
		break;
	default:
		/* Illegal frr_socket_entry instance. */
		assert(0);
	}
	return rv;
}


int frr_getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	struct frr_socket_entry search_entry = {};
	int rv = -1;

	if (!IS_SOCKET_LIB_READY)
		return getpeername(sockfd, addr, addrlen);

	search_entry.fd = sockfd;
	frr_socket_table_find(&search_entry, found_entry);
	if (!found_entry)
		return getpeername(sockfd, addr, addrlen);

	switch (found_entry->protocol) {
	case IPPROTO_FRR_TCP:
		rv = tcp_getpeername(found_entry, addr, addrlen);
		break;
	case IPPROTO_QUIC:
		rv = quic_getpeername(found_entry, addr, addrlen);
		break;
	default:
		/* Illegal frr_socket_entry instance. */
		assert(0);
	}
	return rv;
}


int frr_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	struct frr_socket_entry search_entry = {};
	int rv = -1;

	if (!IS_SOCKET_LIB_READY)
		return getsockname(sockfd, addr, addrlen);

	search_entry.fd = sockfd;
	frr_socket_table_find(&search_entry, found_entry);
	if (!found_entry)
		return getsockname(sockfd, addr, addrlen);

	switch (found_entry->protocol) {
	case IPPROTO_FRR_TCP:
		rv = tcp_getsockname(found_entry, addr, addrlen);
		break;
	case IPPROTO_QUIC:
		rv = quic_getsockname(found_entry, addr, addrlen);
		break;
	default:
		/* Illegal frr_socket_entry instance. */
		assert(0);
	}
	return rv;
}


int frr_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints,
		    struct addrinfo **res)
{
	int rv;

	if (!IS_SOCKET_LIB_READY)
		return getaddrinfo(node, service, hints, res);

	switch (hints->ai_protocol) {
	case IPPROTO_FRR_TCP:
		rv =  tcp_getaddrinfo(node, service, hints, res);
		break;
	case IPPROTO_QUIC:
		rv =  quic_getaddrinfo(node, service, hints, res);
		break;
	default:
		/* It is assumed that unrecognized protocols are in-kernel */
		return getaddrinfo(node, service, hints, res);
	}

	return rv;
}


/* XXX Provides no functionality, but is added for consistency (i.e. changes in frr_getaddrinfo) */
void frr_freeaddrinfo(struct addrinfo *res)
{
	return freeaddrinfo(res);
}


int frr_poll_hook(struct pollfd *fds, nfds_t nfds, int poll_rv)
{
	struct frr_socket_entry search_entry = {};
	struct pollfd *tmp_fd;
	int rv = poll_rv;

	if (poll_rv < 0 || !IS_SOCKET_LIB_READY)
		return poll_rv;

	for (nfds_t i = 0; i < nfds; i++) {
		tmp_fd = &fds[i];
		search_entry.fd = tmp_fd->fd;
		frr_socket_table_find(&search_entry, found_entry);
		if (!found_entry)
			continue;

		switch (found_entry->protocol) {
		case IPPROTO_FRR_TCP:
			/* This protocol never overwrites results */
			continue;
		case IPPROTO_QUIC:
			/* XXX Implement me */
			continue;
		default:
			/* Illegal frr_socket_entry instance. */
			assert(0);
		}
	}

	return rv;
}


int frr_socket_table_add(struct frr_socket_entry *entry)
{
	assert(IS_SOCKET_LIB_READY);

	pthread_rwlock_wrlock(&frr_socket_table.rwlock);
	/* If we ended up removing an entry, then something is going very wrong */
	assert(frr_socket_entry_add(&frr_socket_table.table, entry) == NULL);
	entry->ref_count++;
	zlog_debug("New entry added to socket table: fd=%d protocol=%d", entry->fd, entry->protocol);
	pthread_rwlock_unlock(&frr_socket_table.rwlock);

	return 0;
}


int frr_socket_table_delete(struct frr_socket_entry *entry)
{
	struct frr_socket_entry *found_entry, search_entry = {};
	search_entry.fd = entry->fd;

	assert(IS_SOCKET_LIB_READY);
	if (!entry) {
		errno = EBADF;
		return -1;
	}


	/* To be safe, first verify that the expected entry is in the table before removal */
	pthread_rwlock_wrlock(&frr_socket_table.rwlock);
	rcu_read_lock();
	found_entry = frr_socket_entry_find(&frr_socket_table.table, &search_entry);
	if (entry == found_entry) {
		found_entry = frr_socket_entry_del(&frr_socket_table.table, entry);
		assert(entry == found_entry);
	}
	zlog_debug("Entry deleted from socket table: fd=%d protocol=%d", entry->fd, entry->protocol);
	pthread_rwlock_unlock(&frr_socket_table.rwlock);

	if (!entry) {
		//XXX Some other error?
		rcu_read_unlock();
		errno = EBADF;
		return -1;
	}

	/* Blocks the rcu thread, however, only the transport protocol can clean up its own state */
	rcu_call(_frr_socket_destroy, entry, rcu_head);
	rcu_read_unlock();

	return 0;
}


static void _frr_socket_destroy(struct frr_socket_entry *entry)
{
	zlog_debug("Socket entry is being destroyed: fd=%d protocol=%d", entry->fd, entry->protocol);
	switch (entry->protocol) {
	case IPPROTO_FRR_TCP:
		tcp_destroy_entry(entry);
		break;
	case IPPROTO_QUIC:
		quic_destroy_entry(entry);
		break;
	default:
		/* Unknown transport protocol. Illegal entry */
		assert(0);
	}
}
