// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Title/Function of file
 * Copyright (C) 2025  LabN Consulting, L.L.C.
 */

#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/param.h>

#include "frr_socket.h"
#include "tcp_frr_socket.h"

static const char *dummy_text = "TCPsock";

/* Simple wrappers to test the FRR socket abstraction */
int tcp_socket(int domain, int type)
{
	int fd;
	struct tcp_socket_entry *tcp_entry;

	fd = socket(domain, type, IPPROTO_TCP);
	if (fd < 0)
		return -1;

	tcp_entry = XMALLOC(MTYPE_FRR_SOCKET, sizeof(*tcp_entry));
	if (!tcp_entry) {
		close(fd);
		errno = ENOMEM;
		return -1;
	}

	memset(tcp_entry, 0x00, sizeof(*tcp_entry));
	frr_socket_init(&tcp_entry->entry);
	tcp_entry->entry.protocol = IPPROTO_FRR_TCP;
	tcp_entry->entry.fd = fd;

	strncpy(tcp_entry->dummy, dummy_text, MIN(sizeof(tcp_entry->dummy), sizeof(dummy_text)));
	frr_socket_table_add((struct frr_socket_entry *)tcp_entry);

	return fd;
}


int tcp_bind(struct frr_socket_entry *entry, const struct sockaddr *addr,
			 socklen_t addrlen)
{
	return bind(entry->fd, addr, addrlen);
}


int tcp_connect(struct frr_socket_entry *entry, const struct sockaddr *addr, socklen_t addrlen)
{
	return connect(entry->fd, addr, addrlen);
}


int tcp_listen(struct frr_socket_entry *entry, int backlog)
{
	return listen(entry->fd, backlog);
}


int tcp_accept(struct frr_socket_entry *entry, struct sockaddr *addr, socklen_t *addrlen)
{
	int fd;
	struct tcp_socket_entry *tcp_entry;

	fd = accept(entry->fd, addr, addrlen);
	if (fd < 0)
		return -1;

	tcp_entry = XMALLOC(MTYPE_FRR_SOCKET, sizeof(*tcp_entry));
	if (!tcp_entry) {
		close(fd);
		errno = ENOMEM;
		return -1;
	}

	memset(tcp_entry, 0x00, sizeof(*tcp_entry));
	frr_socket_init(&tcp_entry->entry);
	tcp_entry->entry.protocol = IPPROTO_FRR_TCP;
	tcp_entry->entry.fd = fd;

	strncpy(tcp_entry->dummy, dummy_text, MIN(sizeof(tcp_entry->dummy), sizeof(dummy_text)));
	frr_socket_table_add((struct frr_socket_entry *)tcp_entry);

	return fd;
}


int tcp_close(struct frr_socket_entry *entry)
{
	/* Immediately removes the entry from the table. Then schedules tcp_destroy_entry() for
	 * the event of no other threads holding active references to the entry.
	 */
	return frr_socket_table_delete(entry);
}


ssize_t tcp_writev(struct frr_socket_entry *entry, const struct iovec *iov, int iovcnt)
{
	return writev(entry->fd, iov, iovcnt);
}


ssize_t tcp_read(struct frr_socket_entry *entry, void *buf, size_t count)
{
	return read(entry->fd, buf, count);
}


ssize_t tcp_write(struct frr_socket_entry *entry, const void *buf, size_t count)
{
	return write(entry->fd, buf, count);
}


int tcp_setsockopt(struct frr_socket_entry *entry, int level, int option_name,
			const void *option_value, socklen_t option_len)
{
	return setsockopt(entry->fd, level, option_name, option_value, option_len);
}


int tcp_getsockopt(struct frr_socket_entry *entry, int level, int optname, void *optval,
			socklen_t *optlen)
{
	return getsockopt(entry->fd, level, optname, optval, optlen);
}


int tcp_getpeername(struct frr_socket_entry *entry, struct sockaddr *addr, socklen_t *addrlen)
{
	return getpeername(entry->fd, addr, addrlen);
}


int tcp_getsockname(struct frr_socket_entry *entry, struct sockaddr *addr, socklen_t *addrlen)
{
	return getsockname(entry->fd, addr, addrlen);
}


int tcp_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints,
		    struct addrinfo **res)
{
	int rv;
	struct addrinfo *res_next, frr_hints = {};

	memcpy(&frr_hints, hints, sizeof(*hints));

	/* FRR TCP sockets should requires what a regular TCP socket would require */
	frr_hints.ai_protocol = IPPROTO_TCP;
	rv = getaddrinfo(node, service, &frr_hints, res);
	if (rv != 0)
		return rv;

	/* Change IPPROTO_TCP back to IPPROTO_FRR_TCP */
	for (res_next = *res; res_next != NULL; res_next = res_next->ai_next) {
		if (res_next->ai_protocol == IPPROTO_TCP)
			res_next->ai_protocol = IPPROTO_FRR_TCP;
	}
	return 0;
}


int tcp_destroy_entry(struct frr_socket_entry *entry)
{
	struct tcp_socket_entry *tcp_entry = (struct tcp_socket_entry *)entry;
	/* Not much needs to be done for a TCP FRR socket since we are simply wrapping the kernel.
	 * This will likely not be the case for other transport protocols, which have operational
	 * state!
	 */

	close(entry->fd);
	entry->fd = -1;
	assert(strncmp(tcp_entry->dummy, dummy_text,
		       MIN(sizeof(tcp_entry->dummy), sizeof(dummy_text))) == 0);
	frr_socket_cleanup(entry);
	XFREE(MTYPE_FRR_SOCKET, entry);

	return 0;
}
