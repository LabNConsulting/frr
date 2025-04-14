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
#include "ngtcp2_frr_socket.h"

/* Simple wrappers to test the FRR socket abstraction */
int quic_socket(int domain, int type)
{
	int fd;
	struct ngtcp2_socket_entry *ngtcp2_entry;

	/* A user should understand this as a stream socket (even when UDP is underlying) */
	if (type != SOCK_STREAM) {
		errno = EPROTONOSUPPORT;
		return -1;
	}

	/* ngtcp2 supports IPv6. However, we will not provide that support initially */
	if (domain != AF_INET) {
		errno = EPROTONOSUPPORT;
		return -1;
	}

	fd = socket(domain, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
		return -1;

	ngtcp2_entry = XMALLOC(MTYPE_FRR_SOCKET, sizeof(*ngtcp2_entry));
	if (!ngtcp2_entry) {
		close(fd);
		errno = ENOMEM;
		return -1;
	}

	memset(ngtcp2_entry, 0x00, sizeof(*ngtcp2_entry));
	frr_socket_init(&ngtcp2_entry->entry);
	ngtcp2_entry->entry.protocol = IPPROTO_QUIC;
	ngtcp2_entry->entry.fd = fd;

	frr_socket_table_add((struct frr_socket_entry *)ngtcp2_entry);

	return fd;
}


int quic_bind(struct frr_socket_entry *entry, const struct sockaddr *addr,
			 socklen_t addrlen)
{
	return bind(entry->fd, addr, addrlen);
}


int quic_connect(struct frr_socket_entry *entry, const struct sockaddr *addr, socklen_t addrlen)
{
	return connect(entry->fd, addr, addrlen);
}


int quic_listen(struct frr_socket_entry *entry, int backlog)
{
	return listen(entry->fd, backlog);
}


int quic_accept(struct frr_socket_entry *entry, struct sockaddr *addr, socklen_t *addrlen)
{
	int fd;
	struct ngtcp2_socket_entry *ngtcp2_entry;

	// XXX Not how we want to do accept
	fd = accept(entry->fd, addr, addrlen);
	if (fd < 0)
		return -1;

	ngtcp2_entry = XMALLOC(MTYPE_FRR_SOCKET, sizeof(*ngtcp2_entry));
	if (!ngtcp2_entry) {
		close(fd);
		errno = ENOMEM;
		return -1;
	}

	memset(ngtcp2_entry, 0x00, sizeof(*ngtcp2_entry));
	frr_socket_init(&ngtcp2_entry->entry);
	ngtcp2_entry->entry.protocol = IPPROTO_QUIC;
	ngtcp2_entry->entry.fd = fd;

	frr_socket_table_add((struct frr_socket_entry *)ngtcp2_entry);

	return fd;
}


int quic_close(struct frr_socket_entry *entry)
{
	/* Immediately removes the entry from the table. Then schedules ngtcp2_destroy_entry() for
	 * the event of no other threads holding active references to the entry.
	 */
	return frr_socket_table_delete(entry);
}


ssize_t quic_writev(struct frr_socket_entry *entry, const struct iovec *iov, int iovcnt)
{
	return writev(entry->fd, iov, iovcnt);
}


ssize_t quic_read(struct frr_socket_entry *entry, void *buf, size_t count)
{
	return read(entry->fd, buf, count);
}


ssize_t quic_write(struct frr_socket_entry *entry, const void *buf, size_t count)
{
	return write(entry->fd, buf, count);
}


int quic_setsockopt(struct frr_socket_entry *entry, int level, int option_name,
			const void *option_value, socklen_t option_len)
{
	return setsockopt(entry->fd, level, option_name, option_value, option_len);
}


int quic_getsockopt(struct frr_socket_entry *entry, int level, int optname, void *optval,
			socklen_t *optlen)
{
	return getsockopt(entry->fd, level, optname, optval, optlen);
}


int quic_getpeername(struct frr_socket_entry *entry, struct sockaddr *addr, socklen_t *addrlen)
{
	return getpeername(entry->fd, addr, addrlen);
}


int quic_getsockname(struct frr_socket_entry *entry, struct sockaddr *addr, socklen_t *addrlen)
{
	return getsockname(entry->fd, addr, addrlen);
}


int quic_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints,
		    struct addrinfo **res)
{
	int rv;
	struct addrinfo *res_next, frr_hints = {};

	/* A user should understand this as a stream socket (even when UDP is underlying) */
	if (hints->ai_socktype != SOCK_STREAM)
		return EAI_SOCKTYPE;

	memcpy(&frr_hints, hints, sizeof(*hints));

	/* QUIC sockets should requires an underlying UDP socket */
	frr_hints.ai_protocol = IPPROTO_UDP;
	frr_hints.ai_socktype = SOCK_DGRAM;
	rv = getaddrinfo(node, service, &frr_hints, res);
	if (rv != 0)
		return rv;

	/* Change IPPROTO_UDP back to IPPROTO_QUIC */
	for (res_next = *res; res_next != NULL; res_next = res_next->ai_next) {
		if (res_next->ai_protocol == IPPROTO_UDP)
			res_next->ai_protocol = IPPROTO_QUIC;
	}
	return 0;
}


int quic_destroy_entry(struct frr_socket_entry *entry)
{
	/* Not much needs to be done for a QUIC socket since we are simply wrapping the kernel.
	 * This will likely not be the case for other transport protocols, which have operational
	 * state!
	 */

	close(entry->fd);
	entry->fd = -1;
	frr_socket_cleanup(entry);
	XFREE(MTYPE_FRR_SOCKET, entry);

	return 0;
}
