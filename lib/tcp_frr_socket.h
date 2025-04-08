// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Title/Function of file
 * Copyright (C) 2025  LabN Consulting, L.L.C.
 */

#ifndef _TCP_FRR_SOCKET_H
#define _TCP_FRR_SOCKET_H

#include <zebra.h>
#include <pthread.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/uio.h>
#include <stddef.h>

#include "frr_socket.h"
#include "frratomic.h"
#include "memory.h"
#include "frrevent.h"

extern struct event_loop *frr_socket_shared_event_loop;
extern struct frr_socket_entry_table frr_socket_hash_table;

struct tcp_socket_entry {
	/* Each protocol entry must begin with the generic socket entry */
	struct frr_socket_entry entry;

	/* Any protocol-specific operational state can then be declared in addition */
	char dummy[8];
};

/* Simple wrappers to test the FRR socket abstraction */
int tcp_socket(int domain, int type);
int tcp_bind(struct frr_socket_entry *entry, const struct sockaddr *addr, socklen_t addrlen);
int tcp_connect(struct frr_socket_entry *entry, const struct sockaddr *addr, socklen_t addrlen);
int tcp_listen(struct frr_socket_entry *entry, int backlog);
int tcp_accept(struct frr_socket_entry *entry, struct sockaddr *addr, socklen_t *addrlen);
int tcp_close(struct frr_socket_entry *entry);
ssize_t tcp_writev(struct frr_socket_entry *entry, const struct iovec *iov, int iovcnt);
ssize_t tcp_read(struct frr_socket_entry *entry, void *buf, size_t count);
ssize_t tcp_write(struct frr_socket_entry *entry, const void *buf, size_t count);
int tcp_setsockopt(struct frr_socket_entry *entry, int level, int option_name,
			const void *option_value, socklen_t option_len);
int tcp_getsockopt(struct frr_socket_entry *entry, int level, int optname, void *optval,
			socklen_t *optlen);
int tcp_getpeername(struct frr_socket_entry *entry, struct sockaddr *addr, socklen_t *addrlen);
int tcp_getsockname(struct frr_socket_entry *entry, struct sockaddr *addr, socklen_t *addrlen);
int tcp_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints,
		    struct addrinfo **res);
int tcp_destroy_entry(struct frr_socket_entry *entry);

#endif /* _TCP_FRR_SOCKET_H */
