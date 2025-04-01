// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Title/Function of file
 * Copyright (C) 2025  LabN Consulting, L.L.C.
 */

#ifndef _TEST_TCP_FRR_SOCKET_H
#define _TEST_TCP_FRR_SOCKET_H

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

/* Simple wrappers to test the FRR socket abstraction */
int test_tcp_socket(int domain, int type);
int test_tcp_bind(struct frr_socket_entry *entry, const struct sockaddr *addr, socklen_t addrlen);
int test_tcp_connect(struct frr_socket_entry *entry, const struct sockaddr *addr, socklen_t addrlen);
int test_tcp_listen(struct frr_socket_entry *entry, int backlog);
int test_tcp_accept(struct frr_socket_entry *entry, struct sockaddr *addr, socklen_t *addrlen);
int test_tcp_close(struct frr_socket_entry *entry);
ssize_t test_tcp_writev(struct frr_socket_entry *entry, const struct iovec *iov, int iovcnt);
ssize_t test_tcp_read(struct frr_socket_entry *entry, void *buf, size_t count);
ssize_t test_tcp_write(struct frr_socket_entry *entry, const void *buf, size_t count);
int test_tcp_setsockopt(struct frr_socket_entry *entry, int level, int option_name,
			const void *option_value, socklen_t option_len);
int test_tcp_getsockopt(struct frr_socket_entry *entry, int level, int optname, void *optval,
			socklen_t *optlen);
int test_tcp_getpeername(struct frr_socket_entry *entry, struct sockaddr *addr, socklen_t *addrlen);
int test_tcp_getsockname(struct frr_socket_entry *entry, struct sockaddr *addr, socklen_t *addrlen);
int test_tcp_destroy_entry(struct frr_socket_entry *entry);

#endif /* _TEST_TCP_FRR_SOCKET_H */
