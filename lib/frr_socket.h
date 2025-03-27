// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Title/Function of file
 * Copyright (C) 2025  LabN Consulting, L.L.C.
 */

#ifndef _FRR_SOCKET_H
#define _FRR_SOCKET_H

#include <zebra.h>
#include <pthread.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/uio.h>
#include <stddef.h>

#include "frratomic.h"
#include "memory.h"
#include "frrevent.h"
#include "typesafe.h"

#define IPPROTO_STUB_TCP (IPPROTO_MAX + 1)

PREDECL_HASH(frr_socket_entry);
struct frr_socket_entry {
	int protocol;
	int fd;
	pthread_mutex_t lock;
	_Atomic int ref_count;

	struct frr_socket_entry_item hash_item;
};

struct frr_socket_entry_table {
	pthread_rwlock_t rwlock;
	struct frr_socket_entry_head table;
};

/* For transport protocol stacks */
int async_safe_frr_socket_destroy(int fd);
#define safe_find_frr_socket_entry(hash_table, search_entry, rv_entry)                             \
	pthread_rwlock_rdlock(&hash_table->rwlock);                                                \
	rv_entry = frr_socket_entry_hash_find(hash_table->table, search_entry);                    \
	if (rv_entry)                                                                              \
		frr_ref_inc_autodecrement(&rv_entry->ref_count);                                   \
	pthread_rwlock_unlock(&hash_table->rwlock);
#define safe_add_frr_socket_entry(hash_table, entry)                                               \
	pthread_rwlock_wrlock(&hash_table->rwlock);                                                \
	assert(frr_socket_entry_hash_add(hash_table->table, entry) == NULL);                       \
	entry->ref_count++;                                                                        \
	pthread_rwlock_unlock(&hash_table->rwlock);

/* For FRR socket users */
int frr_socket_lib_init(struct event_loop *shared_loop);
int frr_socket(int domain, int type, int protocol);
int frr_socket_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int frr_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int frr_listen(int sockfd, int backlog);
int frr_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int frr_close(int sockfd);
//ssize_t frr_readv(int fd, const struct iovec *iov, int iovcnt);
ssize_t frr_writev(int sockfd, const struct iovec *iov, int iovcnt);
ssize_t frr_read(int fr, void *buf, size_t count);
ssize_t frr_write(int fd, const void *buf, size_t count);
int frr_setsockopt(int sockfd, int level, int option_name, const void *option_value,
		   socklen_t option_len);
int frr_getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
//int ioctl(int fd, int op, ...);

/* Special case: polling */
int frr_poll_hook(struct pollfd *t_pollfd, int *nums);

#define IS_FRR_SOCKET_PROTOCOL(protocol) XXX
#define IS_FRR_SOCKET(sockfd) XXX

#endif /* _FRR_SOCKET_H */
