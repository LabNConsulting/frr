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

#define IPPROTO_TEST_TCP (IPPROTO_MAX + 1)

DECLARE_MTYPE(FRR_SOCKET);
PREDECL_HASH(frr_socket_entry);

struct frr_socket_entry {
	int protocol;
	int fd;
	pthread_mutex_t lock;
	_Atomic int ref_count;
	struct event *destroy_event;

	struct frr_socket_entry_item hash_item;
};

struct frr_socket_entry_table {
	pthread_rwlock_t rwlock;
	struct frr_socket_entry_head table;
};

extern struct event_loop *frr_socket_shared_event_loop;
extern struct frr_socket_entry_table frr_socket_table;

/* For transport protocol stacks */
static inline _Atomic int *_frr_ref_increment(_Atomic int *ref_count)
{
	(*ref_count)++;
	return ref_count;
}

static inline void _frr_ref_decrement(_Atomic int **ref_count)
{
	if (!*ref_count)
		return;
	(**ref_count)--;
	*ref_count = NULL;
}

struct frr_socket_entry *_frr_socket_table_find(struct frr_socket_entry_head *hash_table,
						struct frr_socket_entry *search_entry);
#define frr_socket_table_find(hash_table, search_entry, rv_entry)                                  \
	pthread_rwlock_rdlock(&(hash_table)->rwlock);                                              \
	rv_entry = _frr_socket_table_find(&(hash_table)->table, search_entry);                     \
	_Atomic int *NAMECTR(_ref_) __attribute__((unused, cleanup(_frr_ref_decrement))) =         \
		rv_entry ? _frr_ref_increment(&rv_entry->ref_count) : NULL;                        \
	pthread_rwlock_unlock(&(hash_table)->rwlock);

int frr_socket_table_add(struct frr_socket_entry_table *hash_table, struct frr_socket_entry *entry);
int frr_socket_table_delete_async(struct frr_socket_entry_table *hash_table,
				  struct frr_socket_entry *entry);


/* For FRR socket users */
int frr_socket_lib_init(struct event_loop *shared_loop);
int frr_socket_lib_finish(void);
int frr_socket_init(struct frr_socket_entry *entry);
int frr_socket_cleanup(struct frr_socket_entry *entry);
int frr_socket(int domain, int type, int protocol);
int frr_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int frr_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int frr_listen(int sockfd, int backlog);
int frr_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int frr_close(int sockfd);
//ssize_t frr_readv(int fd, const struct iovec *iov, int iovcnt);
ssize_t frr_writev(int fd, const struct iovec *iov, int iovcnt);
ssize_t frr_read(int fd, void *buf, size_t count);
ssize_t frr_write(int fd, const void *buf, size_t count);
int frr_setsockopt(int sockfd, int level, int option_name, const void *option_value,
		   socklen_t option_len);
int frr_getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
int frr_getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int frr_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
//int frr_ioctl(int fd, int op, ...);
int frr_poll_hook(struct pollfd *t_pollfd, int *nums);

#endif /* _FRR_SOCKET_H */
