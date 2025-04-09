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
#include "frrcu.h"
#include "jhash.h"

#define IPPROTO_FRR_TCP (IPPROTO_MAX + 1)

DECLARE_MTYPE(FRR_SOCKET);
PREDECL_HASH(frr_socket_entry);

struct frr_socket_entry {
	int protocol;
	int fd;
	pthread_mutex_t lock;
	_Atomic int ref_count;

	struct frr_socket_entry_item hash_item;
	struct rcu_head rcu_head;
};

struct frr_socket_entry_table {
	pthread_rwlock_t rwlock;
	struct frr_socket_entry_head table;
};

extern struct event_loop *frr_socket_threadmaster;
extern struct frr_socket_entry_table frr_socket_table;

/* For transport protocol stacks */
static int frr_socket_entry_compare(const struct frr_socket_entry *a,
				    const struct frr_socket_entry *b)
{
	return numcmp(a->fd, b->fd);
}


static uint32_t frr_socket_entry_hash(const struct frr_socket_entry *a)
{
	return jhash_1word(a->fd, 0x8ae55ea8);
}


DECLARE_HASH(frr_socket_entry, struct frr_socket_entry, hash_item, frr_socket_entry_compare,
	     frr_socket_entry_hash);


static inline struct frr_socket_entry *entry_find_and_lock(struct frr_socket_entry *search_entry)
{
	struct frr_socket_entry *rv_entry;

	pthread_rwlock_rdlock(&frr_socket_table.rwlock);
	rcu_read_lock();
	rv_entry = frr_socket_entry_find(&frr_socket_table.table, search_entry);
	pthread_rwlock_unlock(&frr_socket_table.rwlock);

	return rv_entry;
}


static inline void entry_unlock(struct frr_socket_entry **arg)
{
	rcu_read_unlock();
}


#define frr_socket_table_find(search_entry, declared_entry)                                        \
	struct frr_socket_entry *declared_entry __attribute__((unused, cleanup(entry_unlock))) =   \
		entry_find_and_lock(search_entry);                                                 \
	/* end */

int frr_socket_table_add(struct frr_socket_entry *entry);
int frr_socket_table_delete(struct frr_socket_entry *entry);


/* XXX
 * Library and frr_socket_entry setup/cleanup functions
 */
int frr_socket_lib_init(struct event_loop *shared_threadmaster);
int frr_socket_lib_finish(void);
int frr_socket_init(struct frr_socket_entry *entry);
int frr_socket_cleanup(struct frr_socket_entry *entry);

/* XXX
 * Standard socket and I/O functions to be called by a user
 */
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
int frr_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints,
		    struct addrinfo **res);
void frr_freeaddrinfo(struct addrinfo *res);
//int frr_ioctl(int fd, int op, ...);
int frr_poll_hook(struct pollfd *fds, nfds_t nfds, int poll_rv);

#endif /* _FRR_SOCKET_H */
