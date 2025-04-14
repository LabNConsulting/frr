// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Title/Function of file
 * Copyright (C) 2025  LabN Consulting, L.L.C.
 */

#ifndef _NGTCP2_FRR_SOCKET_H
#define _NGTCP2_FRR_SOCKET_H

#include <zebra.h>
#include <pthread.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/uio.h>
#include <stddef.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>

#include "frr_socket.h"
#include "frratomic.h"
#include "memory.h"
#include "frrevent.h"

extern struct event_loop *frr_socket_shared_event_loop;
extern struct frr_socket_entry_table frr_socket_hash_table;

struct ngtcp2_socket_entry {
	/* Each protocol entry must begin with the generic socket entry */
	struct frr_socket_entry entry;

	/* Any protocol-specific operational state can then be declared in addition */
	ngtcp2_crypto_ossl_ctx *ossl_ctx;
	char dummy[8];
};

/* Simple wrappers to test the FRR socket abstraction */
int quic_socket(int domain, int type);
int quic_bind(struct frr_socket_entry *entry, const struct sockaddr *addr, socklen_t addrlen);
int quic_connect(struct frr_socket_entry *entry, const struct sockaddr *addr, socklen_t addrlen);
int quic_listen(struct frr_socket_entry *entry, int backlog);
int quic_accept(struct frr_socket_entry *entry, struct sockaddr *addr, socklen_t *addrlen);
int quic_close(struct frr_socket_entry *entry);
ssize_t quic_writev(struct frr_socket_entry *entry, const struct iovec *iov, int iovcnt);
ssize_t quic_read(struct frr_socket_entry *entry, void *buf, size_t count);
ssize_t quic_write(struct frr_socket_entry *entry, const void *buf, size_t count);
int quic_setsockopt(struct frr_socket_entry *entry, int level, int option_name,
			const void *option_value, socklen_t option_len);
int quic_getsockopt(struct frr_socket_entry *entry, int level, int optname, void *optval,
			socklen_t *optlen);
int quic_getpeername(struct frr_socket_entry *entry, struct sockaddr *addr, socklen_t *addrlen);
int quic_getsockname(struct frr_socket_entry *entry, struct sockaddr *addr, socklen_t *addrlen);
int quic_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints,
		    struct addrinfo **res);
int quic_destroy_entry(struct frr_socket_entry *entry);

#endif /* _NGTCP2_FRR_SOCKET_H */
