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
#include "sockunion.h"

extern struct event_loop *frr_socket_threadmaster;
extern struct frr_socket_entry_table frr_socket_hash_table;

PREDECL_LIST(fd_fifo);

enum quic_role {
	QUIC_CLIENT,
	QUIC_SERVER,
};

// XXX Do I need something like this?
enum quic_state {
	QUIC_NONE,
	QUIC_LISTENING,
	QUIC_CONNECTING,
	QUIC_STREAM_READY,
	QUIC_STREAM_CLOSING,
	QUIC_CONN_CLOSING,
	QUIC_CLOSED,
};

struct fd_fifo {
	int fd;
	struct fd_fifo_item next_fd;
};

struct ngtcp2_socket_entry {
	/* Each protocol entry must begin with the generic socket entry */
	struct frr_socket_entry entry;

	/* Per-connection state.
	 *
	 * This state may need to be separated and ref-counted in the future if multiple streams over
	 * a single connection is to be supported.
	 */
	union sockunion local_addr;
	ssize_t local_addrlen;
	ngtcp2_transport_params initial_params;
	enum quic_role role;
	ngtcp2_conn *conn;
	SSL_CTX *ssl_ctx;
	SSL *ssl;
	ngtcp2_crypto_ossl_ctx *ossl_ctx;
	ngtcp2_crypto_conn_ref conn_ref;
	ngtcp2_ccerr last_error;
	struct event *t_background_process;
	struct event *t_backgound_probe;

	/* Per-stream state */
	enum quic_state state;
	int64_t quic_stream_id;
	struct stream_fifi *rx_buffer_stream;
	struct stream_fifi *tx_retransmit_stream;
	int64_t tx_offset_acked;
	int listener_fd;  /* To track which socket should accept this entry */

	struct fd_fifo_head unclaimed_fds; /* All not-yet-established connections. Listener only */

};

DECLARE_LIST(fd_fifo, struct fd_fifo, next_fd);

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
