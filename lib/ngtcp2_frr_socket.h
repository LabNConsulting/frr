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
#include <stream.h>
#include <fcntl.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>

#include "frr_socket.h"
#include "frratomic.h"
#include "memory.h"
#include "frrevent.h"
#include "sockunion.h"

#define QUIC_SCIDLEN NGTCP2_MIN_INITIAL_DCIDLEN

extern struct event_loop *frr_socket_threadmaster;
extern struct frr_socket_entry_table frr_socket_hash_table;

PREDECL_LIST(quic_stream_data);

enum quic_state {
	QUIC_NONE,
	QUIC_LISTENING,
	QUIC_CONNECTING,
	QUIC_CONNECTED,
	QUIC_NO_STREAMS,
	QUIC_CLOSED,
	QUIC_STATE_MAX,
};

struct quic_stream_data {

	int entry_fd;  /* Corresponds to entry in the socket table */
	int conn_fd;  /* Other end of sockpair; for conn_data use only */

	struct quic_conn_data *conn_data;

	int64_t stream_id;

	struct stream *tx_next_stream;
	struct stream_fifo *tx_retransmit_buffer;
	int64_t tx_ack_unconsumed;

	bool is_stream_fin;

	/* used for sanity checking */
	uint64_t tx_ack_offset;
	uint64_t rx_offset;

	struct quic_stream_data_item next_stream_data;
};

struct quic_conn_data {
	/* Per-connection state. May correspond to multiple streams in the future.
	 * XXX Explain safe access rules from a socket entry
	 */
	enum quic_state state;
	pthread_mutex_t lock;

	int fd;  /* Underlying UDP connection socket */
	int listen_fd;  /* For poking POLLIN when a new conn is accepted */
	union sockunion local_addr;
	socklen_t local_addrlen;
	ngtcp2_transport_params initial_params;
	ngtcp2_conn *conn;
	SSL_CTX *ssl_ctx;
	SSL *ssl;
	ngtcp2_crypto_ossl_ctx *ossl_ctx;
	ngtcp2_crypto_conn_ref conn_ref;
	ngtcp2_ccerr last_error;
	struct quic_stream_data_head stream_fds;  /* per-stream quic_socket_entry list */
	struct event *t_conn_read;
	struct event *t_conn_write;
	struct event *t_conn_timeout;
	struct event *t_listen;
	struct event *t_socket_closed;
	struct event *t_quic_delete;

	bool lib_shutdown;
	bool wait_for_shutdown_event;
};

struct quic_socket_entry {
	/* Each protocol entry must begin with the generic socket entry */
	struct frr_socket_entry entry;

	/* Per-stream state. Corresponds to a single QUIC connection */
	bool is_user_closed;
	bool is_conn_closed;
	//bool is_stream_fin;
	//int64_t stream_id;
	//struct stream_fifo *rx_buffer;
	//struct stream_fifo *tx_buffer;
	//struct stream_fifo *tx_retransmit_buffer;
	//int64_t tx_ack_unconsumed;
	int64_t rx_consumed; // XXX Change this to atomically increase another counter

	/* used for sanity checking */
	//uint64_t tx_ack_offset;
	//uint64_t rx_offset;

	/* The following references exist *only* for scheduling events. Their reference may need to
	 * be refcounted when multi-stream support is added in the future.
	 */
	struct quic_conn_data *conn_data;
	//struct quic_stream_data *stream_data;

	/* Listener state */
	struct quic_stream_data_head unclaimed_fds;
	int listener_backlog;
};

DECLARE_LIST(quic_stream_data, struct quic_stream_data, next_stream_data);

void quic_socket_lib_finish_hook(struct frr_socket_entry *entry);

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
int quic_poll_hook(struct frr_socket_entry *entry, struct pollfd *p_fd, int *poll_rv);

#endif /* _NGTCP2_FRR_SOCKET_H */
