// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Title/Function of file
 * Copyright (C) 2025  LabN Consulting, L.L.C.
 */

#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/param.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "frr_socket.h"
#include "ngtcp2_frr_socket.h"

/* The following are internal utility functions required for ngtcp2 */


static uint64_t timestamp(void) {
  struct timespec tp;

  //XXX Timestamp is pulled directly from ngtcp2 examples. Do we want to keep this?
  if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0) {
    fprintf(stderr, "clock_gettime: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}


static void rand_cb(uint8_t *dest, size_t destlen,
                    const ngtcp2_rand_ctx *rand_ctx) {
  size_t i;
  (void)rand_ctx;

  //XXX Replace with a cryptographically secure random function
  for (i = 0; i < destlen; ++i) {
    *dest = (uint8_t)random();
  }
}


static int quic_client_tls_init(struct ngtcp2_socket_entry *ngtcp2_entry) {
	// XXX Change the allowed ciphers or curves?
	const char *ciphers =
		"TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256";
	const char *curves = "X25519:P-256:P-384:P-521";

	ngtcp2_entry->ssl_ctx = SSL_CTX_new(TLS_client_method());
	if (!ngtcp2_entry->ssl_ctx) {
		zlog_warn("QUIC: SSL_CTX_new: %s\n", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	SSL_CTX_set_default_verify_paths(ngtcp2_entry->ssl_ctx);

	if (SSL_CTX_set_ciphersuites(ngtcp2_entry->ssl_ctx, ciphers) != 1) {
		zlog_warn("QUIC: SSL_CTX_set_ciphersuites: %s\n",
			  ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	if (SSL_CTX_set1_groups_list(ngtcp2_entry->ssl_ctx, curves) != 1) {
		zlog_warn("QUIC: SSL_CTX_set1_groups_list failed\n");
		return -1;
	}

	// XXX This is where the private key and certificate chain files would be specified.

	ngtcp2_entry->ssl = SSL_new(ngtcp2_entry->ssl_ctx);
	if (ngtcp2_entry->ssl) {
		zlog_warn("QUIC: SSL_new: %s\n", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	ngtcp2_crypto_ossl_ctx_new(&ngtcp2_entry->ossl_ctx, NULL);
	ngtcp2_crypto_ossl_ctx_set_ssl(ngtcp2_entry->ossl_ctx, ngtcp2_entry->ssl);

	if (ngtcp2_crypto_ossl_configure_client_session(ngtcp2_entry->ssl) != 0) {
		zlog_warn("QUIC: ngtcp2_crypto_ossl_configure_client_session failed\n");
		return -1;
	}

	SSL_set_app_data(ngtcp2_entry->ssl, ngtcp2_entry->conn_ref);
	SSL_set_connect_state(ngtcp2_entry->ssl);
	/* XXX Is any of the following actually needed?
	SSL_set_alpn_protos(ssl, (const unsigned char *)ALPN, sizeof(ALPN) - 1);
	if (!numeric_host(REMOTE_HOST)) {
		SSL_set_tlsext_host_name(c->ssl, REMOTE_HOST);
	}
	*/

	return 0;
}


static int quic_client_conn_init(struct ngtcp2_socket_entry *ngtcp2_entry,
				 const struct sockaddr *remote_addr, socklen_t remote_addrlen)
{
	ngtcp2_path path = {
		{
			(struct sockaddr *)&ngtcp2_entry->local_addr,
			ngtcp2_entry->local_addrlen,
		},
		{
			(struct sockaddr *)remote_addr,
			remote_addrlen,
		},
	};
	ngtcp2_callbacks callbacks = {
		ngtcp2_crypto_client_initial_cb,
		NULL, /* recv_client_initial */
		ngtcp2_crypto_recv_crypto_data_cb,
		NULL, /* handshake_completed */
		NULL, /* recv_version_negotiation */
		ngtcp2_crypto_encrypt_cb,
		ngtcp2_crypto_decrypt_cb,
		ngtcp2_crypto_hp_mask_cb,
		NULL, //recv_stream_data_cb,
		NULL, /* acked_stream_data_offset */
		NULL, /* stream_open */
		NULL, //ngtcp2_stream_close_cb,
		NULL, /* recv_stateless_reset */
		ngtcp2_crypto_recv_retry_cb,
		NULL, /* extend_max_local_streams_bidi */
		NULL, /* extend_max_local_streams_uni */
		rand_cb,
		NULL, //get_new_connection_id_cb,
		NULL, /* remove_connection_id */
		ngtcp2_crypto_update_key_cb,
		NULL, /* path_validation */
		NULL, /* select_preferred_address */
		NULL, /* stream_reset */
		NULL, /* extend_max_remote_streams_bidi */
		NULL, /* extend_max_remote_streams_uni */
		NULL, /* extend_max_stream_data */
		NULL, /* dcid_status */
		NULL, //handshake_confirmed,
		NULL, /* recv_new_token */
		ngtcp2_crypto_delete_crypto_aead_ctx_cb,
		ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
		NULL, /* recv_datagram */
		NULL, /* ack_datagram */
		NULL, /* lost_datagram */
		ngtcp2_crypto_get_path_challenge_data_cb,
		NULL, /* stream_stop_sending */
		ngtcp2_crypto_version_negotiation_cb,
		NULL, /* recv_rx_key */
		NULL, /* recv_tx_key */
		NULL, /* early_data_rejected */
	};
	ngtcp2_cid dcid, scid;
	ngtcp2_settings settings;
	int rv;

	/* Create an OpenSSL TLS context for ngtcp2 */
	rv = quic_client_tls_init(ngtcp2_entry);
	if (rv != 0) {
		// XXX Clean up the error stuff
		zlog_warn("QUIC: Failed to create TLS context\n");
		return -1;
	}

	/* Source and destination Connection ID's start out randomized */
	dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
	scid.datalen = 8;
	if (RAND_bytes(dcid.data, (int)dcid.datalen) != 1
	    || RAND_bytes(scid.data, (int)scid.datalen) != 1) {
		zlog_warn("QUIC: Failed to call RAND_bytes\n");
		return -1;
	}

	ngtcp2_settings_default(&settings);
	settings.cc_algo = NGTCP2_CC_ALGO_BBR;
	settings.initial_ts = timestamp();
	//XXX Find a logging functino: settings.log_printf = log_printf;

	rv = ngtcp2_conn_client_new(&ngtcp2_entry->conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1,
				    &callbacks, &settings, &ngtcp2_entry->initial_params, NULL,
				    NULL);
	if (rv != 0) {
		zlog_warn("QUIC: Failed to create ngtcp2 client connection context\n");
		return -1;
	}

	/* Finish integrating ngtcp2 with OpenSSL TLS context */
	ngtcp2_conn_set_tls_native_handle(ngtcp2_entry->conn, ngtcp2_entry->ossl_ctx);

	return 0;
}


/* The following provide the wrappers called by the frr_socket core library */
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

	/* The defaults for a ngtcp2 connection (not necessarily a single stream!) */
	// XXX Revisit these initial parameters to confirm if they are good
	ngtcp2_entry->initial_params.initial_max_streams_uni = 0;
	ngtcp2_entry->initial_params.initial_max_streams_bidi = 1;
	ngtcp2_entry->initial_params.initial_max_stream_data_bidi_local = 128 * 1024;
	ngtcp2_entry->initial_params.initial_max_stream_data_bidi_remote = 128 * 1024;
	ngtcp2_entry->initial_params.initial_max_data = 256 * 1024;

	frr_socket_table_add((struct frr_socket_entry *)ngtcp2_entry);

	return fd;
}


int quic_bind(struct frr_socket_entry *entry, const struct sockaddr *addr,
			 socklen_t addrlen)
{
	assert(entry->protocol == IPPROTO_QUIC);
	return bind(entry->fd, addr, addrlen);
}


int quic_connect(struct frr_socket_entry *entry, const struct sockaddr *addr, socklen_t addrlen)
{
	int rv;
	struct ngtcp2_socket_entry *ngtcp2_entry = (struct ngtcp2_socket_entry *)entry;

	assert(entry->protocol == IPPROTO_QUIC);

	if (ngtcp2_entry->is_listener) {
		errno = EINVAL;
		return -1;
	} else if (ngtcp2_entry->quic_stream_id) {
		// XXX introduce state machine?
		errno = EISCONN;
		return -1;
	}

	rv = connect(entry->fd, addr, addrlen);
	if (rv != 0) {
		/* errno is kept */
		return -1;
	}

	/* Create a client instance of the QUIC context */
	rv = quic_client_conn_init(ngtcp2_entry, addr, addrlen);
	if (!rv) {
		errno = EINVAL;
		return -1;
	}

	errno = EINPROGRESS;
	return -1;
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
