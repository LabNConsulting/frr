// Spdx-License-Identifier: GPL-2.0-or-later
/*
 * Title/Function of file
 * Copyright (C) 2025  LabN Consulting, L.L.C.
 */

#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <fcntl.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "frr_pthread.h"
#include "frr_socket.h"
#include "ngtcp2_frr_socket.h"

#define ONESEC2NANO 1000000000
#define ONEMILLISEC2NANO 1000000

static void quic_background_process(struct event *thread);
static void quic_background_timeout_process(struct event *thread);
static void quic_background_listen(struct event *thread);

/* Keep up to date with the quic_state enum in ngtcp2_frr_socket.h */
static const char *const quic_state_str[] = {
	"QUIC None",
	"QUIC Listening",
	"QUIC Connecting",
	"QUIC Connected",
	"QUIC Connected (No Open Streams)",
	"QUIC Connection Closing",
	"QUIC Connection Closed",
};

/*
 * The following are internal utility functions required for ngtcp2
 * (This excludes events). This includes the definition of many callbacks.
 */

static uint64_t timestamp(void)
{
	struct timespec tp;

	//XXX Timestamp is pulled directly from ngtcp2 examples. Do we want to keep this?
	if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0) {
		fprintf(stderr, "clock_gettime: %s", safe_strerror(errno));
		exit(EXIT_FAILURE);
	}

	return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}


static void keylog_cb(const SSL *ssl, const char *line)
{
	// XXX Read from KEYLOGFILE env variable instead of hardcoded
	FILE *file = fopen("./key.log", "a");

	(void)ssl;

	assert(file != NULL);
	fputs(line, file);
	fputc('\n', file);
	assert(fclose(file) == 0);
}


static void rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx)
{
	size_t i;
	(void)rand_ctx;

	//XXX Replace with a cryptographically secure random function
	for (i = 0; i < destlen; ++i) {
		*dest = (uint8_t)random();
	}
}


static void zlog_ngtcp2(void *user_data, const char *fmt, ...)
{
	va_list ap;
	(void)user_data;

	va_start(ap, fmt);
	vzlog(LOG_DEBUG, fmt, ap);
	va_end(ap);
}


static const char *quic_strstate(int state) {
	if (state >= 0 && state < QUIC_STATE_MAX)
		return quic_state_str[state];
	return "";
}


static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
	struct quic_conn_data *conn_data = conn_ref->user_data;

	/* This callback is needed by ngtcp2 to retreive the connection reference from the SSL
	 * context that we created. It should only be called when conn_data is locked and in the
	 * frr_socket_threadmaster's pthread.
	 */
	assert(pthread_self() == frr_socket_threadmaster->owner);
	assert(pthread_mutex_trylock(&conn_data->lock) != 0);

	/* Confirm that this socket does in fact maintain active connections */
	if (conn_data->state == QUIC_LISTENING || conn_data->state == QUIC_NONE ||
	    conn_data->state == QUIC_CLOSED) {
		zlog_err("QUIC: Trying to get connection of entry in state %s (conn fd %d)",
			 quic_strstate(conn_data->state), conn_data->fd);
		assert(0);
	}

	return conn_data->conn;
}


static void quic_change_state(struct quic_conn_data *conn_data, enum quic_state state) {
	enum quic_state prev_state = conn_data->state;

	if (conn_data->state == state)
		return;
	conn_data->state = state;
	zlog_info("QUIC: entry with fd %d changes state (%s -> %s)", conn_data->fd,
		  quic_strstate(prev_state), quic_strstate(state));
}


static int get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token,
				    size_t cidlen, void *user_data)
{
	(void)conn;
	(void)user_data;

	if (RAND_bytes(cid->data, (int)cidlen) != 1) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	cid->datalen = cidlen;

	if (RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}


static int handshake_confirmed_client_cb(ngtcp2_conn *conn, void *user_data)
{
	int rv;
	struct fd_fifo_entry *fd_entry;
	struct frr_socket_entry search_entry = {};
	struct quic_socket_entry *socket_entry = NULL;
	struct quic_conn_data *conn_data = user_data;
	assert(conn == conn_data->conn);

	fd_entry = fd_fifo_first(&conn_data->stream_fds);
	search_entry.fd = fd_entry->fd;
	frr_socket_table_find(&search_entry, found_entry);
	assert(found_entry && found_entry->protocol == IPPROTO_QUIC);
	socket_entry = (struct quic_socket_entry *)found_entry;

	/* Confirm that we are client-side and not server-side */
	assert(conn_data->state == QUIC_CONNECTING);
	assert(socket_entry->stream_id == -1);

	rv = ngtcp2_conn_open_bidi_stream(conn, &socket_entry->stream_id, &found_entry->fd);
	if (rv != 0) {
		zlog_err("QUIC: Failed to open stream during handshake confirmation, fd %d (conn fd %d)",
			 found_entry->fd, conn_data->fd);
		// XXX implement proper recovery from this error.
		assert(0);
	}

	zlog_info("QUIC: Handshake confirmed by client on fd %d (conn fd %d). Opening stream %lld",
		  found_entry->fd, conn_data->fd, socket_entry->stream_id);
	quic_change_state(conn_data, QUIC_CONNECTED);

	return 0;
}


static int stream_open_server_cb(ngtcp2_conn *conn, int64_t stream_id, void *user_data) {

	struct fd_fifo_entry *fd_entry;
	struct frr_socket_entry search_entry = {};
	struct quic_conn_data *conn_data = user_data;
	assert(conn == conn_data->conn);

	/* Find an entry with that we can assign the stream_id to */
	frr_each_safe (fd_fifo, &conn_data->stream_fds, fd_entry) {
		struct quic_socket_entry *t_socket_entry = NULL;

		search_entry.fd = fd_entry->fd;
		frr_socket_table_find(&search_entry, t_entry);

		/* Bad entry, but avoid fixing within a callback */
		if (t_entry == NULL)
			continue;

		assert(t_entry->protocol == IPPROTO_QUIC);
		t_socket_entry = (struct quic_socket_entry *)t_entry;

		if (t_socket_entry->stream_id != -1)
			continue;

		t_socket_entry->stream_id = stream_id;
		ngtcp2_conn_set_stream_user_data(conn, stream_id, &t_entry->fd);
		quic_change_state(conn_data, QUIC_CONNECTED);

		zlog_info("QUIC: Server found new stream with id %lld. Assigned to fd %d (conn fd %d)",
			  stream_id, t_entry->fd, conn_data->fd);
		return 0;
	}

	zlog_err("QUIC: Server found new stream with id %lld, but there was no entry to give it to!",
		 stream_id);
	assert(0);
	return NGTCP2_ERR_CALLBACK_FAILURE;
}


static int stream_close_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
			   uint64_t app_error_code, void *user_data, void *stream_user_data)
{
	int *fd_ref = stream_user_data;
	struct frr_socket_entry search_entry = {};
	struct quic_socket_entry *socket_entry = NULL;
	struct quic_conn_data *conn_data = user_data;
	assert(conn == conn_data->conn);

	/* fd_ref should have populated in stream_open_server_cb or handshake_confirmed_client_cb */
	if (fd_ref == NULL) {
		zlog_err("QUIC: No entry for closing stream. This is unexpected.");
		assert(0);
	}

	search_entry.fd = *fd_ref;
	frr_socket_table_find(&search_entry, found_entry);
	assert(found_entry && found_entry->protocol == IPPROTO_QUIC);
	socket_entry = (struct quic_socket_entry *)found_entry;

	socket_entry->stream_id = -1;

	/* XXX Until we support multiplexing, only a single stream could have existed */
	assert(conn_data->state == QUIC_CONNECTED);
	quic_change_state(conn_data, QUIC_NO_STREAMS);

	return 0;
}


static int recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
			       uint64_t offset, const uint8_t *data, size_t datalen,
			       void *user_data, void *stream_user_data)
{
	int *fd_ref = stream_user_data;
	struct frr_socket_entry search_entry = {};
	struct quic_socket_entry *socket_entry = NULL;
	struct quic_conn_data *conn_data = user_data;
	assert(conn == conn_data->conn);

	(void)offset;

	/* Our design should result in fd_ref *always* being populated before data is received */
	if (fd_ref == NULL) {
		zlog_err("QUIC: No entry for received data. This is unexpected.");
		assert(0);
	}

	search_entry.fd = *fd_ref;
	frr_socket_table_find(&search_entry, found_entry);
	assert(found_entry && found_entry->protocol == IPPROTO_QUIC);
	socket_entry = (struct quic_socket_entry *)found_entry;

	if (datalen > 0 ) {
		/* XXX Copy the data into the fifo stream buffer! */
	}

	if (flags & NGTCP2_STREAM_DATA_FLAG_FIN) {
		/* Opposite endpoint closed their end of the stream. We will follow them, but cannot
		 * inside any callback. XXX Implement me!
		 */
		// XXX Now what should be done here!
		//socket_entry->is_conn_closed = true;
	}

	/* ngtcp2's on-the-wire window limits do not adjust automatically based on user data */
	// XXX Move this to when data is actually read from the internal buffer! Not just received!
	ngtcp2_conn_extend_max_stream_offset(conn, stream_id, datalen);
	ngtcp2_conn_extend_max_offset(conn, datalen);

	zlog_debug("QUIC: Received %d bytes of data for stream %lld", (int)datalen, stream_id);

	return 0;
}


/*
 * The following are internal helper functions used to create/manage QUIC contexts and streams
 */


static void cleanup_on_init_failure(struct quic_conn_data* conn_data)
{
	if (conn_data->conn) {
		ngtcp2_conn_del(conn_data->conn);
		conn_data->conn = NULL;
	}
	if (conn_data->ossl_ctx) {
		ngtcp2_crypto_ossl_ctx_del(conn_data->ossl_ctx);
		conn_data->ossl_ctx = NULL;
	}
	if (conn_data->ssl) {
		SSL_free(conn_data->ssl);
		conn_data->ssl = NULL;
	}
	if (conn_data->ssl_ctx) {
		SSL_CTX_free(conn_data->ssl_ctx);
		conn_data->ssl_ctx = NULL;
	}
}


static int quic_client_tls_init(struct quic_conn_data *conn_data) {
	// XXX Change the allowed ciphers or curves?
	uint64_t ssl_opts;
	const char *ciphers =
		"TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256";
	const char *curves = "X25519:P-256:P-384:P-521";

	conn_data->ssl_ctx = SSL_CTX_new(TLS_client_method());

	if (!conn_data->ssl_ctx) {
		zlog_warn("QUIC: SSL_CTX_new client: %s", ERR_error_string(ERR_get_error(), NULL));
		goto failed;
	}


	if (SSL_CTX_set_ciphersuites(conn_data->ssl_ctx, ciphers) != 1) {
		zlog_warn("QUIC: SSL_CTX_set_ciphersuites: %s",
			  ERR_error_string(ERR_get_error(), NULL));
		goto failed;
	}

	if (SSL_CTX_set1_groups_list(conn_data->ssl_ctx, curves) != 1) {
		zlog_warn("QUIC: SSL_CTX_set1_groups_list failed");
		goto failed;
	}

	SSL_CTX_set_mode(conn_data->ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
	SSL_CTX_set_default_verify_paths(conn_data->ssl_ctx);

	/* XXX Set and check certs here */

	conn_data->ssl = SSL_new(conn_data->ssl_ctx);
	if (!conn_data->ssl) {
		zlog_warn("QUIC: SSL_new: %s", ERR_error_string(ERR_get_error(), NULL));
		goto failed;
	}

	ngtcp2_crypto_ossl_ctx_new(&conn_data->ossl_ctx, NULL);
	ngtcp2_crypto_ossl_ctx_set_ssl(conn_data->ossl_ctx, conn_data->ssl);

	if (ngtcp2_crypto_ossl_configure_client_session(conn_data->ssl) != 0) {
		zlog_warn("QUIC: ngtcp2_crypto_ossl_configure_client_session failed");
		goto failed;
	}

	SSL_set_app_data(conn_data->ssl, &conn_data->conn_ref);
	SSL_set_connect_state(conn_data->ssl);
	// XXX Set up Server Name Indication? e.g. SSL_set_tlsext_host_name

	return 0;

failed:
	cleanup_on_init_failure(conn_data);
	return -1;
}


static int quic_server_tls_init(struct quic_conn_data *conn_data) {
	// XXX Change the allowed ciphers or curves?
	uint64_t ssl_opts;
	const char *ciphers =
		"TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256";
	const char *curves = "X25519:P-256:P-384:P-521";

	conn_data->ssl_ctx = SSL_CTX_new(TLS_server_method());

	if (!conn_data->ssl_ctx) {
		zlog_warn("QUIC: SSL_CTX_new server: %s", ERR_error_string(ERR_get_error(), NULL));
		goto failed;
	}

	// XXX Not starting with early data. Can change later to UINT32_MAX
	SSL_CTX_set_max_early_data(conn_data->ssl_ctx, 0);

	// XXX Revist this to confirm if some aren't necessary. Also, can this be moved out of loop?
	ssl_opts = (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) |
		   SSL_OP_CIPHER_SERVER_PREFERENCE;
	SSL_CTX_set_options(conn_data->ssl_ctx, ssl_opts);


	if (SSL_CTX_set_ciphersuites(conn_data->ssl_ctx, ciphers) != 1) {
		zlog_warn("QUIC: SSL_CTX_set_ciphersuites: %s",
			  ERR_error_string(ERR_get_error(), NULL));
		goto failed;
	}

	if (SSL_CTX_set1_groups_list(conn_data->ssl_ctx, curves) != 1) {
		zlog_warn("QUIC: SSL_CTX_set1_groups_list failed");
		goto failed;
	}

	SSL_CTX_set_mode(conn_data->ssl_ctx, SSL_MODE_RELEASE_BUFFERS);

	SSL_CTX_set_default_verify_paths(conn_data->ssl_ctx);

	// XXX Do not hardcode this!
	const char *private_key_file = "/usr/local/ssl/certs/priv.key";
	const char *cert_file = "/usr/local/ssl/certs/cert.pem";
	const char *ca_file = "/usr/local/ssl/certs/ca.pem";
	if (SSL_CTX_load_verify_file(conn_data->ssl_ctx, ca_file) != 1) {
		zlog_err("QUIC: SSL_CTX_load_verify_file: %s",
			 ERR_error_string(ERR_get_error(), NULL));
		goto failed;
	}
	if (SSL_CTX_use_PrivateKey_file(conn_data->ssl_ctx, private_key_file,
					SSL_FILETYPE_PEM) != 1) {
		zlog_err("QUIC: SSL_CTX_use_PrivateKey_file: %s",
			 ERR_error_string(ERR_get_error(), NULL));
		goto failed;
	}
	if (SSL_CTX_use_certificate_chain_file(conn_data->ssl_ctx, cert_file) != 1) {
		zlog_err("QUIC: SSL_CTX_use_certificate_chain_file: %s",
			 ERR_error_string(ERR_get_error(), NULL));
		goto failed;
	}
	if (SSL_CTX_check_private_key(conn_data->ssl_ctx) != 1) {
		zlog_err("QUIC: SSL_CTX_check_private_key: %s",
			 ERR_error_string(ERR_get_error(), NULL));
		goto failed;
	}

	/*
	if (conn_data->role == NGTCP2_SERVER) {
		SSL_CTX_set_session_id_context(s->ssl_ctx, (unsigned char *)sid_ctx,
					       strlen(sid_ctx));

		//SSL_CTX_set_verify(s->ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb);

		//XXX: Don't hardcode the keylog file
		SSL_CTX_set_keylog_callback(s->ssl_ctx, keylog_cb);
	}
	*/

	conn_data->ssl = SSL_new(conn_data->ssl_ctx);
	if (!conn_data->ssl) {
		zlog_warn("QUIC: SSL_new: %s", ERR_error_string(ERR_get_error(), NULL));
		goto failed;
	}

	ngtcp2_crypto_ossl_ctx_new(&conn_data->ossl_ctx, NULL);
	ngtcp2_crypto_ossl_ctx_set_ssl(conn_data->ossl_ctx, conn_data->ssl);

	if (ngtcp2_crypto_ossl_configure_server_session(conn_data->ssl) != 0) {
		zlog_warn("QUIC: ngtcp2_crypto_ossl_configure_server_session failed");
		goto failed;
	}

	SSL_set_app_data(conn_data->ssl, &conn_data->conn_ref);
	SSL_set_accept_state(conn_data->ssl);
	// XXX Set up Server Name Indication? e.g. SSL_set_tlsext_servername_callback, etc.

	// XXX Should be turned into a debug-only option later
	remove("./key.log");
	SSL_CTX_set_keylog_callback(conn_data->ssl_ctx, keylog_cb);

	return 0;

failed:
	cleanup_on_init_failure(conn_data);
	return -1;
}


static int quic_server_conn_init(struct quic_conn_data *conn_data,
				 const struct sockaddr *remote_addr, socklen_t remote_addrlen,
				 ngtcp2_cid *dcid, ngtcp2_cid *scid)
{
	ngtcp2_path path = {
		{
			(struct sockaddr *)&conn_data->local_addr,
			conn_data->local_addrlen,
		},
		{
			(struct sockaddr *)remote_addr,
			remote_addrlen,
		},
	};
	ngtcp2_callbacks callbacks = {
		NULL, /* client_initial */
		ngtcp2_crypto_recv_client_initial_cb,
		ngtcp2_crypto_recv_crypto_data_cb,
		NULL, /* handshake_completed */
		NULL, /* recv_version_negotiation */
		ngtcp2_crypto_encrypt_cb,
		ngtcp2_crypto_decrypt_cb,
		ngtcp2_crypto_hp_mask_cb,
		recv_stream_data_cb,
		NULL, /* acked_stream_data_offset */
		stream_open_server_cb,
		stream_close_cb,
		NULL, /* recv_stateless_reset */
		NULL, /* recv_retry */
		NULL, //extend_max_local_streams_bidi, //XXX Needed? Currently NULL
		NULL, /* extend_max_local_streams_uni */
		rand_cb,
		get_new_connection_id_cb,
		NULL, /* remove_connection_id */
		ngtcp2_crypto_update_key_cb,
		NULL, /* path_validation */
		NULL, /* select_preferred_address */
		NULL, /* stream_reset */
		NULL, /* extend_max_remote_streams_bidi */
		NULL, /* extend_max_remote_streams_uni */
		NULL, /* extend_max_stream_data */
		NULL, /* dcid_status */
		NULL, /* handshake_confirmed */
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
	ngtcp2_settings settings;
	int rv;

	ngtcp2_ccerr_default(&conn_data->last_error);

	/* Create an OpenSSL TLS context for ngtcp2 */
	rv = quic_server_tls_init(conn_data);
	if (rv != 0) {
		zlog_warn("QUIC: Failed to create TLS context");
		goto failed;
	}

	if (dcid == NULL || scid == NULL) {
		zlog_warn("QUIC: Source or Destination cid was not provided");
		goto failed;
	}

	ngtcp2_settings_default(&settings);
	settings.cc_algo = NGTCP2_CC_ALGO_BBR;
	settings.initial_ts = timestamp();
	settings.log_printf = zlog_ngtcp2;

	conn_data->initial_params.original_dcid = *scid;
	conn_data->initial_params.original_dcid_present = 1;

	rv = ngtcp2_conn_server_new(&conn_data->conn, dcid, scid, &path, NGTCP2_PROTO_VER_V1,
				    &callbacks, &settings, &conn_data->initial_params, NULL,
				    conn_data);
	if (rv != 0) {
		zlog_warn("QUIC: ngtcp2_conn_server_new: %s", ngtcp2_strerror(rv));
		goto failed;
	}

	ngtcp2_conn_set_tls_native_handle(conn_data->conn, conn_data->ossl_ctx);
	conn_data->conn_ref.get_conn = get_conn;
	conn_data->conn_ref.user_data = conn_data;

	return 0;

failed:
	cleanup_on_init_failure(conn_data);
	return -1;
}

static int quic_client_conn_init(struct quic_conn_data *conn_data,
				 const struct sockaddr *remote_addr, socklen_t remote_addrlen)
{
	ngtcp2_path path = {
		{
			(struct sockaddr *)&conn_data->local_addr,
			conn_data->local_addrlen,
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
		recv_stream_data_cb,
		NULL, /* acked_stream_data_offset */
		NULL, /* stream_open */
		stream_close_cb,
		NULL, /* recv_stateless_reset */
		ngtcp2_crypto_recv_retry_cb,
		NULL, /* extend_max_local_streams_bidi */
		NULL, /* extend_max_local_streams_uni */
		rand_cb,
		get_new_connection_id_cb,
		NULL, /* remove_connection_id */
		ngtcp2_crypto_update_key_cb,
		NULL, /* path_validation */
		NULL, /* select_preferred_address */
		NULL, /* stream_reset */
		NULL, /* extend_max_remote_streams_bidi */
		NULL, /* extend_max_remote_streams_uni */
		NULL, /* extend_max_stream_data */
		NULL, /* dcid_status */
		handshake_confirmed_client_cb,
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

	ngtcp2_ccerr_default(&conn_data->last_error);

	/* Create an OpenSSL TLS context for ngtcp2 */
	rv = quic_client_tls_init(conn_data);
	if (rv != 0) {
		zlog_warn("QUIC: Failure to create TLS context");
		goto failed;
	}

	/* Source and destination Connection ID's start out randomized */
	dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
	scid.datalen = QUIC_SCIDLEN;
	if (RAND_bytes(dcid.data, (int)dcid.datalen) != 1
	    || RAND_bytes(scid.data, (int)scid.datalen) != 1) {
		zlog_warn("QUIC: Failure to call RAND_bytes");
		goto failed;
	}

	ngtcp2_settings_default(&settings);
	settings.cc_algo = NGTCP2_CC_ALGO_BBR;
	settings.initial_ts = timestamp();
	settings.log_printf = zlog_ngtcp2;

	rv = ngtcp2_conn_client_new(&conn_data->conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1,
				    &callbacks, &settings, &conn_data->initial_params, NULL,
				    conn_data);
	if (rv != 0) {
		zlog_warn("QUIC: ngtcp2_conn_client_new: %s", ngtcp2_strerror(rv));
		goto failed;
	}

	ngtcp2_conn_set_tls_native_handle(conn_data->conn, conn_data->ossl_ctx);
	conn_data->conn_ref.get_conn = get_conn;
	conn_data->conn_ref.user_data = conn_data;

	return 0;

failed:
	cleanup_on_init_failure(conn_data);
	return -1;
}


static int quic_send_packet(struct quic_conn_data *conn_data, const uint8_t *data, size_t datalen)
{
	struct iovec iov = { (uint8_t *)data, datalen };
	struct msghdr msg = { 0 };
	ssize_t nwrite;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	do {
		nwrite = sendmsg(conn_data->fd, &msg, 0);
	} while (nwrite == -1 && errno == EINTR);

	if (nwrite == -1) {
		zlog_warn("QUIC: sendmsg: %s", safe_strerror(errno));
		return -1;
	}

	return 0;
}


static void quic_entry_delete(struct quic_socket_entry *socket_entry)
{
	int rv;

	/* There must be agreement between user and conn_data that the entry is ready to be freed */
	if (!socket_entry->is_user_closed || !socket_entry->is_conn_closed) {
		zlog_warn("QUIC: Trying to destroy socket entry with fd=%d but is not agreed that should close.",
			  socket_entry->entry.fd);
		assert(0);
	}

	/* Removes the entry from the FRR socket table and destroys it via a callback after RCU finds
	 * no more references to it. When the last entry is destroyed, so it the conn_data instance.
	 */
	rv = frr_socket_table_delete(&socket_entry->entry);
	if (rv != 0) {
		zlog_warn("QUIC: Trying to destroy socket entry with fd=%d but not found in the table.",
			  socket_entry->entry.fd);
		assert(0);
	}
}


static void quic_delete_conn(struct quic_conn_data *conn_data)
{
	struct frr_socket_entry search_entry = {};
	struct fd_fifo_entry *fd_entry;

	/* When the lib is shutting down, it will destroy the socket entries instead of us */
	if (conn_data->lib_shutdown)
		return;

	frr_each_safe(fd_fifo, &conn_data->stream_fds, fd_entry) {
		struct quic_socket_entry *socket_entry = NULL;

		search_entry.fd = fd_entry->fd;
		frr_socket_table_find(&search_entry, t_entry);
		if (!t_entry)
			continue;
		assert(t_entry->protocol == IPPROTO_QUIC);
		socket_entry = (struct quic_socket_entry *)t_entry;

		socket_entry->is_conn_closed = true;
		if (socket_entry->is_user_closed)
			quic_entry_delete(socket_entry);
	}
}


static void quic_delete_event(struct event *thread)
{
	struct quic_conn_data *conn_data = EVENT_ARG(thread);

	assert(conn_data);
	conn_data->t_quic_delete = NULL;

	frr_with_mutex(&conn_data->lock)
	{
		quic_delete_conn(conn_data);
	}
}


static void quic_schedule_delete_conn(struct quic_conn_data *conn_data)
{
	ngtcp2_duration pto = ONESEC2NANO;

	if (conn_data->conn)
		pto = 3 * ngtcp2_conn_get_pto(conn_data->conn); /* As per RFC 9000 */
	pto = MIN(pto, (ngtcp2_duration)ONESEC2NANO*60*15); /* Arbitrary 15 Minute max */
	pto = pto / ONEMILLISEC2NANO; /* nanoseconds --> milliseconds */

	event_add_timer_msec(frr_socket_threadmaster, quic_delete_event,
			     conn_data, pto, &conn_data->t_quic_delete);
}


static void quic_declare_conn_closed(struct quic_conn_data *conn_data)
{
	quic_change_state(conn_data, QUIC_CLOSED);

	/* Stop all I/O-related background events */
	assert(pthread_self() == frr_socket_threadmaster->owner);
	if (conn_data->t_background_process)
		event_cancel(&conn_data->t_background_process);
	if (conn_data->t_background_timeout)
		event_cancel(&conn_data->t_background_timeout);
	if (conn_data->t_background_listen)
		event_cancel(&conn_data->t_background_listen);

	/* In case a delayed close is in progress, but this time we must close abruptly */
	if (conn_data->t_quic_delete)
		event_cancel(&conn_data->t_quic_delete);

	conn_data->t_background_process = NULL;
	conn_data->t_background_timeout = NULL;
	conn_data->t_background_listen = NULL;
	conn_data->t_quic_delete = NULL;

	if (conn_data->lib_shutdown) {
		quic_delete_conn(conn_data);
	} else {
		quic_schedule_delete_conn(conn_data);
	}
}


static void quic_close_listener(struct quic_conn_data *conn_data)
{
	struct fd_fifo_entry *fd_entry;
	struct frr_socket_entry search_entry = {};
	struct quic_socket_entry *listener_entry = NULL;

	if (conn_data->state != QUIC_LISTENING) {
		zlog_err("QUIC: Trying to close a non-listener with fd=%d as a listener",
			 conn_data->fd);
		assert(0);
	}

	fd_entry = fd_fifo_first(&conn_data->stream_fds);
	search_entry.fd = fd_entry->fd;
	frr_socket_table_find(&search_entry, found_l_entry);
	assert(found_l_entry && found_l_entry->protocol == IPPROTO_QUIC);
	listener_entry = (struct quic_socket_entry *)found_l_entry;

	/* Any in-progress connections must be terminated */
	frr_each_safe(fd_fifo, &listener_entry->unclaimed_fds, fd_entry) {
		search_entry.fd = fd_entry->fd;

		frr_socket_table_find(&search_entry, t_entry);

		if (t_entry)
			quic_close(t_entry);

		fd_fifo_del(&listener_entry->unclaimed_fds, fd_entry);
		XFREE(MTYPE_FRR_SOCKET, fd_entry);
	}

	if (conn_data->t_background_listen) {
		event_cancel(&conn_data->t_background_listen);
	}
	quic_declare_conn_closed(conn_data);
}


static void quic_close_conn(struct quic_conn_data *conn_data)
{
	ngtcp2_ssize nwrite;
	ngtcp2_pkt_info pi;
	ngtcp2_path_storage ps;
	uint8_t buf[1280];

	/* conn_data should be locked by caller */
	assert(pthread_mutex_trylock(&conn_data->lock) != 0);

	if (conn_data->state == QUIC_CLOSED || conn_data->state == QUIC_CLOSING ||
	    ngtcp2_conn_in_closing_period(conn_data->conn) ||
	    ngtcp2_conn_in_draining_period(conn_data->conn)) {
		return;
	}

	ngtcp2_path_storage_zero(&ps);
	nwrite = ngtcp2_conn_write_connection_close(conn_data->conn, &ps.path, &pi, buf,
						    sizeof(buf), &conn_data->last_error,
						    timestamp());

	/* Invalid state means that the handshake never completed, which is is possible */
	if (nwrite < 0 && nwrite != NGTCP2_ERR_INVALID_STATE) {
		zlog_warn("QUIC: ngtcp2_conn_write_connection_close: %s",
			  ngtcp2_strerror((int)nwrite));
	} else if (nwrite > 0) {
		/* As soon as we send out this packet, we can consider the connection dead */
		quic_send_packet(conn_data, buf, (size_t)nwrite);
	} /* nwrite == 0 is a noop */

	quic_declare_conn_closed(conn_data);
}


static void quic_check_all_entries_user_closed(struct quic_conn_data *conn_data)
{
	struct fd_fifo_entry *fd_entry = NULL;
	struct frr_socket_entry search_entry = {};

	/* The connection is only closed once *every* entry is closed (either user/conn side) */
	frr_each_safe(fd_fifo, &conn_data->stream_fds, fd_entry) {
		struct quic_socket_entry *t_socket_entry = NULL;
		search_entry.fd = fd_entry->fd;

		frr_socket_table_find(&search_entry, t_entry);
		if (!t_entry)
			continue;

		assert(t_entry->protocol == IPPROTO_QUIC);
		t_socket_entry = (struct quic_socket_entry *)t_entry;

		if (!t_socket_entry->is_user_closed)
			return;
	}

	/* We determined that the connection needs to be closed. The how-to depends on state */
	switch(conn_data->state) {
	case QUIC_NONE:
	case QUIC_CLOSED:
		quic_declare_conn_closed(conn_data);
		/* quic_declare_conn_closed will start the entry destruction process immediately. */
		break;
	case QUIC_LISTENING:
		quic_close_listener(conn_data);
		break;
	case QUIC_CONNECTING:
	case QUIC_NO_STREAMS:
		quic_close_conn(conn_data);
		break;
	case QUIC_CONNECTED:
		/* Don't take action and let streams flush themselves if able. Not possible in
		 * instances where we are abruptly shutting down.
		 */
		if (conn_data->lib_shutdown)
			quic_close_conn(conn_data);
		break;
	case QUIC_CLOSING:
		/* Do not take any action. The connection is already closing. */
		break;
	case QUIC_STATE_MAX:
		assert(0);
	}
}


static void quic_close_event(struct event *thread)
{
	struct quic_conn_data *conn_data = EVENT_ARG(thread);

	assert(conn_data != NULL);
	frr_mutex_lock_autounlock(&conn_data->lock);

	conn_data->t_socket_closed = NULL;
	conn_data->wait_for_shutdown_event = false;

	quic_check_all_entries_user_closed(conn_data);

	return;
}


static void quic_reschedule_timeout_process(struct quic_conn_data *conn_data)
{
	ngtcp2_tstamp expiry, now;
	uint64_t timeout;

	if (conn_data->t_background_timeout) {
		event_cancel(&conn_data->t_background_timeout);
		conn_data->t_background_timeout = NULL;
	}

	if (conn_data->state == QUIC_NONE || conn_data->state == QUIC_CLOSED)
		return;

	expiry = ngtcp2_conn_get_expiry(conn_data->conn);
	now = timestamp();

	timeout = expiry < now ? 0 : expiry - now;
	timeout = MIN(timeout, (ngtcp2_duration)ONESEC2NANO*60*15); /* Arbitrary 15 Minute max */
	/* nanoseconds --> milliseconds (rounded up) */
	timeout = (timeout + ONEMILLISEC2NANO - 1) / ONEMILLISEC2NANO;

	event_add_timer_msec(frr_socket_threadmaster, quic_background_timeout_process,
			     conn_data, timeout, &conn_data->t_background_timeout);
}


static int quic_write_to_conn(struct quic_conn_data *conn_data)
{
	ngtcp2_tstamp ts = timestamp();
	ngtcp2_pkt_info pi;
	ngtcp2_ssize nwrite;
	uint8_t buf[1452];
	ngtcp2_path_storage ps;
	ngtcp2_vec datav;
	size_t datavcnt;
	int64_t stream_id = -1;  /* Default for writing just connection data */
	ngtcp2_ssize written_datalen;
	uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
	bool stream_fin;
	const uint8_t* msg = NULL; // XXX Remove me!
	size_t msg_size = 0;
	struct fd_fifo_entry *fd_entry;
	struct frr_socket_entry search_entry = {};
	struct quic_socket_entry *socket_entry;

	ngtcp2_path_storage_zero(&ps);

	fd_entry = fd_fifo_first(&conn_data->stream_fds);
	assert(fd_entry);
	search_entry.fd = fd_entry->fd;
	frr_socket_table_find(&search_entry, found_entry);
	assert(found_entry && found_entry->protocol == IPPROTO_QUIC);
	socket_entry = (struct quic_socket_entry *)found_entry;

	if (socket_entry->msg && socket_entry->stream_id != -1 &&
	    conn_data->state == QUIC_CONNECTED) {
		stream_id = socket_entry->stream_id;
		msg = (const uint8_t *)socket_entry->msg;
		msg_size = 11;
		//flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
		//stream_fin = true;
	}

	/* conn_data should be locked by caller who is in the frr_socket_threadmaster's pthread */
	assert(pthread_self() == frr_socket_threadmaster->owner);
	assert(pthread_mutex_trylock(&conn_data->lock) != 0);

	for (;;) {

		if (conn_data->state == QUIC_NONE || conn_data->state == QUIC_CLOSED)
			return 0;

		// XXX Get data to read/write (but not if stream_fin!)

		nwrite = ngtcp2_conn_write_stream(conn_data->conn, &ps.path, &pi, buf,
						  sizeof(buf), &written_datalen, flags, stream_id,
						  msg, msg_size, ts);

		// XXX Remove me
		if (msg && written_datalen > 0) {
			msg = NULL;
			msg_size = 0;
			socket_entry->msg = NULL;
			stream_id = -1;
		}

		if (nwrite < 0) {
			switch (nwrite) {
			case NGTCP2_ERR_WRITE_MORE:
				/* ngtcp2 can still pack more into this packet */
				/*
				c->stream.nwrite += (size_t)wdatalen;

				if (wdatalen > 0) {
					flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
					nwrite = ngtcp2_conn_writev_stream(c->conn, &ps.path, &pi,
									   buf, sizeof(buf), NULL,
									   flags, stream_id, NULL,
									   0, ts);
					blocked = true;
				}
				XXX Actually write from the packet!
				*/
				continue;
			case NGTCP2_ERR_STREAM_SHUT_WR:
				/* Stream is half-closed or being reset */
				zlog_warn(
					"QUIC: ngtcp2_conn_writev_stream failed due to being shut");
				assert(0); // XXX Unsure as to how to handle this yet
				break;
			case NGTCP2_ERR_STREAM_DATA_BLOCKED:
				/* Stream is blocked due to congestion control */
				assert(written_datalen == -1);
				stream_id = -1; /* Return to only writing control data*/
				// XXX How to check when we are unclocked?
				continue;
			case NGTCP2_ERR_STREAM_NOT_FOUND:
				/* How did we get this stream? Not fatal, but still concerning. */
				zlog_warn("QUIC: ngtcp2_conn_writev_stream found invalid stream: %lld",
					  stream_id);
				stream_id = -1;
				continue;
			case NGTCP2_ERR_CLOSING:
			case NGTCP2_ERR_DRAINING:
				/* The connection has closed */
				quic_declare_conn_closed(conn_data);
				return 0;
			default:
				zlog_err("QUIC: ngtcp2_conn_writev_stream: %s",
					 ngtcp2_strerror((int)nwrite));
				/* XXX Close with error
				ngtcp2_ccerr_set_liberr(&c->last_error, (int)nwrite, NULL, 0);
				*/
				return -1;
			}
		}

		if (nwrite == 0)
			break;

		else if (written_datalen > 0) {
			/* XXX Adjust data written from the buffer here!
			c->stream.nwrite += (size_t)wdatalen;
			*/
		}

		quic_send_packet(conn_data, buf, (size_t)nwrite);
		break;
	}

	quic_reschedule_timeout_process(conn_data);

	return 0;
}


static int quic_process_read_packet(struct quic_conn_data *conn_data, uint8_t *pkt,
				    size_t pktsize, struct msghdr *msg)
{
	ngtcp2_path path = {};
	ngtcp2_pkt_info pi = { 0 };
	ngtcp2_version_cid vc;
	int rv;

	// XXX Drop the packet if the source/dest don't match expected path.
	// (Due to unconnected over connected sockets)

	rv = ngtcp2_pkt_decode_version_cid(&vc, pkt, pktsize, QUIC_SCIDLEN);
	if (rv != 0) {
		/* XXX We currently don't take advantage of version negotiation */
		zlog_warn("QUIC: ngtcp2_pkt_decode_version_cid failed on packet");
		return 0;
	}

	path.local.addrlen = conn_data->local_addrlen;
	path.local.addr = (struct sockaddr *)&conn_data->local_addr;
	path.remote.addrlen = msg->msg_namelen;
	path.remote.addr = msg->msg_name;

	// XXX drop the packet if it is not from the expected remote (unconnected over connected
	// race conition)

	/* The caller of this function should have locked conn_data for us. */
	assert(pthread_mutex_trylock(&conn_data->lock) != 0);
	rv = ngtcp2_conn_read_pkt(conn_data->conn, &path, &pi, pkt, pktsize, timestamp());

	if (rv != 0) {
		if (rv == NGTCP2_ERR_CLOSING || rv == NGTCP2_ERR_DRAINING) {
			/* We have detected that the connection is closed */
			quic_declare_conn_closed(conn_data);
			return 0;
		}

		zlog_warn("QUIC: ngtcp2_conn_read_pkt: %s", ngtcp2_strerror(rv));

		if (conn_data->last_error.error_code) {
			/* Do not overwrite the last error the library encountered */
			return -1;
		}

		switch (rv) {
		case NGTCP2_ERR_CRYPTO:
			ngtcp2_ccerr_set_tls_alert(&conn_data->last_error,
						   ngtcp2_conn_get_tls_alert(conn_data->conn),
						   NULL, 0);
			break;
		default:
			ngtcp2_ccerr_set_liberr(&conn_data->last_error, rv, NULL, 0);
		}

		return -1;
	}

	/* Automatically close the connection if all open streams have closed */
	if (conn_data->state == QUIC_NO_STREAMS) {
		quic_close_conn(conn_data);
	}

	return 0;
}


static int quic_process_listener_packet(struct quic_conn_data *conn_data, uint8_t *pkt,
					size_t pktsize, struct msghdr *msg)
{
	ngtcp2_path path;
	ngtcp2_pkt_info pi = { 0 };
	ngtcp2_version_cid vc;
	ngtcp2_pkt_hd hd;
	int rv, domain, new_fd = 0;
	socklen_t domain_len = sizeof(domain);
	struct quic_socket_entry *socket_entry = NULL;
	struct quic_socket_entry *listen_entry = NULL;
	struct quic_conn_data *new_conn_data = NULL;
	struct frr_socket_entry search_entry = {};
	struct fd_fifo_entry *listen_fd_entry = NULL;
	struct fd_fifo_entry *fd_entry = NULL;

	assert(conn_data->state == QUIC_LISTENING);

	/* Check if the packet is a valid start of a new connection */
	rv = ngtcp2_accept(&hd, pkt, (size_t)pktsize);
	if (rv != 0) {
		zlog_warn("QUIC: ngtcp2_accept received invalid packet (discarded)");
		return 0;
	}

	/* Retreive the tracked listener frr_socket_entry. We will modify it. */
	listen_fd_entry = fd_fifo_first(&conn_data->stream_fds);
	assert(listen_fd_entry);
	search_entry.fd = listen_fd_entry->fd;
	frr_socket_table_find(&search_entry, found_entry);
	assert(found_entry && found_entry->protocol == IPPROTO_QUIC);
	listen_entry = (struct quic_socket_entry *)found_entry;

	/* Ignore the new connection if we are at capacity */
	// XXX Need to check listener entry for this
	if (fd_fifo_count(&listen_entry->unclaimed_fds) >= (size_t)listen_entry->listener_backlog) {
		zlog_warn("QUIC: cannot start a new connection due to backlog");
		return 0;
	}

	path.local.addrlen = conn_data->local_addrlen;
	path.local.addr = (struct sockaddr *)&conn_data->local_addr;
	path.remote.addrlen = msg->msg_namelen;
	path.remote.addr = msg->msg_name;

	/* To start a new connection, we create a new socket_entry/conn_data pair and enter it into
	 * the listen_entry to be tracked.
	 */
	if (getsockopt(conn_data->fd, SOL_SOCKET, SO_DOMAIN, &domain, &domain_len) != 0) {
		zlog_warn("QUIC: listener getsockopt SO_DOMAIN: %s", safe_strerror(errno));
		goto failed;
	}
	new_fd = quic_socket(domain, SOCK_STREAM);
	if (new_fd < 0) {
		zlog_warn("QUIC: listener socket: %s", safe_strerror(errno));
		goto failed;
	}

	/* Immediately retreive the entry so we can pass it to quic_* setup functions */
	search_entry.fd = new_fd;
	frr_socket_table_find(&search_entry, new_entry);
	assert(new_entry && new_entry->protocol == IPPROTO_QUIC);
	socket_entry = (struct quic_socket_entry *)new_entry;

	rv = quic_bind(new_entry, (struct sockaddr *)&conn_data->local_addr,
		       conn_data->local_addrlen);
	if (rv != 0) {
		zlog_warn("QUIC: listener bind error: %s", safe_strerror(errno));
		goto failed;
	}

	/* locking conn_data is safe, since we know its state (we just created it!) */
	new_conn_data = socket_entry->conn_data;
	frr_mutex_lock_autounlock(&new_conn_data->lock);

	rv = connect(new_conn_data->fd, path.remote.addr, path.remote.addrlen);
	if (rv < 0) {
		zlog_warn("QUIC: listener connect: %s", safe_strerror(errno));
		goto failed;
	}

	rv = quic_server_conn_init(new_conn_data, path.remote.addr, path.remote.addrlen,
				   &hd.scid, &hd.dcid);
	if (rv != 0) {
		zlog_warn("QUIC: failed to create server connection context");
		goto failed;
	}

	quic_change_state(new_conn_data, QUIC_CONNECTING);

	/* Finally, read the packet that started this new connection. Calling this method directly
	 * may be unsafe in the future when we enable 0rtt in ngtcp2.
	 */
	rv = quic_process_read_packet(new_conn_data, pkt, pktsize, msg);
	if (rv == -1) {
		zlog_warn(
			"QUIC: newly created server connection context is being immediately destroyed");
		goto failed;
	}

	fd_entry = XMALLOC(MTYPE_FRR_SOCKET, sizeof(*fd_entry));
	if (!fd_entry) {
		errno = ENOMEM;
		zlog_warn("QUIC: Internal memory allocation failed");
		goto failed;
	}
	memset(fd_entry, 0x00, sizeof(*fd_entry));
	fd_entry->fd = new_entry->fd;
	fd_fifo_add_tail(&listen_entry->unclaimed_fds, fd_entry);

	/* Start the normal background processing loop. The response to the initial packet will be
	 * generated within this loop by the ngtcp2 library.
	 */
	event_add_write(frr_socket_threadmaster, quic_background_process, new_conn_data,
			new_conn_data->fd, &new_conn_data->t_background_process);

	// XXX Also start the loop on timeout.

	return 0;

failed:
	/* quic_close() can cleanup after all these failure states already */
	// XXX Is the previous statement true?
	if (socket_entry != NULL) {
		quic_close((struct frr_socket_entry *)socket_entry);
	}

	return -1;
}


static int quic_read_from_conn(struct quic_conn_data *conn_data)
{
	uint8_t buf[65536];
	union sockunion addr;
	struct iovec iov = { buf, sizeof(buf) };
	struct msghdr msg = { 0 };
	ssize_t nread;
	int rv;

	msg.msg_name = &addr;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	/* conn_data should be locked by caller who is in the frr_socket_threadmaster's pthread */
	assert(pthread_self() == frr_socket_threadmaster->owner);
	assert(pthread_mutex_trylock(&conn_data->lock) != 0);

	/* Repeatedly read until there is nothing left */
	// XXX Do we want to change this behavior to break at some point?
	for (;;) {

		if (conn_data->state == QUIC_NONE || conn_data->state == QUIC_CLOSED)
			return 0;

		msg.msg_namelen = sizeof(addr);
		nread = recvmsg(conn_data->fd, &msg, MSG_DONTWAIT);

		if (nread == -1) {
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				// XXX Properly handle the error
				zlog_warn("QUIC: recvmsg: %s", safe_strerror(errno));
				return -1;
			}
			break;
		}

		if (conn_data->state == QUIC_LISTENING) {
			rv = quic_process_listener_packet(conn_data, buf, (size_t)nread, &msg);
		} else {
			rv = quic_process_read_packet(conn_data, buf, (size_t)nread, &msg);
		}

		if (rv < 0)
			return rv;
	}

	return 0;
}


/*
 * The following are events that may be scheduled
 */


static void quic_background_process(struct event *thread)
{
	struct quic_conn_data *conn_data = EVENT_ARG(thread);
	assert(conn_data != NULL);
	frr_mutex_lock_autounlock(&conn_data->lock);

	if (conn_data->state == QUIC_NONE || conn_data->state == QUIC_CLOSED) {
		return;
	}

	conn_data->t_background_process = NULL;

	if (quic_read_from_conn(conn_data) < 0) {
		// XXX Reset the connection?
	}

	if (quic_write_to_conn(conn_data) < 0) {
		// XXX Reset the connection?
	}

	if (conn_data->state != QUIC_CLOSED) {
		event_add_read(frr_socket_threadmaster, quic_background_process, conn_data,
			       conn_data->fd, &conn_data->t_background_process);
	}
}


static void quic_background_timeout_process(struct event *thread)
{
	int rv;
	struct quic_conn_data *conn_data = EVENT_ARG(thread);

	assert(conn_data != NULL);
	frr_mutex_lock_autounlock(&conn_data->lock);

	if (conn_data->state == QUIC_NONE || conn_data->state == QUIC_CLOSED) {
		return;
	}

	conn_data->t_background_timeout = NULL;

	rv = ngtcp2_conn_handle_expiry(conn_data->conn, timestamp());
	if (rv != 0) {
		zlog_err("QUIC: ngtcp2_conn_handle_expiry: %s", ngtcp2_strerror(rv));
		assert(0); // XXX Properly handle the error?
	}

	if (quic_write_to_conn(conn_data) < 0) {
		// XXX Reset the connection?
	}

	/* This event gets rescheduled within quic_write_to_conn */
}



static void quic_background_listen(struct event *thread)
{
	struct quic_conn_data *conn_data = EVENT_ARG(thread);
	assert(conn_data != NULL);
	frr_mutex_lock_autounlock(&conn_data->lock);

	if (conn_data->state == QUIC_CLOSED) {
		return;
	} else if (conn_data->state != QUIC_LISTENING) {
		zlog_err("QUIC: Listening process unexpectedly found scheduled on non-listener (conn %d).",
			 conn_data->fd);
		assert(0);
	}

	conn_data->t_background_listen = NULL;

	if (quic_read_from_conn(conn_data) < 0) {
		//XXX Reset the connection?
	}

	if (conn_data->state != QUIC_CLOSED) {
		event_add_read(frr_socket_threadmaster, quic_background_listen, conn_data,
			       conn_data->fd, &conn_data->t_background_listen);
	}
}


/*
 * The following provide the wrappers called by the frr_socket core library
 */
int quic_socket(int domain, int type)
{
	int sock_fd, conn_fd;
	bool del_mutex = false;
	struct quic_socket_entry *socket_entry;
	struct quic_conn_data *conn_data;
	struct fd_fifo_entry *fd_entry;

	/* A user should understand this as a stream socket (even when UDP is underlying) */
	if (type != SOCK_STREAM) {
		errno = EPROTONOSUPPORT;
		goto failed;
	}

	/* ngtcp2 supports IPv6. However, we will not provide that support initially */
	if (domain != AF_INET) {
		errno = EPROTONOSUPPORT;
		goto failed;
	}

	conn_fd = socket(domain, SOCK_DGRAM, IPPROTO_UDP);
	if (conn_fd < 0)
		goto failed;

	/* This fd will be handed to the user. It will correspond to a single stream. The fd *MUST*
	 * be allocated by the kernel, else it would not be compatible with the existing usage of
	 * kernel socket fds. Opening /dev/null is a bit hacky, but serves this purpose.
	 */
	sock_fd = open("/dev/null", O_RDWR);
	assert(sock_fd);

	socket_entry = XMALLOC(MTYPE_FRR_SOCKET, sizeof(*socket_entry));
	conn_data = XMALLOC(MTYPE_FRR_SOCKET, sizeof(*conn_data));
	if (!socket_entry || !conn_data) {
		errno = ENOMEM;
		goto failed;
	}

	memset(conn_data, 0x00, sizeof(*conn_data));
	conn_data->fd = conn_fd;
	conn_data->state = QUIC_NONE;
	/* The defaults for a ngtcp2 connection (not necessarily a single stream!) */
	// XXX Revisit these initial parameters to confirm if they are good
	ngtcp2_transport_params_default(&conn_data->initial_params);
	conn_data->initial_params.initial_max_streams_uni = 0;
	conn_data->initial_params.initial_max_streams_bidi = 1;
	conn_data->initial_params.initial_max_stream_data_bidi_local = 128 * 1024;
	conn_data->initial_params.initial_max_stream_data_bidi_remote = 128 * 1024;
	conn_data->initial_params.initial_max_data = 256 * 1024;
	fd_fifo_init(&conn_data->stream_fds);
	if (pthread_mutex_init(&conn_data->lock, NULL) != 0) {
		errno = ENOMEM;
		del_mutex = true;
		goto failed;
	}

	memset(socket_entry, 0x00, sizeof(*socket_entry));
	frr_socket_init(&socket_entry->entry);
	socket_entry->entry.protocol = IPPROTO_QUIC;
	socket_entry->entry.fd = sock_fd;
	socket_entry->stream_id = -1;  /* Stream id may be 0, but is guarenteed not -1 */
	socket_entry->is_user_closed = false;
	socket_entry->is_conn_closed = false;
	socket_entry->is_stream_fin = false;
	socket_entry->conn_data = conn_data;
	fd_fifo_init(&socket_entry->unclaimed_fds);
	socket_entry->msg = "Hello world"; // XXX Remove me!

	/* Add a "reference" from the conn_data -> socket_entry. The conn_data WILL aquire this
	 * socket entry (via locking) to fetch/deposit stream data, change values, etc.
	 */
	fd_entry = XMALLOC(MTYPE_FRR_SOCKET, sizeof(*fd_entry));
	if (!fd_entry) {
		errno = ENOMEM;
		goto failed;
	}
	memset(fd_entry, 0x00, sizeof(*fd_entry));
	fd_entry->fd = sock_fd;
	fd_fifo_add_tail(&conn_data->stream_fds, fd_entry);

	frr_socket_table_add((struct frr_socket_entry *)socket_entry);

	return sock_fd;

failed:
	if (sock_fd != -1) {
		close(sock_fd);
		sock_fd = -1;
	}
	if (conn_fd != -1) {
		close(conn_fd);
		conn_fd = -1;
	}
	if (del_mutex) {
		pthread_mutex_destroy(&conn_data->lock);
	}
	if (socket_entry) {
	        XFREE(MTYPE_FRR_SOCKET, socket_entry);
		socket_entry = NULL;
	}
	if (conn_data) {
	        XFREE(MTYPE_FRR_SOCKET, conn_data);
		conn_data = NULL;
	}
	if (fd_entry) {
		XFREE(MTYPE_FRR_SOCKET, fd_entry);
		fd_entry = NULL;
	}

	return -1;
}


int quic_bind(struct frr_socket_entry *entry, const struct sockaddr *addr, socklen_t addrlen)
{
	int rv;
	struct quic_socket_entry *socket_entry = (struct quic_socket_entry *)entry;
	struct quic_conn_data *conn_data;
	assert(entry->protocol == IPPROTO_QUIC);
	conn_data = socket_entry->conn_data;

	frr_try_with_mutex(&conn_data->lock)
	{
		if (conn_data->state != QUIC_NONE) {
			errno = EINVAL;
			return -1;
		}

		if (setsockopt(conn_data->fd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) <
		    0) {
			zlog_warn("QUIC: listener on %d (conn %d) setsockopt SO_REUSEADDR: %s",
				  entry->fd, conn_data->fd, safe_strerror(errno));
			errno = EADDRINUSE;
			return -1;
		}

		rv = bind(conn_data->fd, addr, addrlen);
		if (rv != 0) {
			/* errno is kept */
			return -1;
		}

		conn_data->local_addrlen = sizeof(conn_data->local_addr);
		rv = getsockname(conn_data->fd, (struct sockaddr *)&conn_data->local_addr,
				 &conn_data->local_addrlen);
		assert(rv == 0);
		return 0;
	}

	/* Failed to aquire lock, thus the conn_data instance must be active. Illegal func. call */
	errno = EINVAL;
	return -1;
}


int quic_connect(struct frr_socket_entry *entry, const struct sockaddr *addr, socklen_t addrlen)
{
	int rv;
	struct quic_socket_entry *socket_entry = (struct quic_socket_entry *)entry;
	struct quic_conn_data *conn_data;
	assert(entry->protocol == IPPROTO_QUIC);
	conn_data = socket_entry->conn_data;

	frr_try_with_mutex(&conn_data->lock)
	{
		if (conn_data->state == QUIC_CONNECTED || conn_data->state == QUIC_CONNECTING) {
			errno = EISCONN;
			return -1;
		} else if (conn_data->state != QUIC_NONE) {
			errno = EINVAL;
			return -1;
		}

		rv = connect(conn_data->fd, addr, addrlen);
		if (rv != 0) {
			/* errno is kept */
			return -1;
		}

		rv = quic_client_conn_init(conn_data, addr, addrlen);
		if (rv != 0) {
			/* XXX Disconnect the socket? And is this the right error? */
			errno = EINVAL;
			return -1;
		}

		quic_change_state(conn_data, QUIC_CONNECTING);
		event_add_write(frr_socket_threadmaster, quic_background_process, conn_data,
				conn_data->fd, &conn_data->t_background_process);

		/* We always will "fail" with EINPROGRESS in order to allow for background events to
		 * be completed. This includes perfoming the handshake and automatically creating at
		 * least one stream.
		 */
		errno = EINPROGRESS;
		return -1;
	}

	/* Failed to aquire lock, thus the conn_data instance must be active. Illegal func. call */
	errno = EINVAL;
	return -1;
}


int quic_listen(struct frr_socket_entry *entry, int backlog)
{
	struct quic_socket_entry *socket_entry = (struct quic_socket_entry *)entry;
	struct quic_conn_data *conn_data;

	assert(entry->protocol == IPPROTO_QUIC);
	conn_data = socket_entry->conn_data;

	frr_try_with_mutex(&conn_data->lock)
	{
		if (conn_data->state != QUIC_NONE) {
			// XXX What is the correct error code?
			errno = EINVAL;
			return -1;
		}

		socket_entry->listener_backlog = backlog;

		quic_change_state(conn_data, QUIC_LISTENING);
		event_add_read(frr_socket_threadmaster, quic_background_listen, conn_data,
			       conn_data->fd, &conn_data->t_background_process);

		return 0;
	}

	/* Failed to aquire lock, thus the conn_data instance must be active. Illegal func. call */
	errno = EINVAL;
	return -1;
}


int quic_accept(struct frr_socket_entry *entry, struct sockaddr *addr, socklen_t *addrlen)
{
	struct fd_fifo_entry *fd_entry = NULL;
	struct frr_socket_entry search_entry = {};
	struct quic_socket_entry *socket_entry = NULL;
	assert(entry->protocol == IPPROTO_QUIC);
	socket_entry = (struct quic_socket_entry *)entry;

	if (socket_entry->listener_backlog <= 0) {
		errno = EINVAL;
		return -1;
	}

	frr_each_safe(fd_fifo, &socket_entry->unclaimed_fds, fd_entry) {
		struct quic_socket_entry *t_socket_entry = NULL;
		search_entry.fd = fd_entry->fd;

		frr_socket_table_find(&search_entry, t_entry);

		/* Connection failed, and has already been deleted */
		// XXX How to deal with the kernel re-using fd's? Could that cause a bug?
		if (t_entry == NULL) {
			fd_fifo_del(&socket_entry->unclaimed_fds, fd_entry);
			XFREE(MTYPE_FRR_SOCKET, fd_entry);
			continue;
		}

		assert(t_entry->protocol == IPPROTO_QUIC);
		t_socket_entry = (struct quic_socket_entry *)t_entry;

		if (t_socket_entry->is_user_closed) {
			/* Connection has failed. Stop tracking this entry */
			// XXX If accept is not called, then failed connections can be missed?
			fd_fifo_del(&socket_entry->unclaimed_fds, fd_entry);
			XFREE(MTYPE_FRR_SOCKET, fd_entry);
			continue;
		} else if (t_socket_entry->stream_id == -1) {
			continue;
		}

		fd_fifo_del(&socket_entry->unclaimed_fds, fd_entry);
		XFREE(MTYPE_FRR_SOCKET, fd_entry);

		/* XXX Copy address information into return buffers */

		return t_entry->fd;
	}

	errno = EWOULDBLOCK;
	return -1;
}


int quic_close(struct frr_socket_entry *entry)
{
	struct quic_socket_entry *socket_entry = NULL;
	struct quic_conn_data *conn_data;

	assert(entry->protocol == IPPROTO_QUIC);
	socket_entry = (struct quic_socket_entry *)entry;

	socket_entry->is_user_closed = true;
	socket_entry->is_stream_fin = true;

	if (socket_entry->is_conn_closed) {
		quic_entry_delete(socket_entry);
	} else {
		/* Notification to the conn_data instance that a user is ready to close an entry */
		conn_data = socket_entry->conn_data;
		pthread_mutex_unlock(&entry->lock);
		frr_with_mutex (&conn_data->lock) {
			event_add_timer_msec(frr_socket_threadmaster, quic_close_event, conn_data,
					     0, &conn_data->t_socket_closed);
		}
		pthread_mutex_lock(&entry->lock);
	}

	return 0;
}


ssize_t quic_writev(struct frr_socket_entry *entry, const struct iovec *iov, int iovcnt)
{
	assert(0); // XXX Implement me
	return writev(entry->fd, iov, iovcnt);
}


ssize_t quic_read(struct frr_socket_entry *entry, void *buf, size_t count)
{
	assert(0); // XXX Implement me
	return read(entry->fd, buf, count);
}


ssize_t quic_write(struct frr_socket_entry *entry, const void *buf, size_t count)
{
	assert(0); // XXX Implement me
	return write(entry->fd, buf, count);
}


int quic_setsockopt(struct frr_socket_entry *entry, int level, int option_name,
		    const void *option_value, socklen_t option_len)
{
	assert(0); // XXX Implement me
	return setsockopt(entry->fd, level, option_name, option_value, option_len);
}


int quic_getsockopt(struct frr_socket_entry *entry, int level, int optname, void *optval,
		    socklen_t *optlen)
{
	int rv = 1;
	struct quic_socket_entry *socket_entry = NULL;
	struct quic_conn_data *conn_data;

	assert(entry->protocol == IPPROTO_QUIC);
	socket_entry = (struct quic_socket_entry *)entry;
	conn_data = socket_entry->conn_data;
	assert(conn_data);

	/* We need to aquire both the frr_socket_entry and conn_data intance, but don't have priority
	 * to aquire the latter. We release our entry and aquire it in the reverse (safe) order.
	 */
	pthread_mutex_unlock(&entry->lock);
	frr_mutex_lock_autounlock(&conn_data->lock);
	pthread_mutex_lock(&entry->lock);

	if (level == SOL_SOCKET) {
		switch (optname) {
		case SO_ERROR:
			// XXX Handle ECONNREFUSED? ENETUNREACH? etc.
			rv = getsockopt(conn_data->fd, level, optname, optval, optlen);
			if (rv == 0 && socket_entry->stream_id == -1) {
				/* Overwrite optval with EINPRORESS if still connecting */
				rv = 0;
				*(int *)optval = EINPROGRESS;
			}
			break;
		}
	}


	/* If we didn't handle it ourselves, push it up to libc */
	if (rv == 1)
		rv = getsockopt(conn_data->fd, level, optname, optval, optlen);

	return rv;
}


int quic_getpeername(struct frr_socket_entry *entry, struct sockaddr *addr, socklen_t *addrlen)
{
	int rv = -1;
	struct quic_socket_entry *socket_entry = NULL;
	struct quic_conn_data *conn_data;

	assert(entry->protocol == IPPROTO_QUIC);
	socket_entry = (struct quic_socket_entry *)entry;
	conn_data = socket_entry->conn_data;
	assert(conn_data);

	/* To safely aquire the conn_data lock, we must release our own */
	pthread_mutex_unlock(&entry->lock);
	frr_with_mutex(&conn_data->lock) {
		rv = getpeername(conn_data->fd, addr, addrlen);
	}
	pthread_mutex_lock(&entry->lock);

	return rv;
}


int quic_getsockname(struct frr_socket_entry *entry, struct sockaddr *addr, socklen_t *addrlen)
{
	int rv = -1;
	struct quic_socket_entry *socket_entry = NULL;
	struct quic_conn_data *conn_data;

	assert(entry->protocol == IPPROTO_QUIC);
	socket_entry = (struct quic_socket_entry *)entry;
	conn_data = socket_entry->conn_data;
	assert(conn_data);

	/* To safely aquire the conn lock, we must release our own */
	pthread_mutex_unlock(&entry->lock);
	frr_with_mutex(&conn_data->lock) {
		rv = getsockname(conn_data->fd, addr, addrlen);
		//XXX Assert that addr and addrlen are consistent with saved
	}
	pthread_mutex_lock(&entry->lock);

	return rv;
}


int quic_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints,
		     struct addrinfo **res)
{
	int rv;
	struct addrinfo *res_next, quic_hints = {};

	/* A user should understand this as a stream socket (even when UDP is underlying) */
	if (hints->ai_socktype != SOCK_STREAM)
		return EAI_SOCKTYPE;

	memcpy(&quic_hints, hints, sizeof(*hints));

	/* QUIC sockets required an underlying UDP socket */
	quic_hints.ai_protocol = IPPROTO_UDP;
	quic_hints.ai_socktype = SOCK_DGRAM;
	rv = getaddrinfo(node, service, &quic_hints, res);
	if (rv != 0)
		return rv;

	/* Change IPPROTO_UDP back to IPPROTO_QUIC */
	for (res_next = *res; res_next != NULL; res_next = res_next->ai_next) {
		if (res_next->ai_protocol == IPPROTO_UDP) {
			res_next->ai_protocol = IPPROTO_QUIC;
			res_next->ai_socktype = SOCK_STREAM;
		}
	}

	return 0;
}


// XXX Fix this
int quic_poll_hook(struct frr_socket_entry *entry, struct pollfd *p_fd, int *poll_rv)
{
	struct quic_socket_entry *socket_entry = NULL;
	assert(entry->protocol == IPPROTO_QUIC);
	socket_entry = (struct quic_socket_entry *)entry;

	if (socket_entry->listener_backlog > 0) {
		/* Search for an established connection with a stream ready for accept */
		struct fd_fifo_entry *fd_entry = NULL;
		struct frr_socket_entry search_entry = {};

		frr_each_safe (fd_fifo, &socket_entry->unclaimed_fds, fd_entry) {
			struct quic_socket_entry *t_socket_entry = NULL;
			search_entry.fd = fd_entry->fd;

			frr_socket_table_find(&search_entry, t_entry);
			if (t_entry == NULL)
				continue;

			assert(t_entry->protocol == IPPROTO_QUIC);
			t_socket_entry = (struct quic_socket_entry *)t_entry;

			if (t_socket_entry->stream_id == -1)
				continue;

			/* At this point, we have found at least 1 ready socket for accept */
			if (p_fd->events & POLLIN && !(p_fd->revents & POLLIN)) {
				*poll_rv += p_fd->revents ? 0 : 1;
				p_fd->revents |= POLLIN;
			}
			return 0;
		}

		/* If we didn't find a ready socket, then clear the result */
		if (p_fd->events & POLLIN && p_fd->revents & POLLIN) {
			p_fd->revents &= ~POLLIN;
			*poll_rv -= p_fd->revents ? 0 : 1;
		}
	} else if (socket_entry->stream_id == -1) {
		/* Clear all POLLIN and POLLOUT events. Not I/O stream capable yet. */
		if (p_fd->events & POLLIN && p_fd->revents & POLLIN) {
			p_fd->revents &= ~POLLIN;
			*poll_rv -= p_fd->revents ? 0 : 1;
		}
		if (p_fd->events & POLLOUT && p_fd->revents & POLLOUT) {
			p_fd->revents &= ~POLLOUT;
			*poll_rv -= p_fd->revents ? 0 : 1;
		}
	}

	return 0;
}


// XXX Fix issue regarding event_cancel_async vs event_cancel
void quic_socket_lib_finish_hook(struct frr_socket_entry *entry)
{
	struct quic_socket_entry *socket_entry = NULL;
	if (entry == NULL)
		return;
	struct quic_conn_data *conn_data;
	assert(entry->protocol == IPPROTO_QUIC);
	socket_entry = (struct quic_socket_entry *)entry;
	conn_data = socket_entry->conn_data;

	socket_entry->is_user_closed = true;
	socket_entry->is_stream_fin = true;

	/* conn_data events; Since we don't have priority to aquire the conn_data lock, but we must
	 * aquire it, we release the frr_socket_entry lock that is implicitely held.
	 */
	pthread_mutex_unlock(&entry->lock);
	conn_data = socket_entry->conn_data;
	frr_mutex_lock_autounlock(&conn_data->lock);

	/* This is the last point at run-time where we are sure that the frr_socket_threadmaster is
	 * a valid reference. Since the connection can only be shutdown within the event loop, we
	 * must schedule the event and then wait until the event executes.
	 */
	conn_data->lib_shutdown = true;
	conn_data->wait_for_shutdown_event = true;
	if (!conn_data->t_socket_closed) {
		event_add_timer_msec(frr_socket_threadmaster, quic_close_event,
				     conn_data, 0, &conn_data->t_socket_closed);
	}

	/* Ugly hack. We need assurance that the quic_close_event has completed before we
	 * return control to frr_socket_lib_finish. Any open connections need to properly close.
	 */
	while(conn_data->wait_for_shutdown_event) {
		pthread_mutex_unlock(&conn_data->lock);
		usleep(1000);
		pthread_mutex_lock(&conn_data->lock);
	}

	pthread_mutex_lock(&entry->lock);
}


static void quic_destroy_conn(struct quic_conn_data *conn_data)
{
	struct fd_fifo_entry *fd_entry = NULL;

	zlog_info("QUIC: Destroying conn_data instance with UDP socket fd=%d", conn_data->fd);

	if (conn_data->conn) {
		ngtcp2_conn_del(conn_data->conn);
		conn_data->conn = NULL;
	}
	if (conn_data->ossl_ctx) {
		ngtcp2_crypto_ossl_ctx_del(conn_data->ossl_ctx);
		conn_data->ossl_ctx = NULL;
	}
	if (conn_data->ssl) {
		SSL_free(conn_data->ssl);
		conn_data->ssl = NULL;
	}
	if (conn_data->ssl_ctx) {
		SSL_CTX_free(conn_data->ssl_ctx);
		conn_data->ssl_ctx = NULL;
	}

	/* Since RCU shuts down after pthreads, we cannot be sure that the threadmaster reference is
	 * still any good. Thus, we avoid taking action and instead log a warnings if we find events
	 * that we don't expect to exist.
	 */
	if (conn_data->t_background_timeout != NULL) {
		zlog_warn("QUIC: conn_data with UDP fd=%d had event t_background_timeout scheduled at deletion",
			  conn_data->fd);
	}
	if (conn_data->t_background_process != NULL) {
		zlog_warn("QUIC: conn_data with UDP fd=%d had event t_background_process scheduled at deletion",
			  conn_data->fd);
	}
	if (conn_data->t_background_listen != NULL) {
		zlog_warn("QUIC: conn_data with UDP fd=%d had event t_background_listen scheduled at deletion",
			  conn_data->fd);
	}
	if (conn_data->t_socket_closed != NULL) {
		zlog_warn("QUIC: conn_data with UDP fd=%d had event t_socket_closed scheduled at deletion",
			  conn_data->fd);
	}
	if (conn_data->t_quic_delete != NULL) {
		zlog_warn("QUIC: conn_data with UDP fd=%d had event t_quic_delete scheduled at deletion",
			  conn_data->fd);
	}

	frr_each_safe (fd_fifo, &conn_data->stream_fds, fd_entry) {
		fd_fifo_del(&conn_data->stream_fds, fd_entry);
		XFREE(MTYPE_FRR_SOCKET, fd_entry);
	}
	fd_fifo_fini(&conn_data->stream_fds);

	// XXX Clean up stream buffers once implemented.

	close(conn_data->fd);
	conn_data->fd = -1;
	pthread_mutex_destroy(&conn_data->lock);
	XFREE(MTYPE_FRR_SOCKET, conn_data);
}


/* XXX This should not be called directly except by RCU_call in frr_socket_table_delete */
int quic_destroy_entry(struct frr_socket_entry *entry)
{
	int rv;
	struct quic_socket_entry *socket_entry = NULL;
	struct quic_conn_data *conn_data;
	assert(entry->protocol == IPPROTO_QUIC);
	socket_entry = (struct quic_socket_entry *)entry;
	conn_data = socket_entry->conn_data;

	zlog_info("QUIC: Destroying socket entry with fd=%d", entry->fd);

	rv = pthread_mutex_trylock(&conn_data->lock);
	if (rv != 0) {
		/* This lock was aquired. RCU determined should not be possible. Not good */
		zlog_err("QUIC: Destroying socket entry with fd=%d (conn fd %d). But failed to aquire lock.",
			 entry->fd, conn_data->fd);
		assert(0);
	} else if (conn_data->state != QUIC_CLOSED) {
		zlog_err("QUIC: Destroying socket entry fd=%d (conn fd %d). Found unexpected state: %s",
			 entry->fd, conn_data->fd, quic_strstate(conn_data->state));
		assert(0);
	}

	/* XXX When multiplexing is supported, only destroy conn on last refcount */
	quic_destroy_conn(conn_data);
	socket_entry->conn_data = NULL;

	// XXX Cleanup streams

	/* Clean up listener state if it exists */
	struct fd_fifo_entry *fd_entry;
	frr_each_safe (fd_fifo, &socket_entry->unclaimed_fds, fd_entry) {
		fd_fifo_del(&socket_entry->unclaimed_fds, fd_entry);
		XFREE(MTYPE_FRR_SOCKET, fd_entry);
	}
	fd_fifo_fini(&socket_entry->unclaimed_fds);

	close(entry->fd);
	entry->fd = -1;
	frr_socket_cleanup(entry);
	XFREE(MTYPE_FRR_SOCKET, entry);

	return 0;
}
