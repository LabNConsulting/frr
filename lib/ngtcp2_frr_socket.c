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

#include "frr_pthread.h"
#include "frr_socket.h"
#include "ngtcp2_frr_socket.h"

static const char *const quic_state_str[] = {
	"QUIC None",
	"QUIC Listening",
	"QUIC Connecting",
	"QUIC Stream Ready",
	"QUIC Stream Closing",
	"QUIC Connection Closing",
	"QUIC Closed",
};

/*
 * The following are internal utility functions required for ngtcp2
 * (This excludes events)
 */

static uint64_t timestamp(void) {
  struct timespec tp;

  //XXX Timestamp is pulled directly from ngtcp2 examples. Do we want to keep this?
  if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0) {
    fprintf(stderr, "clock_gettime: %s", safe_strerror(errno));
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


static const char *quic_strstate(int state) {
	if (state >= 0 && state < QUIC_STATE_MAX)
		return quic_state_str[state];
	return "";
}


static void quic_change_state(struct ngtcp2_socket_entry *ngtcp2_entry, enum quic_state state) {
	enum quic_state prev_state = ngtcp2_entry->state;
	ngtcp2_entry->state = state;
	zlog_debug("QUIC: entry with fd %d changes state (%s -> %s)", ngtcp2_entry->entry.fd,
		   quic_strstate(prev_state), quic_strstate(state));
}


static void cleanup_on_init_failure(struct ngtcp2_socket_entry* ngtcp2_entry)
{
	if (ngtcp2_entry->conn) {
		ngtcp2_conn_del(ngtcp2_entry->conn);
		ngtcp2_entry->conn = NULL;
	}
	if (ngtcp2_entry->ossl_ctx) {
		ngtcp2_crypto_ossl_ctx_del(ngtcp2_entry->ossl_ctx);
		ngtcp2_entry->ossl_ctx = NULL;
	}
	if (ngtcp2_entry->ssl) {
		SSL_free(ngtcp2_entry->ssl);
		ngtcp2_entry->ssl = NULL;
	}
	if (ngtcp2_entry->ssl_ctx) {
		SSL_CTX_free(ngtcp2_entry->ssl_ctx);
		ngtcp2_entry->ssl_ctx = NULL;
	}
}


static int quic_tls_init(struct ngtcp2_socket_entry *ngtcp2_entry) {
	// XXX Change the allowed ciphers or curves?
	uint64_t ssl_opts;
	const char *ciphers =
		"TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256";
	const char *curves = "X25519:P-256:P-384:P-521";

	ngtcp2_entry->ssl_ctx = SSL_CTX_new(TLS_client_method());
	if (!ngtcp2_entry->ssl_ctx) {
		zlog_warn("QUIC: SSL_CTX_new: %s", ERR_error_string(ERR_get_error(), NULL));
		goto failed;
	}

	if (ngtcp2_entry->role == QUIC_SERVER) {
		// XXX Not starting with early data. Can change later to UINT32_MAX
		SSL_CTX_set_max_early_data(ngtcp2_entry->ssl_ctx, 0);

		// XXX Revist this to confirm if some aren't necessary. Also, can this be moved out of loop?
		ssl_opts = (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) |
			   SSL_OP_CIPHER_SERVER_PREFERENCE;
		SSL_CTX_set_options(ngtcp2_entry->ssl_ctx, ssl_opts);
	}

	if (SSL_CTX_set_ciphersuites(ngtcp2_entry->ssl_ctx, ciphers) != 1) {
		zlog_warn("QUIC: SSL_CTX_set_ciphersuites: %s",
			  ERR_error_string(ERR_get_error(), NULL));
		goto failed;
	}

	if (SSL_CTX_set1_groups_list(ngtcp2_entry->ssl_ctx, curves) != 1) {
		zlog_warn("QUIC: SSL_CTX_set1_groups_list failed");
		goto failed;
	}

	SSL_CTX_set_mode(ngtcp2_entry->ssl_ctx, SSL_MODE_RELEASE_BUFFERS);

	//SSL_CTX_set_alpn_select_cb(s->ssl_ctx, alpn_select_proto_cb, NULL);

	SSL_CTX_set_default_verify_paths(ngtcp2_entry->ssl_ctx);
	/*
	const char *private_key_file = "./certs/priv.key";
	const char *cert_file = "./certs/cert.pem";
	const char *ca_file = "./certs/ca.pem";
	if (SSL_CTX_load_verify_file(s->ssl_ctx, ca_file) != 1) {
		fprintf(stderr, "SSL_CTX_load_verify_file: %s",
			ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}
	if (SSL_CTX_use_PrivateKey_file(s->ssl_ctx, private_key_file, SSL_FILETYPE_PEM) != 1) {
		fprintf(stderr, "SSL_CTX_use_PrivateKey_file: %s",
			ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}
	if (SSL_CTX_use_certificate_chain_file(s->ssl_ctx, cert_file) != 1) {
		fprintf(stderr, "SSL_CTX_use_certificate_chain_file: %s",
			ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}
	if (SSL_CTX_check_private_key(s->ssl_ctx) != 1) {
		fprintf(stderr, "SSL_CTX_check_private_key: %s",
			ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}
	*/

	/*
	if (ngtcp2_entry->role == NGTCP2_SERVER) {
		SSL_CTX_set_session_id_context(s->ssl_ctx, (unsigned char *)sid_ctx,
					       strlen(sid_ctx));

		//SSL_CTX_set_verify(s->ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb);

		//XXX: Don't hardcode the keylog file
		SSL_CTX_set_keylog_callback(s->ssl_ctx, keylog_cb);
	}
	*/

	ngtcp2_entry->ssl = SSL_new(ngtcp2_entry->ssl_ctx);
	if (ngtcp2_entry->ssl) {
		zlog_warn("QUIC: SSL_new: %s", ERR_error_string(ERR_get_error(), NULL));
		goto failed;
	}

	ngtcp2_crypto_ossl_ctx_new(&ngtcp2_entry->ossl_ctx, NULL);
	ngtcp2_crypto_ossl_ctx_set_ssl(ngtcp2_entry->ossl_ctx, ngtcp2_entry->ssl);

	if (ngtcp2_entry->role == QUIC_CLIENT) {
		if (ngtcp2_crypto_ossl_configure_client_session(ngtcp2_entry->ssl) != 0) {
			zlog_warn("QUIC: ngtcp2_crypto_ossl_configure_client_session failed");
			goto failed;
		}
	} else if (ngtcp2_entry->role == QUIC_SERVER) {
		if (ngtcp2_crypto_ossl_configure_server_session(ngtcp2_entry->ssl) != 0) {
			zlog_warn("QUIC: ngtcp2_crypto_ossl_configure_server_session failed");
			goto failed;
		}
	} else {
		zlog_err("QUIC: Illegal role (neither client or server role selected)");
		assert(0);
	}

	SSL_set_app_data(ngtcp2_entry->ssl, &ngtcp2_entry->conn_ref);
	SSL_set_connect_state(ngtcp2_entry->ssl);
	/* XXX Is any of the following actually needed?
	SSL_set_alpn_protos(ssl, (const unsigned char *)ALPN, sizeof(ALPN) - 1);
	if (!numeric_host(REMOTE_HOST)) {
		SSL_set_tlsext_host_name(c->ssl, REMOTE_HOST);
	}
	*/

	return 0;

failed:
	cleanup_on_init_failure(ngtcp2_entry);
	return -1;
}


static int quic_server_conn_init(struct ngtcp2_socket_entry *ngtcp2_entry,
				 const struct sockaddr *remote_addr, socklen_t remote_addrlen,
				 ngtcp2_cid *dcid, ngtcp2_cid *scid)
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
		NULL, /* client_initial */
		ngtcp2_crypto_recv_client_initial_cb,
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
		NULL, /* recv_retry */
		NULL, //extend_max_local_streams_bidi, //XXX Needed? Currently NULL
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

	ngtcp2_ccerr_default(&ngtcp2_entry->last_error);

	/* Create an OpenSSL TLS context for ngtcp2 */
	ngtcp2_entry->role = QUIC_SERVER;
	rv = quic_tls_init(ngtcp2_entry);
	if (rv != 0) {
		zlog_warn("QUIC: Failed to create TLS context");
		goto failure;
	}

	if (dcid == NULL || scid == NULL) {
		zlog_warn("QUIC: Source or Destination cid was not provided");
		goto failure;
	}

	ngtcp2_settings_default(&settings);
	settings.cc_algo = NGTCP2_CC_ALGO_BBR;
	settings.initial_ts = timestamp();
	//XXX Find a logging functino: settings.log_printf = log_printf;

	ngtcp2_entry->initial_params.original_dcid = *scid;
	ngtcp2_entry->initial_params.original_dcid_present = 1;

	rv = ngtcp2_conn_server_new(&ngtcp2_entry->conn, dcid, scid, &path, NGTCP2_PROTO_VER_V1,
				    &callbacks, &settings, &ngtcp2_entry->initial_params, NULL,
				    &ngtcp2_entry->entry.fd);
	if (rv != 0) {
		zlog_warn("QUIC: ngtcp2_conn_server_new: %s", ngtcp2_strerror(rv));
		goto failure;
	}

	ngtcp2_conn_set_tls_native_handle(ngtcp2_entry->conn, ngtcp2_entry->ossl_ctx);

	return 0;

failure:
	cleanup_on_init_failure(ngtcp2_entry);
	return -1;
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

	ngtcp2_ccerr_default(&ngtcp2_entry->last_error);

	/* Create an OpenSSL TLS context for ngtcp2 */
	ngtcp2_entry->role = QUIC_CLIENT;
	rv = quic_tls_init(ngtcp2_entry);
	if (rv != 0) {
		zlog_warn("QUIC: Failure to create TLS context");
		goto failure;
	}

	/* Source and destination Connection ID's start out randomized */
	dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
	scid.datalen = QUIC_SCIDLEN;
	if (RAND_bytes(dcid.data, (int)dcid.datalen) != 1
	    || RAND_bytes(scid.data, (int)scid.datalen) != 1) {
		zlog_warn("QUIC: Failure to call RAND_bytes");
		goto failure;
	}

	ngtcp2_settings_default(&settings);
	settings.cc_algo = NGTCP2_CC_ALGO_BBR;
	settings.initial_ts = timestamp();
	//XXX Find a logging functino: settings.log_printf = log_printf;

	rv = ngtcp2_conn_client_new(&ngtcp2_entry->conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1,
				    &callbacks, &settings, &ngtcp2_entry->initial_params, NULL,
				    &ngtcp2_entry->entry.fd);
	if (rv != 0) {
		zlog_warn("QUIC: ngtcp2_conn_client_new: %s", ngtcp2_strerror(rv));
		goto failure;
	}

	/* Finish integrating ngtcp2 with OpenSSL TLS context */
	ngtcp2_conn_set_tls_native_handle(ngtcp2_entry->conn, ngtcp2_entry->ossl_ctx);

	return 0;

failure:
	cleanup_on_init_failure(ngtcp2_entry);
	return -1;
}


static int quic_send_packet(struct ngtcp2_socket_entry *ngtcp2_entry, const uint8_t *data,
			    size_t datalen)
{
	struct iovec iov = { (uint8_t *)data, datalen };
	struct msghdr msg = { 0 };
	ssize_t nwrite;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	do {
		nwrite = sendmsg(ngtcp2_entry->entry.fd, &msg, 0);
	} while (nwrite == -1 && errno == EINTR);

	if (nwrite == -1) {
		zlog_warn("QUIC: sendmsg: %s", safe_strerror(errno));
		return -1;
	}

	return 0;
}


static void quic_close_conn(struct ngtcp2_socket_entry *ngtcp2_entry)
{
	ngtcp2_ssize nwrite;
	ngtcp2_pkt_info pi;
	ngtcp2_path_storage ps;
	uint8_t buf[1280];

	quic_change_state(ngtcp2_entry, QUIC_CLOSED);

	if (ngtcp2_conn_in_closing_period(ngtcp2_entry->conn) ||
	    ngtcp2_conn_in_draining_period(ngtcp2_entry->conn)) {
		return;
	}

	ngtcp2_path_storage_zero(&ps);

	nwrite = ngtcp2_conn_write_connection_close(ngtcp2_entry->conn, &ps.path, &pi, buf,
						    sizeof(buf), &ngtcp2_entry->last_error,
						    timestamp());
	if (nwrite < 0) {
		zlog_warn("QUIC: ngtcp2_conn_write_connection_close: %s",
			  ngtcp2_strerror((int)nwrite));
		return;
	}

	quic_send_packet(ngtcp2_entry, buf, (size_t)nwrite);
}


static int quic_write_to_endpoint(struct ngtcp2_socket_entry *ngtcp2_entry)
{
	ngtcp2_tstamp ts = timestamp();
	ngtcp2_pkt_info pi;
	ngtcp2_ssize nwrite;
	uint8_t buf[1452];
	ngtcp2_path_storage ps;
	ngtcp2_vec datav;
	size_t datavcnt;
	int64_t stream_id = -1;
	ngtcp2_ssize written_datalen;
	uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
	int fin;

	ngtcp2_path_storage_zero(&ps);

	// XXX Track what to do if a client is closing, closed

	if (ngtcp2_entry->state == QUIC_STREAM_READY)
		stream_id = ngtcp2_entry->stream_id;

	for (;;) {
		nwrite = ngtcp2_conn_writev_stream(ngtcp2_entry->conn, &ps.path, &pi, buf,
						   sizeof(buf), &written_datalen, flags, stream_id,
						   NULL, 0, ts);

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
				continue;
			case NGTCP2_ERR_STREAM_NOT_FOUND:
				/* How did we get this stream? Not fatal, but still concerning. */
				zlog_warn("QUIC: ngtcp2_conn_writev_stream found invalid stream: %lld",
					  stream_id);
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

		/* Nothing to do if the packet is empty */
		if (nwrite == 0)
			break;

		if (written_datalen > 0) {
			/* XXX Adjust data written from the buffer here!
			c->stream.nwrite += (size_t)wdatalen;
			*/
		}

		quic_send_packet(ngtcp2_entry, buf, (size_t)nwrite);
		break;
	}

	return 0;
}


static int quic_process_read_packet(struct ngtcp2_socket_entry *ngtcp2_entry, uint8_t *pkt,
				    size_t pktsize, struct msghdr *msg)
{
	ngtcp2_path path;
	ngtcp2_pkt_info pi = { 0 };
	ngtcp2_version_cid vc;
	int rv;

	rv = ngtcp2_pkt_decode_version_cid(&vc, pkt, pktsize, QUIC_SCIDLEN);
	if (rv != 0) {
		/* We currently don't take advantage of version negotiation */
		zlog_warn("QUIC: ngtcp2_pkt_decode_version_cid failed on packet");
		return 0;
	}

	path.local.addrlen = ngtcp2_entry->local_addrlen;
	path.local.addr = (struct sockaddr *)&ngtcp2_entry->local_addr;
	path.remote.addrlen = msg->msg_namelen;
	path.remote.addr = msg->msg_name;
	rv = ngtcp2_conn_read_pkt(ngtcp2_entry->conn, &path, &pi, pkt, pktsize, timestamp());


	// XXX Need to clean up this section
	if (rv != 0) {
		zlog_warn("QUIC: ngtcp2_conn_read_pkt: %s", ngtcp2_strerror(rv));
		if (!ngtcp2_entry->last_error.error_code) {
			if (rv == NGTCP2_ERR_CRYPTO) {
				ngtcp2_ccerr_set_tls_alert(&ngtcp2_entry->last_error,
							   ngtcp2_conn_get_tls_alert(
								   ngtcp2_entry->conn),
							   NULL, 0);
			} else {
				ngtcp2_ccerr_set_liberr(&ngtcp2_entry->last_error, rv, NULL, 0);
			}
		}
		return -1;
	}

	return 0;
}


static int quic_process_listener_packet(struct ngtcp2_socket_entry *ngtcp2_entry, uint8_t *pkt,
					size_t pktsize, struct msghdr *msg)
{
	struct ngtcp2_socket_entry *new_ngtcp2_entry = NULL;
	ngtcp2_path path;
	ngtcp2_pkt_info pi = { 0 };
	ngtcp2_version_cid vc;
	ngtcp2_pkt_hd hd;
	int rv, new_fd = 0;

	/* Check if the packet is a valid start of a new connection */
	rv = ngtcp2_accept(&hd, pkt, (size_t)pktsize);
	if (rv != 0) {
		zlog_warn("QUIC: ngtcp2_accept received invalid packet (discarded)");
		return 0;
	}

	/* Ignore the new connection if we are at capacity */
	if (fd_fifo_count(&ngtcp2_entry->unclaimed_fds) >= (size_t)ngtcp2_entry->listener_backlog) {
		zlog_warn("QUIC: cannot start a new connection due to backlog");
		return 0;
	}

	path.local.addrlen = ngtcp2_entry->local_addrlen;
	path.local.addr = (struct sockaddr *)&ngtcp2_entry->local_addr;
	path.remote.addrlen = msg->msg_namelen;
	path.remote.addr = msg->msg_name;

	/* Valid packet! Create a new connected socket ontop the unconnected listening socket */
	struct sockaddr *local_addr = (struct sockaddr *)&ngtcp2_entry->local_addr;
	socklen_t local_addrlen = ngtcp2_entry->local_addrlen;
	int domain;
	socklen_t domain_len = sizeof(domain);
	if (getsockopt(ngtcp2_entry->entry.fd, SOL_SOCKET, SO_DOMAIN, &domain, &domain_len) != 0) {
		zlog_warn("QUIC: listener getsockopt SO_DOMAIN: %s", safe_strerror(errno));
		goto failure;
	}
	if ((new_fd = quic_socket(domain, SOCK_DGRAM)) < 0) {
		zlog_warn("QUIC: listener socket: %s", safe_strerror(errno));
		goto failure;
	}

	struct frr_socket_entry search_entry = {
		.fd = new_fd,
	};
	/* Note that this locks the new_entry! No other thread should be aware of this entry's fd,
	 * and therefore never should try and find it. Therefore, no deadlock should happen despite
	 * the risk of aquiring two entry locks at once.
	 */
	frr_socket_table_find(&search_entry, new_entry);
	assert(new_entry && new_entry->protocol == IPPROTO_QUIC);
	new_ngtcp2_entry = (struct ngtcp2_socket_entry *)new_entry;

	if (quic_setsockopt(new_entry, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0) {
		zlog_warn("QUIC: listener setsockopt SO_REUSEADDR: %s", safe_strerror(errno));
		goto failure;
	}
	if (quic_bind(new_entry, local_addr, local_addrlen) != 0) {
		zlog_warn("QUIC: listener bind error: %s", safe_strerror(errno));
		goto failure;
	}

	if (connect(new_fd, path.remote.addr, path.remote.addrlen) < 0) {
		zlog_warn("QUIC: listener connect: %s", safe_strerror(errno));
		goto failure;
	}

	rv = quic_server_conn_init(new_ngtcp2_entry, path.remote.addr, path.remote.addrlen,
				   &hd.scid, &hd.dcid);
	if (!rv) {
		zlog_warn("QUIC: failed to create server connection context");
		goto failure;
	}

	quic_change_state(new_ngtcp2_entry, QUIC_CONNECTING);

	/* Finally, read the packet that started this new connection. */
	if (quic_process_read_packet(new_ngtcp2_entry, pkt, pktsize, msg) == -1) {
		zlog_warn(
			"QUIC: newly created server connection context is being immediately destroyed");
		goto failure;
	}

	/* We have to manually track this fd until it is handed out to the user */
	struct fd_fifo *fd_fifo_entry = XMALLOC(MTYPE_FRR_SOCKET, sizeof(*fd_fifo_entry));
	if (fd_fifo_entry) {
		errno = ENOMEM;
		zlog_warn("QUIC: Internal memory allocation failed");
		goto failure;
	}
	memset(fd_fifo_entry, 0x00, sizeof(*fd_fifo_entry));
	fd_fifo_entry->fd = new_entry->fd;
	fd_fifo_add_tail(&ngtcp2_entry->unclaimed_fds, fd_fifo_entry);

	return 0;

failure:
	/* quic_close() will free appropriate state */
	if (new_ngtcp2_entry != NULL) {
		quic_close((struct frr_socket_entry *)new_ngtcp2_entry);
	}

	return -1;
}


static int quic_read_from_endpoint(struct ngtcp2_socket_entry *ngtcp2_entry)
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

	/* Repeatedly read until there is nothing left */
	for (;;) {
		//XXX Deal with closing here?

		msg.msg_namelen = sizeof(addr);
		nread = recvmsg(ngtcp2_entry->entry.fd, &msg, MSG_DONTWAIT);

		if (nread == -1) {
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				zlog_warn("QUIC: recvmsg: %s", safe_strerror(errno));
				return -1;
			}
			break;
		}

		if (ngtcp2_entry->state == QUIC_LISTENING) {
			rv = quic_process_listener_packet(ngtcp2_entry, buf, (size_t)nread, &msg);
		} else {
			rv = quic_process_read_packet(ngtcp2_entry, buf, (size_t)nread, &msg);
		}

		if (rv == -1) {
			return -1;
		}
	}

	return 0;
}

/*
 * The following are events that may be scheduled
 */


static void quic_background_process(struct event *thread)
{
	int *fd_ref = EVENT_ARG(thread);
	int fd = *fd_ref;
	struct frr_socket_entry search_entry = {
		.fd = fd,
	};
	struct ngtcp2_socket_entry *ngtcp2_entry = NULL;

	frr_socket_table_find(&search_entry, found_entry);
	assert(found_entry && found_entry->protocol == IPPROTO_QUIC);
	ngtcp2_entry = (struct ngtcp2_socket_entry *)found_entry;

	// XXX Don't like the entire bit being locked
	ngtcp2_entry->t_background_process = NULL;

	if (quic_read_from_endpoint(ngtcp2_entry) < 0) {
		//XXX what to do? Immediately close connection?
	}

	if (quic_write_to_endpoint(ngtcp2_entry) < 0) {
		//XXX what to do? Immediately close connection?
	}

	/* pollin/pollout events should not be scheduled if the socket is read/writable
		 * from a user standpoint! We do not want to overwrite their events.
		 */
	// XXX Is this where a socket deletion event should be scheduled?
	if (ngtcp2_entry->state == QUIC_CLOSED) {
		// XXX Schedule the socket deletion event
	} else if (ngtcp2_entry->state != QUIC_STREAM_READY) {
		event_add_read(frr_socket_threadmaster, quic_background_process, fd_ref, fd,
			       &ngtcp2_entry->t_background_process);
	}
}


static void quic_background_listen(struct event *thread)
{
	int *fd_ref = EVENT_ARG(thread);
	int fd = *fd_ref;
	struct frr_socket_entry search_entry = {
		.fd = fd,
	};
	struct ngtcp2_socket_entry *ngtcp2_entry = NULL;

	frr_socket_table_find(&search_entry, found_entry);
	assert(found_entry && found_entry->protocol == IPPROTO_QUIC);
	ngtcp2_entry = (struct ngtcp2_socket_entry *)found_entry;

	ngtcp2_entry->t_background_listen = NULL;

	if (quic_read_from_endpoint(ngtcp2_entry) < 0) {
		//XXX what to do? Immediately close connection?
	}

	event_add_read(frr_socket_threadmaster, quic_background_listen, fd_ref, fd,
		       &ngtcp2_entry->t_background_listen);
}


/*
 * The following provide the wrappers called by the frr_socket core library
 */
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

	ngtcp2_entry->state = QUIC_NONE;
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


int quic_bind(struct frr_socket_entry *entry, const struct sockaddr *addr, socklen_t addrlen)
{
	assert(entry->protocol == IPPROTO_QUIC);
	return bind(entry->fd, addr, addrlen);
}


int quic_connect(struct frr_socket_entry *entry, const struct sockaddr *addr, socklen_t addrlen)
{
	int rv;
	struct ngtcp2_socket_entry *ngtcp2_entry = (struct ngtcp2_socket_entry *)entry;

	assert(entry->protocol == IPPROTO_QUIC);

	if (ngtcp2_entry->state == QUIC_STREAM_READY) {
		errno = EISCONN;
		return -1;
	} else if (ngtcp2_entry->state != QUIC_NONE) {
		//XXX is EINVAL a deviation from spec?
		errno = EINVAL;
		return -1;
	}

	rv = connect(entry->fd, addr, addrlen);
	if (rv != 0) {
		/* errno is kept */
		return -1;
	}

	rv = quic_client_conn_init(ngtcp2_entry, addr, addrlen);
	if (!rv) {
		/* XXX Disconnect the socket? And is this the right error? */
		errno = EINVAL;
		return -1;
	}

	quic_change_state(ngtcp2_entry, QUIC_CONNECTING);
	event_add_read(frr_socket_threadmaster, quic_background_process, &entry->fd, entry->fd,
		       &ngtcp2_entry->t_background_process);
	// XXX Add a probe event similar to the background process

	/* We always will "fail" with EINPROGRESS in order to allow for background events to be
	 * completed. This includes perfoming the handshake and automatically creating a stream.
	 */
	errno = EINPROGRESS;
	return -1;
}


int quic_listen(struct frr_socket_entry *entry, int backlog)
{
	assert(entry && entry->protocol == IPPROTO_QUIC);
	struct ngtcp2_socket_entry *ngtcp2_entry = (struct ngtcp2_socket_entry *)entry;

	if (ngtcp2_entry->state != QUIC_NONE) {
		// XXX What is correct error code?
		errno = EOPNOTSUPP;
		return -1;
	}

	ngtcp2_entry->listener_backlog = backlog;
	quic_change_state(ngtcp2_entry, QUIC_LISTENING);
	event_add_read(frr_socket_threadmaster, quic_background_listen, &entry->fd, entry->fd,
		       &ngtcp2_entry->t_background_process);

	return 0;
}


int quic_accept(struct frr_socket_entry *entry, struct sockaddr *addr, socklen_t *addrlen)
{
	int fd;
	struct fd_fifo *fd_entry;
	struct frr_socket_entry search_entry = {};
	struct ngtcp2_socket_entry *ngtcp2_entry = NULL;
	assert(entry->protocol == IPPROTO_QUIC);
	ngtcp2_entry = (struct ngtcp2_socket_entry *)entry;

	if (ngtcp2_entry->state != QUIC_LISTENING) {
		errno = EINVAL;
		return -1;
	}

	frr_each_safe (fd_fifo, &ngtcp2_entry->unclaimed_fds, fd_entry) {
		struct ngtcp2_socket_entry *t_ngtcp2_entry = NULL;
		search_entry.fd = fd_entry->fd;

		/* This locks the returned entry for the local scope. However, since the returned
		 * entry should never be try to aquire the listener entry, deadlock should not be
		 * possible. */
		frr_socket_table_find(&search_entry, t_entry);

		/* Connection failed, and has already been deleted */
		// XXX How to deal with the kernel re-using fd's? Could that cause a bug?
		if (t_entry == NULL) {
			fd_fifo_del(&ngtcp2_entry->unclaimed_fds, fd_entry);
			XFREE(MTYPE_FRR_SOCKET, fd_entry);
			continue;
		}

		assert(t_entry->protocol == IPPROTO_QUIC);
		t_ngtcp2_entry = (struct ngtcp2_socket_entry *)t_entry;

		if (t_ngtcp2_entry->state == QUIC_CONNECTING) {
			continue;
		} else if (t_ngtcp2_entry->state != QUIC_STREAM_READY) {
			/* Remove entries in a state we don't expect */
			zlog_warn("QUIC: Listener on socket %d was tracking entry with unexpected state: %s",
				  fd_entry->fd, quic_strstate(t_ngtcp2_entry->state));
			fd_fifo_del(&ngtcp2_entry->unclaimed_fds, fd_entry);
			XFREE(MTYPE_FRR_SOCKET, fd_entry);
			continue;
		}

		/* State must be QUIC_STREAM_READY. We are good to hand off the socket */
		//XXX Cancel all POLLIN-POLLOUT events if they are still going instead of assert
		assert(ngtcp2_entry->t_background_process == NULL);

		fd_fifo_del(&ngtcp2_entry->unclaimed_fds, fd_entry);
		XFREE(MTYPE_FRR_SOCKET, fd_entry);

		return t_entry->fd;
	}

	errno = EWOULDBLOCK;
	return -1;
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
