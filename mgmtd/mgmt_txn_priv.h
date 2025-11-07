// SPDX-License-Identifier: GPL-2.0-or-later
/*
  * November 7 2025, Christian Hopps <chopps@labn.net>
  *
  * Copyright (c) 2025, LabN Consulting, L.L.C.
  *
  */
#ifndef _FRR_MGMTD_TXN_PRIV_H_
#define _FRR_MGMTD_TXN_PRIV_H_

#include "lib/mgmt_msg_native.h"
#include "mgmtd/mgmt_be_adapter.h"
#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_ds.h"

#define _dbg(fmt, ...)	   DEBUGD(&mgmt_debug_txn, "TXN: %s: " fmt, __func__, ##__VA_ARGS__)
#define _log_warn(fmt, ...) zlog_warn("%s: ERROR: " fmt, __func__, ##__VA_ARGS__)
#define _log_err(fmt, ...) zlog_err("%s: ERROR: " fmt, __func__, ##__VA_ARGS__)

enum mgmt_txn_req_type {
	MGMTD_TXN_PROC_COMMITCFG = 1,
	MGMTD_TXN_PROC_GETTREE,
	MGMTD_TXN_PROC_RPC,
};

enum mgmt_commit_phase {
	MGMTD_COMMIT_PHASE_SEND_CFG = 0,
	MGMTD_COMMIT_PHASE_APPLY_CFG,
	MGMTD_COMMIT_PHASE_FINISH,
};

struct mgmt_commit_cfg_req {
	enum mgmt_ds_id src_ds_id;
	struct mgmt_ds_ctx *src_ds_ctx;
	enum mgmt_ds_id dst_ds_id;
	struct mgmt_ds_ctx *dst_ds_ctx;
	uint32_t nb_txn_id;
	uint8_t validate_only : 1;
	uint8_t abort : 1;
	uint8_t implicit : 1;
	uint8_t rollback : 1;
	uint8_t init : 1;
	uint8_t unlock : 1;

	/* Track commit phases */
	enum mgmt_commit_phase phase;

	/*
	 * Additional information when the commit is triggered by native edit
	 * request.
	 */
	struct mgmt_edit_req *edit;


	/* Used for holding changes mgmtd itself is interested in */
	struct nb_transaction *mgmtd_nb_txn;

	/*
	 * Details on all the Backend Clients associated with
	 * this commit.
	 */
	uint64_t clients;	   /* interested clients */
	uint64_t clients_wait;	   /* set when cfg_req sent */

	struct mgmt_commit_stats *cmt_stats;
};

struct txn_req_get_tree {
	char *xpath;	       /* xpath of tree to get */
	uint64_t sent_clients; /* Bitmask of clients sent req to */
	uint64_t recv_clients; /* Bitmask of clients recv reply from */
	int32_t partial_error; /* an error while gather results */
	uint8_t result_type;   /* LYD_FORMAT for results */
	uint8_t wd_options;    /* LYD_PRINT_WD_* flags for results */
	uint8_t exact;	       /* if exact node is requested */
	uint8_t simple_xpath;  /* if xpath is simple */
	struct lyd_node *client_results; /* result tree from clients */
};

struct txn_req_rpc {
	char *xpath;	       /* xpath of rpc/action to invoke */
	uint64_t sent_clients; /* Bitmask of clients sent req to */
	uint64_t recv_clients; /* Bitmask of clients recv reply from */
	uint8_t result_type;   /* LYD_FORMAT for results */
	char *errstr;	       /* error string */
	struct lyd_node *client_results; /* result tree from clients */
};

PREDECL_LIST(mgmt_txn_reqs);

struct mgmt_txn_req {
	struct mgmt_txn_ctx *txn;
	enum mgmt_txn_req_type req_type;
	uint64_t req_id;
	union {
		/*
		 * XXX Make the sub-structure variants either allocated or
		 * embedded -- not both; embedding only the commit_cfg variant
		 * makes little sense since it is the largest of the variants
		 * though!
		 */
		struct txn_req_get_tree *get_tree;
		struct txn_req_rpc *rpc;
		struct mgmt_commit_cfg_req commit_cfg;
	} req;

	/* So far used by commit_cfg to expand to others */
	enum mgmt_result error; /* MGMTD return code */
	char *err_info;		/* darr str */

	struct mgmt_txn_reqs_item list_linkage;
};

DECLARE_LIST(mgmt_txn_reqs, struct mgmt_txn_req, list_linkage);

#define FOREACH_TXN_REQ_IN_LIST(list, req)                                     \
	frr_each_safe (mgmt_txn_reqs, list, req)

struct mgmt_txn_ctx {
	uint64_t session_id; /* One transaction per client session */
	uint64_t txn_id;
	enum mgmt_txn_type type;

	struct event *proc_comm_cfg;
	struct event *proc_get_tree;
	struct event *comm_cfg_timeout;
	struct event *get_tree_timeout;
	struct event *rpc_timeout;
	struct event *clnup;

	int refcount;

	struct mgmt_txns_item list_linkage;

	/*
	 * List of pending requests.
	 */
	struct mgmt_txn_reqs_head reqs;

	/*
	 * There will always be one commit-config allowed for a given
	 * transaction/session. Keep a pointer to it for quick access.
	 */
	struct mgmt_txn_req *commit_cfg_req;
};

DECLARE_LIST(mgmt_txns, struct mgmt_txn_ctx, list_linkage);


/* Config TXN */
extern void mgmt_txn_cfg_cleanup(struct mgmt_txn_req *txn_req);
extern int mgmt_txn_cfg_client_connect(struct mgmt_be_client_adapter *adapter);
extern void mgmt_txn_cfg_client_disconnect(struct mgmt_be_client_adapter *adapter,
					   struct mgmt_txn_ctx *txn);
extern void mgmt_txn_cfg_handle_error(struct mgmt_be_client_adapter *adapter, uint64_t txn_id,
				      uint64_t req_id, int error, const char *errstr);

/* General TXN */
extern void mgmt_txn_cleanup_txn(struct mgmt_txn_ctx **txn);
extern struct mgmt_txn_ctx *mgmt_txn_create_new(uint64_t session_id, enum mgmt_txn_type type);

extern struct mgmt_txn_req *mgmt_txn_req_alloc(struct mgmt_txn_ctx *txn, uint64_t req_id,
					       enum mgmt_txn_req_type req_type);
extern void mgmt_txn_req_free(struct mgmt_txn_req **txn_req);
extern struct mgmt_txn_ctx *txn_lookup(uint64_t txn_id);


extern struct event_loop *mgmt_txn_tm;

#endif /* _FRR_MGMTD_TXN_PRIV_H_ */
