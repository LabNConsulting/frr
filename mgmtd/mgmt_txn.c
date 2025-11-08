// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MGMTD Transactions
 *
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 * Copyright (c) 2025, LabN Consulting, L.L.C.
 */

#include <zebra.h>
#include "darr.h"
#include "hash.h"
#include "jhash.h"
#include "libfrr.h"
#include "mgmt_msg.h"
#include "mgmt_msg_native.h"
#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_memory.h"
#include "mgmtd/mgmt_txn.h"
#include "mgmtd/mgmt_txn_priv.h"
#include "mgmtd/mgmt_be_adapter.h"

#define MGMTD_TXN_INCREF(txn)		    txn_incref(txn, __FILE__, __LINE__)
#define MGMTD_TXN_DECREF(txn, in_hash_free) txn_decref(txn, in_hash_free, __FILE__, __LINE__)

#define FOREACH_TXN_IN_LIST(mm, txn) frr_each_safe (mgmt_txns, &(mm)->txn_list, (txn))

static void txn_incref(struct mgmt_txn_ctx *txn, const char *file, int line);
static void txn_decref(struct mgmt_txn_ctx **txn, bool in_hash_free, const char *file, int line);

static struct mgmt_master *mgmt_txn_mm;

struct event_loop *mgmt_txn_tm;

/*
 * Create a transaction request (work) under a transaction.
 */
struct mgmt_txn_req *mgmt_txn_req_alloc(struct mgmt_txn_ctx *txn, uint64_t req_id,
					enum mgmt_txn_req_type req_type)
{
	struct mgmt_txn_req *txn_req;

	txn_req = XCALLOC(MTYPE_MGMTD_TXN_REQ, sizeof(struct mgmt_txn_req));
	assert(txn_req);
	txn_req->txn = txn;
	txn_req->req_id = req_id;
	txn_req->req_type = req_type;

	switch (txn_req->req_type) {
	case MGMTD_TXN_PROC_COMMITCFG:
		/*
		 * XXX Not allocated, makes no sense to have some allocated and
		 * some not, and this embedded one is the largest of the lot
		 */

		txn->commit_cfg_req = txn_req;
		_dbg("Added a new COMMITCFG req-id: %" PRIu64 " txn-id: %" PRIu64
		     " session-id: %" PRIu64,
		     txn_req->req_id, txn->txn_id, txn->session_id);

		break;
	case MGMTD_TXN_PROC_GETTREE:
		txn_req->req.get_tree = XCALLOC(MTYPE_MGMTD_TXN_GETTREE_REQ,
						sizeof(struct txn_req_get_tree));

		_dbg("Added a new GETTREE req-id: %" PRIu64 " txn-id: %" PRIu64
		     " session-id: %" PRIu64,
		     txn_req->req_id, txn->txn_id, txn->session_id);
		break;
	case MGMTD_TXN_PROC_RPC:
		txn_req->req.rpc = XCALLOC(MTYPE_MGMTD_TXN_RPC_REQ, sizeof(struct txn_req_rpc));

		_dbg("Added a new RPC req-id: %" PRIu64 " txn-id: %" PRIu64 " session-id: %" PRIu64,
		     txn_req->req_id, txn->txn_id, txn->session_id);
		break;
	}

	mgmt_txn_reqs_add_tail(&txn->reqs, txn_req);

	MGMTD_TXN_INCREF(txn);

	return txn_req;
}

/*
 * Free a transaction request from under a transaction
 */
void mgmt_txn_req_free(struct mgmt_txn_req **txn_req)
{
	struct mgmt_txn_ctx *txn = (*txn_req)->txn;
	struct mgmt_txn_req *safe_req = NULL;
	uint64_t txn_id = txn->txn_id;

	switch ((*txn_req)->req_type) {
	case MGMTD_TXN_PROC_COMMITCFG:
		/* prevent recursion */
		safe_req = *txn_req;
		*txn_req = NULL;
		txn_req = &safe_req;
		mgmt_txn_cfg_cleanup(*txn_req);
		/* NOTE: config request state is not allocated separately */
		break;
	case MGMTD_TXN_PROC_GETTREE:
		_dbg("Deleting GETTREE req-id: %" PRIu64 " of txn-id: %" PRIu64,
		     (*txn_req)->req_id, txn_id);
		lyd_free_all((*txn_req)->req.get_tree->client_results);
		XFREE(MTYPE_MGMTD_XPATH, (*txn_req)->req.get_tree->xpath);
		XFREE(MTYPE_MGMTD_TXN_GETTREE_REQ, (*txn_req)->req.get_tree);
		break;
	case MGMTD_TXN_PROC_RPC:
		_dbg("Deleting RPC req-id: %" PRIu64 " txn-id: %" PRIu64, (*txn_req)->req_id,
		     txn_id);
		lyd_free_all((*txn_req)->req.rpc->client_results);
		XFREE(MTYPE_MGMTD_ERR, (*txn_req)->req.rpc->errstr);
		XFREE(MTYPE_MGMTD_XPATH, (*txn_req)->req.rpc->xpath);
		XFREE(MTYPE_MGMTD_TXN_RPC_REQ, (*txn_req)->req.rpc);
		break;
	}

	mgmt_txn_reqs_del(&txn->reqs, *txn_req);
	_dbg("Removed req-id: %Lu from request-list (left:%zu)", (*txn_req)->req_id,
	     mgmt_txn_reqs_count(&txn->reqs));

	darr_free((*txn_req)->err_info);
	MGMTD_TXN_DECREF(&(*txn_req)->txn, false);
	XFREE(MTYPE_MGMTD_TXN_REQ, (*txn_req));
	*txn_req = NULL;
}

static struct mgmt_txn_ctx *txn_lookup_by_session_id(struct mgmt_master *cm, uint64_t session_id,
						     enum mgmt_txn_type type)
{
	struct mgmt_txn_ctx *txn;

	FOREACH_TXN_IN_LIST (cm, txn) {
		if (txn->session_id == session_id && txn->type == type)
			return txn;
	}

	return NULL;
}

struct mgmt_txn_ctx *mgmt_txn_create_new(uint64_t session_id, enum mgmt_txn_type type)
{
	struct mgmt_txn_ctx *txn = NULL;

	/* Do not allow multiple config transactions */
	if (type == MGMTD_TXN_TYPE_CONFIG && mgmt_config_txn_in_progress())
		return NULL;

	txn = txn_lookup_by_session_id(mgmt_txn_mm, session_id, type);
	if (!txn) {
		txn = XCALLOC(MTYPE_MGMTD_TXN, sizeof(struct mgmt_txn_ctx));
		assert(txn);

		txn->session_id = session_id;
		txn->type = type;
		mgmt_txns_add_tail(&mgmt_txn_mm->txn_list, txn);
		/* TODO: why do we need N lists for one transaction */
		mgmt_txn_reqs_init(&txn->reqs);
		txn->commit_cfg_req = NULL;
		txn->refcount = 0;
		if (!mgmt_txn_mm->next_txn_id)
			mgmt_txn_mm->next_txn_id++;
		txn->txn_id = mgmt_txn_mm->next_txn_id++;
		hash_get(mgmt_txn_mm->txn_hash, txn, hash_alloc_intern);

		_dbg("Added new '%s' txn-id: %" PRIu64, mgmt_txn_type2str(type), txn->txn_id);

		if (type == MGMTD_TXN_TYPE_CONFIG)
			mgmt_txn_mm->cfg_txn = txn;

		MGMTD_TXN_INCREF(txn);
	}

	return txn;
}

static void mgmt_txn_delete(struct mgmt_txn_ctx **txn, bool in_hash_free)
{
	MGMTD_TXN_DECREF(txn, in_hash_free);
}

static unsigned int txn_hash_key(const void *data)
{
	const struct mgmt_txn_ctx *txn = data;

	return jhash2((uint32_t *)&txn->txn_id,
		      sizeof(txn->txn_id) / sizeof(uint32_t), 0);
}

static bool txn_hash_cmp(const void *d1, const void *d2)
{
	const struct mgmt_txn_ctx *txn1 = d1;
	const struct mgmt_txn_ctx *txn2 = d2;

	return (txn1->txn_id == txn2->txn_id);
}

static void txn_hash_free(void *data)
{
	struct mgmt_txn_ctx *txn = data;

	mgmt_txn_delete(&txn, true);
}

static void txn_hash_init(void)
{
	if (!mgmt_txn_mm || mgmt_txn_mm->txn_hash)
		return;

	mgmt_txn_mm->txn_hash = hash_create(txn_hash_key, txn_hash_cmp, "MGMT Transactions");
}

static void txn_hash_destroy(void)
{
	if (!mgmt_txn_mm || !mgmt_txn_mm->txn_hash)
		return;

	hash_clean(mgmt_txn_mm->txn_hash, txn_hash_free);
	hash_free(mgmt_txn_mm->txn_hash);
	mgmt_txn_mm->txn_hash = NULL;
}

struct mgmt_txn_ctx *txn_lookup(uint64_t txn_id)
{
	struct mgmt_txn_ctx key = { 0 };
	struct mgmt_txn_ctx *txn;

	if (!mgmt_txn_mm || !mgmt_txn_mm->txn_hash)
		return NULL;

	key.txn_id = txn_id;
	txn = hash_lookup(mgmt_txn_mm->txn_hash, &key);

	return txn;
}

uint64_t mgmt_txn_get_session_id(uint64_t txn_id)
{
	struct mgmt_txn_ctx *txn = txn_lookup(txn_id);

	return txn ? txn->session_id : MGMTD_SESSION_ID_NONE;
}

static void txn_incref(struct mgmt_txn_ctx *txn, const char *file, int line)
{
	txn->refcount++;
	_dbg("%s:%d --> INCREF %s txn-id: %" PRIu64 " refcnt: %d", file, line,
	     mgmt_txn_type2str(txn->type), txn->txn_id, txn->refcount);
}

static void txn_decref(struct mgmt_txn_ctx **txn, bool in_hash_free, const char *file, int line)
{
	assert(*txn && (*txn)->refcount);

	(*txn)->refcount--;
	_dbg("%s:%d --> DECREF %s txn-id: %" PRIu64 " refcnt: %d", file, line,
	     mgmt_txn_type2str((*txn)->type), (*txn)->txn_id, (*txn)->refcount);
	if (!(*txn)->refcount) {
		if ((*txn)->type == MGMTD_TXN_TYPE_CONFIG)
			if (mgmt_txn_mm->cfg_txn == *txn)
				mgmt_txn_mm->cfg_txn = NULL;
		event_cancel(&(*txn)->proc_comm_cfg);
		event_cancel(&(*txn)->comm_cfg_timeout);
		event_cancel(&(*txn)->get_tree_timeout);
		if (!in_hash_free)
			hash_release(mgmt_txn_mm->txn_hash, *txn);

		mgmt_txns_del(&mgmt_txn_mm->txn_list, *txn);

		_dbg("Deleted %s txn-id: %" PRIu64 " session-id: %" PRIu64,
		     mgmt_txn_type2str((*txn)->type), (*txn)->txn_id, (*txn)->session_id);

		XFREE(MTYPE_MGMTD_TXN, *txn);
	}

	*txn = NULL;
}

void mgmt_txn_cleanup_txn(struct mgmt_txn_ctx **txn)
{
	/* TODO: Any other cleanup applicable */

	mgmt_txn_delete(txn, false);
}

static void txn_cleanup_all_txns(void)
{
	struct mgmt_txn_ctx *txn;

	if (!mgmt_txn_mm || !mgmt_txn_mm->txn_hash)
		return;

	FOREACH_TXN_IN_LIST (mgmt_txn_mm, txn)
		mgmt_txn_cleanup_txn(&txn);
}

int mgmt_txn_init(struct mgmt_master *m, struct event_loop *loop)
{
	if (mgmt_txn_mm || mgmt_txn_tm)
		assert(!"MGMTD TXN: Call txn_init() only once");

	mgmt_txn_mm = m;
	mgmt_txn_tm = loop;
	mgmt_txns_init(&m->txn_list);
	txn_hash_init();
	assert(!m->cfg_txn);
	m->cfg_txn = NULL;

	return 0;
}

void mgmt_txn_destroy(void)
{
	txn_cleanup_all_txns();
	txn_hash_destroy();
}

bool mgmt_config_txn_in_progress(void)
{
	if (mgmt_txn_mm && mgmt_txn_mm->cfg_txn)
		return true;

	return false;
}

uint64_t mgmt_create_txn(uint64_t session_id, enum mgmt_txn_type type)
{
	struct mgmt_txn_ctx *txn;

	txn = mgmt_txn_create_new(session_id, type);
	return txn ? txn->txn_id : MGMTD_TXN_ID_NONE;
}

void mgmt_destroy_txn(uint64_t *txn_id)
{
	struct mgmt_txn_ctx *txn;

	txn = txn_lookup(*txn_id);
	if (!txn)
		return;

	mgmt_txn_delete(&txn, false);
	*txn_id = MGMTD_TXN_ID_NONE;
}

int mgmt_txn_notify_be_adapter_conn(struct mgmt_be_client_adapter *adapter,
				    bool connect)
{
	struct mgmt_txn_ctx *txn;

	if (connect)
		return mgmt_txn_cfg_client_connect(adapter);
	else {
		/*
		 * Check if any transaction is currently on-going that
		 * involves this backend client. If so check if we can now
		 * advance that configuration.
		 */
		FOREACH_TXN_IN_LIST (mgmt_txn_mm, txn) {
			/* XXX update to handle get-tree and RPC too! */
			if (txn->type == MGMTD_TXN_TYPE_CONFIG)
				mgmt_txn_cfg_client_disconnect(adapter, txn);
		}
	}

	return 0;
}

/* =========================== */
/* GET TREE (data) BACKEND TXN */
/* =========================== */

static int txn_get_tree_data_done(struct mgmt_txn_ctx *txn, struct mgmt_txn_req *txn_req)
{
	struct txn_req_get_tree *get_tree = txn_req->req.get_tree;
	uint64_t req_id = txn_req->req_id;
	struct lyd_node *result;
	int ret = NB_OK;

	/* cancel timer and send reply onward */
	event_cancel(&txn->get_tree_timeout);

	if (!get_tree->simple_xpath && get_tree->client_results) {
		/*
		 * We have a complex query so Filter results by the xpath query.
		 */
		if (yang_lyd_trim_xpath(&get_tree->client_results, txn_req->req.get_tree->xpath))
			ret = NB_ERR;
	}

	result = get_tree->client_results;

	if (ret == NB_OK && result && get_tree->exact)
		result = yang_dnode_get(result, get_tree->xpath);

	if (ret == NB_OK)
		ret = mgmt_fe_adapter_send_tree_data(txn->session_id, txn->txn_id, txn_req->req_id,
						     get_tree->result_type, get_tree->wd_options,
						     result, get_tree->partial_error, false);

	/* we're done with the request */
	mgmt_txn_req_free(&txn_req);

	if (ret) {
		_log_err("Error sending the results of GETTREE for txn-id %" PRIu64
			 " req_id %" PRIu64 " to requested type %u",
			 txn->txn_id, req_id, get_tree->result_type);

		(void)mgmt_fe_adapter_txn_error(txn->txn_id, req_id, false,
						errno_from_nb_error(ret),
						"Error converting results of GETTREE");
	}

	return ret;
}

/*
 * Get-tree data from the backend client.
 */
int mgmt_txn_handle_tree_data_reply(struct mgmt_be_client_adapter *adapter,
				    struct mgmt_msg_tree_data *data_msg, size_t msg_len)
{
	uint64_t txn_id = data_msg->refer_id;
	uint64_t req_id = data_msg->req_id;

	enum mgmt_be_client_id id = adapter->id;
	struct mgmt_txn_ctx *txn = txn_lookup(txn_id);
	struct mgmt_txn_req *txn_req;
	struct txn_req_get_tree *get_tree;
	struct lyd_node *tree = NULL;
	LY_ERR err;

	if (!txn) {
		_log_err("GETTREE reply from %s for a missing txn-id %" PRIu64, adapter->name,
			 txn_id);
		return -1;
	}

	/* Find the request. */
	FOREACH_TXN_REQ_IN_LIST (&txn->reqs, txn_req)
		if (txn_req->req_id == req_id)
			break;
	if (!txn_req) {
		_log_err("GETTREE reply from %s for txn-id %" PRIu64 " missing req_id %" PRIu64,
			 adapter->name, txn_id, req_id);
		return -1;
	}

	get_tree = txn_req->req.get_tree;

	/* store the result */
	err = lyd_parse_data_mem(ly_native_ctx, (const char *)data_msg->result,
				 data_msg->result_type, LYD_PARSE_STRICT | LYD_PARSE_ONLY,
				 0 /*LYD_VALIDATE_OPERATIONAL*/, &tree);
	if (err) {
		_log_err("GETTREE reply from %s for txn-id %" PRIu64 " req_id %" PRIu64
			 " error parsing result of type %u",
			 adapter->name, txn_id, req_id, data_msg->result_type);
	}
	if (!err) {
		/* TODO: we could merge ly_errs here if it's not binary */

		if (!get_tree->client_results)
			get_tree->client_results = tree;
		else
			err = lyd_merge_siblings(&get_tree->client_results, tree,
						 LYD_MERGE_DESTRUCT);
		if (err) {
			_log_err("GETTREE reply from %s for txn-id %" PRIu64 " req_id %" PRIu64
				 " error merging result",
				 adapter->name, txn_id, req_id);
		}
	}
	if (!get_tree->partial_error)
		get_tree->partial_error = (data_msg->partial_error ? data_msg->partial_error
								   : (int)err);

	if (!data_msg->more)
		get_tree->recv_clients |= (1u << id);

	/* check if done yet */
	if (get_tree->recv_clients != get_tree->sent_clients)
		return 0;

	return txn_get_tree_data_done(txn, txn_req);
}

static void txn_get_tree_timeout(struct event *event)
{
	struct mgmt_txn_ctx *txn;
	struct mgmt_txn_req *txn_req;

	txn_req = (struct mgmt_txn_req *)EVENT_ARG(event);
	txn = txn_req->txn;

	assert(txn);
	assert(txn->type == MGMTD_TXN_TYPE_SHOW);


	_log_err("Backend timeout txn-id: %" PRIu64 " ending get-tree", txn->txn_id);

	/*
	 * Send a get-tree data reply.
	 *
	 * NOTE: The transaction cleanup will be triggered from Front-end
	 * adapter.
	 */

	txn_req->req.get_tree->partial_error = -ETIMEDOUT;
	txn_get_tree_data_done(txn, txn_req);
}

/**
 * Send get-tree requests to each client indicated in `clients` bitmask, which
 * has registered operational state that matches the given `xpath`
 */
int mgmt_txn_send_get_tree(uint64_t txn_id, uint64_t req_id, uint64_t clients,
			   enum mgmt_ds_id ds_id, LYD_FORMAT result_type, uint8_t flags,
			   uint32_t wd_options, bool simple_xpath, struct lyd_node **ylib,
			   const char *xpath)
{
	struct mgmt_be_client_adapter *adapter;
	struct mgmt_msg_get_tree *msg;
	struct mgmt_txn_ctx *txn;
	struct mgmt_txn_req *txn_req;
	struct txn_req_get_tree *get_tree;
	enum mgmt_be_client_id id;
	ssize_t slen = strlen(xpath);

	txn = txn_lookup(txn_id);
	if (!txn)
		return -1;

	/* If error in this function below here, be sure to free the req */
	txn_req = mgmt_txn_req_alloc(txn, req_id, MGMTD_TXN_PROC_GETTREE);
	get_tree = txn_req->req.get_tree;
	get_tree->result_type = result_type;
	get_tree->wd_options = wd_options;
	get_tree->exact = CHECK_FLAG(flags, GET_DATA_FLAG_EXACT);
	get_tree->simple_xpath = simple_xpath;
	get_tree->xpath = XSTRDUP(MTYPE_MGMTD_XPATH, xpath);

	if (CHECK_FLAG(flags, GET_DATA_FLAG_CONFIG)) {
		/*
		 * If the requested datastore is operational, get the config
		 * from running.
		 */
		struct mgmt_ds_ctx *ds = mgmt_ds_get_ctx_by_id(mm, ds_id == MGMTD_DS_OPERATIONAL
									   ? MGMTD_DS_RUNNING
									   : ds_id);
		struct nb_config *config = mgmt_ds_get_nb_config(ds);

		if (config) {
			struct ly_set *set = NULL;
			LY_ERR err;

			err = lyd_find_xpath(config->dnode, xpath, &set);
			if (err) {
				get_tree->partial_error = err;
				goto state;
			}

			/*
			 * If there's a single result, duplicate the returned
			 * node. If there are multiple results, duplicate the
			 * whole config and mark simple_xpath as false so the
			 * result is trimmed later in txn_get_tree_data_done.
			 */
			if (set->count == 1) {
				err = lyd_dup_single(set->dnodes[0], NULL,
						     LYD_DUP_WITH_PARENTS | LYD_DUP_WITH_FLAGS |
							     LYD_DUP_RECURSIVE,
						     &get_tree->client_results);
				if (!err)
					while (get_tree->client_results->parent)
						get_tree->client_results =
							lyd_parent(get_tree->client_results);
			} else if (set->count > 1) {
				err = lyd_dup_siblings(config->dnode, NULL,
						       LYD_DUP_RECURSIVE | LYD_DUP_WITH_FLAGS,
						       &get_tree->client_results);
				if (!err)
					get_tree->simple_xpath = false;
			}

			if (err)
				get_tree->partial_error = err;

			ly_set_free(set, NULL);
		}
	}
state:
	if (*ylib) {
		LY_ERR err;

		err = lyd_merge_siblings(&get_tree->client_results, *ylib, LYD_MERGE_DESTRUCT);
		*ylib = NULL;
		if (err) {
			_log_err("Error merging yang-library result for txn-id: %Lu", txn_id);
			return NB_ERR;
		}
	}

	/* If we are only getting config, we are done */
	if (!CHECK_FLAG(flags, GET_DATA_FLAG_STATE) ||
	    ds_id != MGMTD_DS_OPERATIONAL || !clients)
		return txn_get_tree_data_done(txn, txn_req);

	msg = mgmt_msg_native_alloc_msg(struct mgmt_msg_get_tree, slen + 1,
					MTYPE_MSG_NATIVE_GET_TREE);
	msg->refer_id = txn_id;
	msg->req_id = req_id;
	msg->code = MGMT_MSG_CODE_GET_TREE;
	/* Always operate with the binary format in the backend */
	msg->result_type = LYD_LYB;
	strlcpy(msg->xpath, xpath, slen + 1);

	assert(clients);
	FOREACH_BE_ADAPTER_BITS (id, adapter, clients) {
		if (mgmt_be_send_native(adapter, msg))
			continue;
		SET_IDBIT(get_tree->sent_clients, id);
	}

	mgmt_msg_native_free_msg(msg);

	/* Return if we didn't send any messages to backends */
	if (!get_tree->sent_clients)
		return txn_get_tree_data_done(txn, txn_req);

	/* Start timeout timer - pulled out of register event code so we can
	 * pass a different arg
	 */
	event_add_timer(mgmt_txn_tm, txn_get_tree_timeout, txn_req,
			MGMTD_TXN_GET_TREE_MAX_DELAY_SEC, &txn->get_tree_timeout);
	return 0;
}

/* =============== */
/* RPC BACKEND TXN */
/* =============== */

/*
 * RPC txn has completed
 */
static int txn_rpc_done(struct mgmt_txn_ctx *txn, struct mgmt_txn_req *txn_req)
{
	struct txn_req_rpc *rpc = txn_req->req.rpc;
	uint64_t req_id = txn_req->req_id;

	/* cancel timer and send reply onward */
	event_cancel(&txn->rpc_timeout);

	if (rpc->errstr)
		mgmt_fe_adapter_txn_error(txn->txn_id, req_id, false, -EINVAL, rpc->errstr);
	else if (mgmt_fe_adapter_send_rpc_reply(txn->session_id, txn->txn_id, req_id,
						rpc->result_type, rpc->client_results)) {
		_log_err("Error sending the results of RPC for txn-id %" PRIu64 " req_id %" PRIu64
			 " to requested type %u",
			 txn->txn_id, req_id, rpc->result_type);

		(void)mgmt_fe_adapter_txn_error(txn->txn_id, req_id, false, -EINVAL,
						"Error converting results of RPC");
	}

	/* we're done with the request */
	mgmt_txn_req_free(&txn_req);

	return 0;
}

int mgmt_txn_handle_rpc_reply(struct mgmt_be_client_adapter *adapter,
			      struct mgmt_msg_rpc_reply *reply_msg, size_t msg_len)
{
	uint64_t txn_id = reply_msg->refer_id;
	uint64_t req_id = reply_msg->req_id;
	enum mgmt_be_client_id id = adapter->id;
	struct mgmt_txn_ctx *txn = txn_lookup(txn_id);
	struct mgmt_txn_req *txn_req;
	struct txn_req_rpc *rpc;
	struct lyd_node *tree;
	size_t data_len = msg_len - sizeof(*reply_msg);
	LY_ERR err = LY_SUCCESS;

	if (!txn) {
		_log_err("RPC reply from %s for a missing txn-id %" PRIu64, adapter->name, txn_id);
		return -1;
	}

	/* Find the request. */
	FOREACH_TXN_REQ_IN_LIST (&txn->reqs, txn_req)
		if (txn_req->req_id == req_id)
			break;
	if (!txn_req) {
		_log_err("RPC reply from %s for txn-id %" PRIu64 " missing req_id %" PRIu64,
			 adapter->name, txn_id, req_id);
		return -1;
	}

	rpc = txn_req->req.rpc;

	tree = NULL;
	if (data_len)
		err = yang_parse_rpc(rpc->xpath, reply_msg->result_type, reply_msg->data, true,
				     &tree);
	if (err) {
		_log_err("RPC reply from %s for txn-id %" PRIu64 " req_id %" PRIu64
			 " error parsing result of type %u: %s",
			 adapter->name, txn_id, req_id, reply_msg->result_type, ly_strerrcode(err));
	}
	if (!err && tree) {
		if (!rpc->client_results)
			rpc->client_results = tree;
		else
			err = lyd_merge_siblings(&rpc->client_results, tree, LYD_MERGE_DESTRUCT);
		if (err) {
			_log_err("RPC reply from %s for txn-id %" PRIu64 " req_id %" PRIu64
				 " error merging result: %s",
				 adapter->name, txn_id, req_id, ly_strerrcode(err));
		}
	}
	if (err) {
		XFREE(MTYPE_MGMTD_ERR, rpc->errstr);
		rpc->errstr = XSTRDUP(MTYPE_MGMTD_ERR, "Cannot parse result from the backend");
	}

	rpc->recv_clients |= (1u << id);

	/* check if done yet */
	if (rpc->recv_clients != rpc->sent_clients)
		return 0;

	return txn_rpc_done(txn, txn_req);
}

static void txn_rpc_timeout(struct event *event)
{
	struct mgmt_txn_ctx *txn;
	struct mgmt_txn_req *txn_req;

	txn_req = (struct mgmt_txn_req *)EVENT_ARG(event);
	txn = txn_req->txn;

	assert(txn);
	assert(txn->type == MGMTD_TXN_TYPE_RPC);

	_log_err("Backend timeout txn-id: %" PRIu64 " ending rpc", txn->txn_id);

	/*
	 * Send a get-tree data reply.
	 *
	 * NOTE: The transaction cleanup will be triggered from Front-end
	 * adapter.
	 */

	txn_req->req.rpc->errstr = XSTRDUP(MTYPE_MGMTD_ERR, "Operation on the backend timed-out");
	txn_rpc_done(txn, txn_req);
}

int mgmt_txn_send_rpc(uint64_t txn_id, uint64_t req_id, uint64_t clients, LYD_FORMAT result_type,
		      const char *xpath, const char *data, size_t data_len)
{
	struct mgmt_be_client_adapter *adapter;
	struct mgmt_txn_ctx *txn;
	struct mgmt_txn_req *txn_req;
	struct mgmt_msg_rpc *msg;
	struct txn_req_rpc *rpc;
	enum mgmt_be_client_id id;

	txn = txn_lookup(txn_id);
	if (!txn)
		return -1;

	txn_req = mgmt_txn_req_alloc(txn, req_id, MGMTD_TXN_PROC_RPC);
	rpc = txn_req->req.rpc;
	rpc->xpath = XSTRDUP(MTYPE_MGMTD_XPATH, xpath);
	rpc->result_type = result_type;

	msg = mgmt_msg_native_alloc_msg(struct mgmt_msg_rpc, 0,
					MTYPE_MSG_NATIVE_RPC);
	msg->refer_id = txn_id;
	msg->req_id = req_id;
	msg->code = MGMT_MSG_CODE_RPC;
	msg->request_type = result_type;

	mgmt_msg_native_xpath_encode(msg, xpath);
	if (data)
		mgmt_msg_native_append(msg, data, data_len);

	assert(clients);
	FOREACH_BE_ADAPTER_BITS (id, adapter, clients) {
		if (mgmt_be_send_native(adapter, msg))
			continue;
		SET_IDBIT(rpc->sent_clients, id);
	}

	mgmt_msg_native_free_msg(msg);

	if (!rpc->sent_clients)
		return txn_rpc_done(txn, txn_req);

	event_add_timer(mgmt_txn_tm, txn_rpc_timeout, txn_req,
			MGMTD_TXN_RPC_MAX_DELAY_SEC, &txn->rpc_timeout);

	return 0;
}

/* =================== */
/* SEND NOTIFY BACKEND */
/* =================== */

int mgmt_txn_send_notify_selectors(uint64_t req_id, uint64_t session_id, uint64_t clients,
				   const char **selectors)
{
	struct mgmt_be_client_adapter *adapter;
	struct mgmt_msg_notify_select *msg;
	enum mgmt_be_client_id id;
	char **all_selectors = NULL;
	uint i;

	msg = mgmt_msg_native_alloc_msg(struct mgmt_msg_notify_select, 0,
					MTYPE_MSG_NATIVE_NOTIFY_SELECT);
	msg->refer_id = session_id;
	msg->req_id = req_id;
	msg->code = MGMT_MSG_CODE_NOTIFY_SELECT;
	msg->replace = selectors == NULL;
	msg->get_only = session_id != MGMTD_SESSION_ID_NONE;

	if (selectors == NULL) {
		/* Get selectors for all sessions */
		all_selectors = mgmt_fe_get_all_selectors();
		selectors = (const char **)all_selectors;
	}

	darr_foreach_i (selectors, i)
		mgmt_msg_native_add_str(msg, selectors[i]);

	assert(clients);
	FOREACH_BE_ADAPTER_BITS (id, adapter, clients) {
		if (mgmt_be_send_native(adapter, msg))
			continue;
	}
	mgmt_msg_native_free_msg(msg);

	if (all_selectors)
		darr_free_free(all_selectors);

	return 0;
}

/* ============== */
/* ERROR HANDLING */
/* ============== */

/*
 * Error reply from the backend client.
 *
 * NOTE: can disconnect (and delete) the backend.
 */
void mgmt_txn_handle_error_reply(struct mgmt_be_client_adapter *adapter, uint64_t txn_id,
				 uint64_t req_id, int error, const char *errstr)
{
	enum mgmt_be_client_id id = adapter->id;
	struct mgmt_txn_ctx *txn = txn_lookup(txn_id);
	struct txn_req_get_tree *get_tree;
	struct txn_req_rpc *rpc;
	struct mgmt_txn_req *txn_req;

	if (!txn) {
		_log_err("Error reply from %s cannot find txn-id %" PRIu64, adapter->name, txn_id);
		return;
	}

	if (txn->type == MGMTD_TXN_TYPE_CONFIG) {
		mgmt_txn_cfg_handle_error(adapter, txn_id, req_id, error, errstr);
		return;
	}

	/*
	 * Find the non-config request.
	 */

	FOREACH_TXN_REQ_IN_LIST (&txn->reqs, txn_req)
		if (txn_req->req_id == req_id)
			break;
	if (!txn_req) {
		_log_err("Error reply from %s for txn-id %" PRIu64 " cannot find req_id %" PRIu64,
			 adapter->name, txn_id, req_id);
		return;
	}

	_log_err("Error reply from %s for txn-id %" PRIu64 " req_id %" PRIu64, adapter->name,
		 txn_id, req_id);

	switch (txn_req->req_type) {
	case MGMTD_TXN_PROC_GETTREE:
		get_tree = txn_req->req.get_tree;
		get_tree->recv_clients |= (1u << id);
		get_tree->partial_error = error;

		/* check if done yet */
		if (get_tree->recv_clients == get_tree->sent_clients)
			txn_get_tree_data_done(txn, txn_req);
		return;
	case MGMTD_TXN_PROC_RPC:
		rpc = txn_req->req.rpc;
		rpc->recv_clients |= (1u << id);
		if (errstr) {
			XFREE(MTYPE_MGMTD_ERR, rpc->errstr);
			rpc->errstr = XSTRDUP(MTYPE_MGMTD_ERR, errstr);
		}
		/* check if done yet */
		if (rpc->recv_clients == rpc->sent_clients)
			txn_rpc_done(txn, txn_req);
		return;
	case MGMTD_TXN_PROC_COMMITCFG:
		/* this is handled above */
		break;
	default:
		assert(!"non-native req type in native error path");
	}
}

void mgmt_txn_status_write(struct vty *vty)
{
	struct mgmt_txn_ctx *txn;

	vty_out(vty, "MGMTD Transactions\n");

	FOREACH_TXN_IN_LIST (mgmt_txn_mm, txn) {
		vty_out(vty, "  Txn: \t\t\t0x%p\n", txn);
		vty_out(vty, "    Txn-Id: \t\t\t%" PRIu64 "\n", txn->txn_id);
		vty_out(vty, "    Session-Id: \t\t%" PRIu64 "\n",
			txn->session_id);
		vty_out(vty, "    Type: \t\t\t%s\n",
			mgmt_txn_type2str(txn->type));
		vty_out(vty, "    Ref-Count: \t\t\t%d\n", txn->refcount);
	}
	vty_out(vty, "  Total: %d\n", (int)mgmt_txns_count(&mgmt_txn_mm->txn_list));
}
