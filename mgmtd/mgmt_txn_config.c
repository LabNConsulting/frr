// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * November 7 2025, Christian Hopps <chopps@labn.net>
 *
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


struct mgmt_edit_req {
	char xpath_created[XPATH_MAXLEN];
	bool created;
	bool unlock;
};

static void txn_cfg_commit_timedout(struct event *event);
static void txn_cfg_adapter_acked(struct mgmt_txn_req *txn_req,
				  struct mgmt_be_client_adapter *adapter);
static void txn_cfg_finish_commit(struct mgmt_txn_req *txn_req, enum mgmt_result result,
				  const char *error_if_any);

/* ======= */
/* UTILITY */
/* ======= */

static inline const char *txn_cfg_phase_name(struct mgmt_txn_req *txn_req)
{
	switch (txn_req->req.commit_cfg.phase) {
	case MGMTD_COMMIT_PHASE_SEND_CFG:
		return "SEND-CFG";
	case MGMTD_COMMIT_PHASE_APPLY_CFG:
		return "APPLY-CFG";
	case MGMTD_COMMIT_PHASE_FINISH:
		return "FINISH";
	}
	return "Invalid/Unknown";
}

static int txn_cfg_set_error(struct mgmt_txn_req *txn_req, enum mgmt_result error,
			     const char *error_info)
{
	txn_req->error = error;
	darr_in_strdup(txn_req->err_info, error_info);
	return -1;
}

static struct mgmt_txn_req *
txn_cfg_ensure_be_msg(uint64_t txn_id, struct mgmt_be_client_adapter *adapter, const char *tag)
{
	struct mgmt_txn_ctx *txn = txn_lookup(txn_id);
	struct mgmt_txn_req *txn_req;

	if (!txn) {
		_log_err("%s reply from '%s' for txn-id: %Lu no TXN, resetting connection", tag,
			 adapter->name, txn_id);
		return NULL;
	}
	if (txn->type != MGMTD_TXN_TYPE_CONFIG) {
		_log_err("%s reply from '%s' for txn-id: %Lu failed wrong txn TYPE %u, resetting connection",
			 tag, adapter->name, txn_id, txn->type);
		return NULL;
	}
	txn_req = txn->commit_cfg_req;
	if (!txn_req) {
		_log_err("%s reply from '%s' for txn-id: %Lu failed no COMMITCFG_REQ, resetting connection",
			 tag, adapter->name, txn_id);
		return NULL;
	}
	/* make sure we are part of this config commit */
	if (!IS_IDBIT_SET(txn_req->req.commit_cfg.clients, adapter->id)) {
		_log_err("%s reply from '%s' for txn-id %Lu not participating, resetting connection",
			 tag, adapter->name, txn_id);
		return NULL;
	}
	return txn_req;
}

/* ======================================= */
/* SEND PHASE - Sending Config to Backends */
/* ======================================= */

/*
 * This is the real workhorse. Take the list of changes and check each change
 * against our backend clients to see who is interested. For each interested
 * client we create a config message -- we also track which changes mgmtd itself
 * is interested in. If a client is interested we add the change to it's config
 * message and track the type of chagne in another string array.
 *
 * When done with the changes we first handle mgmtd's own changes, validating,
 * and preparing them into the mgmtd candidate (using normal lib/northbound
 * routines). Then for each backend client we complete it's config message by
 * append the action string and then we send it to the client.
 *
 * Return: 0 on success, the caller should arrange to receive REPLYS from the
 * clients before proceeding further, if no clients were interested the caller
 * should proceed to apply the mgmtd local changes (if any) to complete the txn.
 *
 * On failure, if we were called from a front-end client (the TXN has a
 * session_id) we have it reply with the error and cleanup the txn. Otherwise
 * this is an internal txn and we just cleanup the txn in that case. In either
 * case we return -1 and the caller should not proceed further.
 *
 * Can disconnect backends, but this is not called from backends, so it's safe.
 */

static int txn_cfg_make_and_send_msgs(struct mgmt_txn_req *txn_req,
				      const struct nb_config_cbs *changes,
				      uint64_t init_client_mask)
{
	struct nb_config_cb *cb, *nxt;
	struct nb_config_change *chg;
	struct nb_config_cbs mgmtd_changes = { 0 };
	char *xpath = NULL, *value = NULL;
	enum mgmt_be_client_id id;
	struct mgmt_be_client_adapter *adapter;
	struct mgmt_commit_cfg_req *cmtcfg_req;
	struct mgmt_msg_cfg_req **cfg_msgs = NULL;
	char **cfg_actions = NULL;
	uint64_t *num_cfg_data = NULL;
	bool mgmtd_interest;
	uint batch_items = 0;
	uint num_chgs = 0;
	uint64_t clients, chg_clients;
	char op;
	int ret = -1;

	cmtcfg_req = &txn_req->req.commit_cfg;

	RB_FOREACH_SAFE (cb, nb_config_cbs, changes, nxt) {
		chg = (struct nb_config_change *)cb;

		/*
		 * Could have directly pointed to xpath in nb_node.
		 * But dont want to mess with it now.
		 * xpath = chg->cb.nb_node->xpath;
		 */
		xpath = lyd_path(chg->cb.dnode, LYD_PATH_STD, NULL, 0);
		if (!xpath) {
			(void)txn_cfg_set_error(txn_req, MGMTD_INTERNAL_ERROR,
						"Internal error! Could not get Xpath from Ds node!");
			nb_config_diff_del_changes(&mgmtd_changes);
			goto done;
		}

		value = (char *)lyd_get_value(chg->cb.dnode);
		if (!value)
			value = (char *)MGMTD_BE_CONTAINER_NODE_VAL;

		_dbg("XPATH: %s, Value: '%s'", xpath, value ? value : "NIL");

		/* Collect changes for mgmtd itself */
		mgmtd_interest = false;
		if (!init_client_mask && mgmt_is_mgmtd_interested(xpath) &&
		    /* We send tree changes to BEs that we don't need callbacks for */
		    nb_cb_operation_is_valid(cb->operation, cb->dnode->schema)) {
			uint32_t seq = cb->seq;

			nb_config_diff_add_change(&mgmtd_changes, cb->operation, &seq, cb->dnode);
			mgmtd_interest = true;
		}
		if (init_client_mask)
			clients = init_client_mask;
		else
			clients = mgmt_be_interested_clients(xpath, MGMT_BE_XPATH_SUBSCR_TYPE_CFG);
		if (!clients)
			_dbg("No backends interested in xpath: %s", xpath);

		if (mgmtd_interest || clients)
			num_chgs++;

		chg_clients = 0;
		FOREACH_BE_ADAPTER_BITS (id, adapter, clients) {
			SET_IDBIT(chg_clients, id);

			darr_ensure_i(cfg_msgs, id);
			darr_ensure_i(cfg_actions, id);
			if (DEBUG_MODE_CHECK(&mgmt_debug_txn, DEBUG_MODE_ALL))
				darr_ensure_i(num_cfg_data, id);
			if (!cfg_msgs[id]) {
				/* Allocate a new config message */
				struct mgmt_msg_cfg_req *msg;

				msg = mgmt_msg_native_alloc_msg(struct mgmt_msg_cfg_req, 0,
								MTYPE_MSG_NATIVE_CFG_REQ);
				msg->code = MGMT_MSG_CODE_CFG_REQ;
				msg->refer_id = txn_req->txn->txn_id;
				msg->req_id = txn_req->req_id;
				cfg_msgs[id] = msg;
			}

			/*
			 * On the backend, we don't really care if it's CREATE
			 * or MODIFY, because the existence was already checked
			 * on the frontend. Therefore we use SET for both.
			 */
			op = chg->cb.operation == NB_CB_DESTROY ? 'd' : 'm';
			darr_push(cfg_actions[id], op);

			mgmt_msg_native_add_str(cfg_msgs[id], xpath);
			if (op == 'm')
				mgmt_msg_native_add_str(cfg_msgs[id], value);
			if (DEBUG_MODE_CHECK(&mgmt_debug_txn, DEBUG_MODE_ALL)) {
				num_cfg_data[id]++;
				_dbg(" -- %s, batch item: %Lu", adapter->name, num_cfg_data[id]);
			}

			batch_items++;
		}

		if (clients && clients != chg_clients)
			_dbg("Some deamons interested in XPATH are not currently connected");

		cmtcfg_req->clients |= chg_clients;

		free(xpath);
	}
	cmtcfg_req->cmt_stats->last_batch_cnt = batch_items;

	if (!RB_EMPTY(nb_config_cbs, &mgmtd_changes)) {
		/* Create a northbound transaction for local mgmtd config changes */
		char errmsg[BUFSIZ] = { 0 };
		size_t errmsg_len = sizeof(errmsg);
		struct nb_context nb_ctx = { 0 };

		_dbg("Processing mgmtd bound changes");

		assert(!cmtcfg_req->mgmtd_nb_txn);
		nb_ctx.client = NB_CLIENT_MGMTD_SERVER;

		/* Prepare the mgmtd local config changes */
		/*
		 * This isn't calling the VALIDATE callback, it's just
		 * running PREPARE. See #19948
		 */
		if (nb_changes_commit_prepare(nb_ctx, mgmtd_changes, "mgmtd-changes", NULL,
					      &cmtcfg_req->mgmtd_nb_txn, errmsg, errmsg_len)) {
			_log_err("Failed to prepare local config for mgmtd: %s", errmsg);
			if (cmtcfg_req->mgmtd_nb_txn) {
				nb_candidate_commit_abort(cmtcfg_req->mgmtd_nb_txn, NULL, 0);
				cmtcfg_req->mgmtd_nb_txn = NULL;
			}
			(void)txn_cfg_set_error(txn_req, MGMTD_INTERNAL_ERROR,
						"Failed to prepare local config for mgmtd");
			goto done;
		}
		assert(cmtcfg_req->mgmtd_nb_txn);
	}

	/* Record txn create start time */
	if (mm->perf_stats_en)
		gettimeofday(&cmtcfg_req->cmt_stats->txn_create_start, NULL);

	/* Send the messages to the backends */
	FOREACH_BE_ADAPTER_BITS (id, adapter, cmtcfg_req->clients) {
		/* NUL terminate actions string and add to tail of message */
		darr_push(cfg_actions[id], 0);
		mgmt_msg_native_add_str(cfg_msgs[id], cfg_actions[id]);
		_dbg("Finished CFG_REQ for '%s' txn-id: %Lu with actions: %s", adapter->name,
		     txn_req->txn->txn_id, cfg_actions[id]);

		if (mgmt_be_send_native(adapter, cfg_msgs[id])) {
			/* remove this client and reset the connection */
			UNSET_IDBIT(cmtcfg_req->clients, id);
			msg_conn_disconnect(adapter->conn, false);
		}
		cmtcfg_req->cmt_stats->last_num_cfgdata_reqs++;
	}
	/* Record who we are waiting for */
	cmtcfg_req->clients_wait = cmtcfg_req->clients;

	if (cmtcfg_req->clients) {
		/* set a timeout for hearing back from the backend clients */
		event_add_timer(mgmt_txn_tm, txn_cfg_commit_timedout, txn_req->txn,
				MGMTD_TXN_CFG_COMMIT_MAX_DELAY_SEC,
				&txn_req->txn->comm_cfg_timeout);
	} else {
		/* We have no connected interested clients */
		if (cmtcfg_req->mgmtd_nb_txn)
			_dbg("No connected and interested backend clients, proceed with mgmtd local changes");
		else
			_dbg("No connected and interested backend clients, proceed to apply changes");
		txn_cfg_adapter_acked(txn_req, NULL);
	}

	ret = 0;
done:
	darr_free(num_cfg_data);
	darr_free_func(cfg_msgs, mgmt_msg_native_free_msg);
	darr_free_free(cfg_actions);
	return ret;
}

/*
 * Abort the sent config -- XXX better name this
 */
static int txn_cfg_send_txn_delete(struct mgmt_be_client_adapter *adapter, uint64_t txn_id)
{
	struct mgmt_msg_txn_req *msg;
	int ret;

	msg = mgmt_msg_native_alloc_msg(struct mgmt_msg_txn_req, 0, MTYPE_MSG_NATIVE_TXN_REQ);
	msg->code = MGMT_MSG_CODE_TXN_REQ;
	msg->refer_id = txn_id;
	msg->create = false;

	ret = mgmt_be_send_native(adapter, msg);
	mgmt_msg_native_free_msg(msg);
	return ret;
}

/*
 * Given a list of config changes, make backend client messages and send them. Aslo
 * apply any mgmtd specific config as well.
 */
static int txn_cfg_send_changes(struct mgmt_txn_ctx *txn, struct nb_config_cbs *cfg_chgs,
				uint64_t init_client_mask)
{
	int ret;

	if (mm->perf_stats_en)
		gettimeofday(&txn->commit_cfg_req->req.commit_cfg.cmt_stats->prep_cfg_start, NULL);

	ret = txn_cfg_make_and_send_msgs(txn->commit_cfg_req, cfg_chgs, init_client_mask);
	nb_config_diff_del_changes(cfg_chgs);
	return ret;
}

/*
 * Handle CFG_REQ reply from backend client adapter. This is the only point of
 * failure that is expected in the config commit process; it is where the
 * backend client can report validation or prepare errors.
 *
 * NOTE: can disconnect (and delete) the backend.
 */
static void txn_cfg_handle_cfg_reply(struct mgmt_txn_req *txn_req, bool success,
				     const char *error_if_any,
				     struct mgmt_be_client_adapter *adapter)
{
	struct mgmt_commit_cfg_req *cmtcfg_req = &txn_req->req.commit_cfg;

	assert(cmtcfg_req);

	if (!IS_IDBIT_SET(cmtcfg_req->clients_wait, adapter->id)) {
		_log_warn("CFG_REPLY from '%s' but not waiting for it for txn-id: %Lu, resetting connection",
			  adapter->name, txn_req->txn->txn_id);
		msg_conn_disconnect(adapter->conn, false);
		return;
	}

	if (success)
		_dbg("CFG_REPLY from '%s'", adapter->name);
	else {
		_log_err("CFG_REQ to '%s' failed err: %s", adapter->name, error_if_any ?: "None");
		txn_cfg_finish_commit(txn_req, MGMTD_VALIDATION_ERROR,
				      error_if_any ?: "config validation failed by backend daemon");
		return;
	}

	txn_cfg_adapter_acked(txn_req, adapter);
}


/* ============================================== */
/* APPLY PHASE - Applying Sent Config on Backends */
/* ============================================== */

/*
 * Send CFG_APPLY_REQs to all the backend client.
 */
static void txn_cfg_send_cfg_apply(struct mgmt_txn_req *txn_req)
{
	enum mgmt_be_client_id id;
	struct mgmt_be_client_adapter *adapter;
	struct mgmt_commit_cfg_req *cmtcfg_req;
	struct mgmt_msg_cfg_apply_req *msg;
	uint64_t txn_id = txn_req->txn->txn_id;

	assert(txn_req->txn->type == MGMTD_TXN_TYPE_CONFIG);

	cmtcfg_req = &txn_req->req.commit_cfg;
	assert(!cmtcfg_req->validate_only);

	if (mm->perf_stats_en)
		gettimeofday(&cmtcfg_req->cmt_stats->apply_cfg_start, NULL);
	/*
	 * Handle mgmtd internal special case
	 */
	if (cmtcfg_req->mgmtd_nb_txn) {
		char errmsg[BUFSIZ] = { 0 };

		_dbg("Applying mgmtd local bound changes");

		(void)nb_candidate_commit_apply(cmtcfg_req->mgmtd_nb_txn, false, NULL, errmsg,
						sizeof(errmsg));
		cmtcfg_req->mgmtd_nb_txn = NULL;
	}

	msg = mgmt_msg_native_alloc_msg(struct mgmt_msg_cfg_apply_req, 0,
					MTYPE_MSG_NATIVE_CFG_APPLY_REQ);
	msg->code = MGMT_MSG_CODE_CFG_APPLY_REQ;
	msg->refer_id = txn_id;
	FOREACH_BE_ADAPTER_BITS (id, adapter, cmtcfg_req->clients) {
		if (mgmt_be_send_native(adapter, msg)) {
			msg_conn_disconnect(adapter->conn, false);
			continue;
		}
		SET_IDBIT(cmtcfg_req->clients_wait, id);
		cmtcfg_req->cmt_stats->last_num_apply_reqs++;
	}
	mgmt_msg_native_free_msg(msg);

	if (!cmtcfg_req->clients_wait) {
		_dbg("No backends to wait for on CFG_APPLY for txn-id: %Lu", txn_id);
		txn_cfg_adapter_acked(txn_req, NULL);
	}
}


static void txn_cfg_send_cfg_apply(struct mgmt_txn_req *txn_req);

/* ==================================== */
/* FINISH PHASE - Finish the Commit TXN */
/* ==================================== */

/*
 * Finish processing a commit-config request.
 *
 * NOTE: can disconnect (and delete) backends.
 */
static void txn_cfg_finish_commit(struct mgmt_txn_req *txn_req, enum mgmt_result result,
				  const char *error_if_any)
{
	bool success, apply_op, accept_changes, discard_changes;
	struct mgmt_commit_cfg_req *ccreq = &txn_req->req.commit_cfg;
	struct mgmt_txn_ctx *txn = txn_req->txn;
	int ret;

	success = (result == MGMTD_SUCCESS || result == MGMTD_NO_CFG_CHANGES);

	/*
	 * Send reply to front-end session (if any).
	 */
	if (!txn->session_id)
		ret = 0; /* No front-end session to reply to (rollback or init) */
	else if (!ccreq->edit)
		/* This means we are in the mgmtd CLI vty code */
		ret = mgmt_fe_send_commit_cfg_reply(txn->session_id, txn->txn_id, ccreq->src_ds_id,
						    ccreq->dst_ds_id, txn_req->req_id,
						    ccreq->validate_only, ccreq->unlock, result,
						    error_if_any);
	else
		ret = mgmt_fe_adapter_send_edit_reply(txn->session_id, txn->txn_id,
						      txn_req->req_id, ccreq->edit->unlock, true,
						      ccreq->edit->created,
						      ccreq->edit->xpath_created, success ? 0 : -1,
						      error_if_any);
	if (ret)
		_log_err("Failed sending config reply for txn-id: %Lu session-id: %Lu",
			 txn->txn_id, txn->session_id);
	/*
	 * Stop the commit-timeout timer.
	 */
	event_cancel(&txn->comm_cfg_timeout);

	/*
	 * Decide what our datastores should now look like
	 *
	 * Accept changes into running (candidate->running):
	 *
	 *    If this is a commit (apply or rollback) and we've at least started
	 *    telling backend clients to apply, we need to accept the changes
	 *    into running. Any clients who have not acked the apply yet will be
	 *    disconnected in the txn cleanup so they sync to running on
	 *    reconnect.
	 *
	 * Discard candidate changes (running->candidate):
	 *
	 *    If this is a successful abort, or a failed immediate-effect config
	 *    operation. Failed means no backend clients have been told to apply
	 *    the config yet, and immediate-effect config ops are from classic
	 *    CLI interface (unlock set) or edit messages with implicit commit
	 *    indicated (implicit set, e.g., as used by clients like RESTCONF).
	 *
	 *    In particular when doing validate-only operation (`commit check`)
	 *    the candidate shouldn't revert, the user will expect to keep
	 *    modifying it to make it valid.
	 *
	 *    NOTE: the mgmtd front-end adapter code should ideally be doing
	 *    this candidate restore itself as it is the one modifying the
	 *    candidate datastore. So this is sloppy. This code is handling a
	 *    commit request so it is either accepting the changes into running
	 *    or it is not.
	 *
	 * It would be nice to reduce options to better represent some of the
	 * mutual exclusivity, not all variations are valid (e.g., validate_only
	 * will never be set with abort or init or rollback or when doing
	 * immediate-effect operations).
	 */
	apply_op = !ccreq->validate_only && !ccreq->abort && !ccreq->init;
	accept_changes = ccreq->phase >= MGMTD_COMMIT_PHASE_APPLY_CFG && apply_op;
	discard_changes = (result == MGMTD_SUCCESS && ccreq->abort) ||
			  (apply_op && ccreq->phase < MGMTD_COMMIT_PHASE_APPLY_CFG &&
			   (ccreq->implicit || ccreq->unlock));

	if (accept_changes) {
		bool create_cmt_info_rec = (result != MGMTD_NO_CFG_CHANGES && !ccreq->rollback);

		mgmt_ds_copy_dss(ccreq->dst_ds_ctx, ccreq->src_ds_ctx, create_cmt_info_rec);
	}
	if (discard_changes)
		mgmt_ds_copy_dss(ccreq->src_ds_ctx, ccreq->dst_ds_ctx, false);

	if (ccreq->rollback) {
		mgmt_ds_unlock(ccreq->src_ds_ctx);
		mgmt_ds_unlock(ccreq->dst_ds_ctx);
		/*
		 * Resume processing the rollback command.
		 *
		 * TODO: there's no good reason to special case rollback, the
		 * rollback boolean should be passed back to the FE client and it
		 * can do the right thing.
		 */
		mgmt_history_rollback_complete(success);
	}

	if (ccreq->init) {
		/*
		 * This is the backend init request.
		 * We need to unlock the running datastore.
		 */
		mgmt_ds_unlock(ccreq->dst_ds_ctx);
	}

	ccreq->cmt_stats = NULL;
	mgmt_txn_req_free(&txn->commit_cfg_req);

	/*
	 * The CONFIG Transaction should be destroyed from Frontend-adapter.
	 * But in case the transaction is not triggered from a front-end session
	 * we need to cleanup by itself.
	 */
	if (!txn->session_id)
		mgmt_txn_cleanup_txn(&txn);
}

/* =================== */
/* (3) STATE MACHINERY */
/* =================== */

static void txn_cfg_next_phase(struct mgmt_txn_req *txn_req)
{
	struct mgmt_commit_cfg_req *ccreq = &txn_req->req.commit_cfg;

	switch (ccreq->phase) {
	case MGMTD_COMMIT_PHASE_SEND_CFG:
		if (ccreq->validate_only)
			ccreq->phase = MGMTD_COMMIT_PHASE_FINISH;
		else
			ccreq->phase = MGMTD_COMMIT_PHASE_APPLY_CFG;
		break;
	case MGMTD_COMMIT_PHASE_APPLY_CFG:
		if (mm->perf_stats_en)
			gettimeofday(&ccreq->cmt_stats->apply_cfg_end, NULL);
		ccreq->phase = MGMTD_COMMIT_PHASE_FINISH;
		break;
	case MGMTD_COMMIT_PHASE_FINISH:
	default:
		assert(!"Invalid commit phase transition from FINISH");
		break;
	}

	_dbg("CONFIG-STATE-MACHINE txn-id: %Lu transition to state: %s", txn_req->txn->txn_id,
	     txn_cfg_phase_name(txn_req));

	switch (ccreq->phase) {
	case MGMTD_COMMIT_PHASE_APPLY_CFG:
		txn_cfg_send_cfg_apply(txn_req);
		break;
	case MGMTD_COMMIT_PHASE_FINISH:
		if (mm->perf_stats_en)
			gettimeofday(&ccreq->cmt_stats->txn_del_start, NULL);
		txn_cfg_finish_commit(txn_req, MGMTD_SUCCESS, NULL);
		return;
	case MGMTD_COMMIT_PHASE_SEND_CFG:
	default:
		assert(!"Invalid commit phase transition to SEND_CFG");
	}
}

static void txn_cfg_adapter_acked(struct mgmt_txn_req *txn_req,
				  struct mgmt_be_client_adapter *adapter)
{
	struct mgmt_commit_cfg_req *ccreq = &txn_req->req.commit_cfg;

	_dbg("CONFIG-STATE-MACHINE txn-id: %Lu in state: %s", txn_req->txn->txn_id,
	     txn_cfg_phase_name(txn_req));

	if (adapter) {
		enum mgmt_be_client_id id = adapter->id;

		if (IS_IDBIT_SET(ccreq->clients_wait, id))
			UNSET_IDBIT(ccreq->clients_wait, id);
		else
			_dbg("Wasn't waiting on client: %s", adapter->name);
	}

	if (ccreq->clients_wait) {
		_dbg("CONFIG-STATE-MACHINE txn-id: %Lu still waiting on clients: 0x%Lx",
		     txn_req->txn->txn_id, ccreq->clients_wait);
		return;
	}

	txn_cfg_next_phase(txn_req);
}

static void txn_cfg_commit_timedout(struct event *event)
{
	struct mgmt_txn_ctx *txn;
	struct mgmt_txn_req *txn_req;
	struct mgmt_commit_cfg_req *ccreq;

	txn = (struct mgmt_txn_ctx *)EVENT_ARG(event);
	assert(txn);
	assert(txn->type == MGMTD_TXN_TYPE_CONFIG);
	txn_req = txn->commit_cfg_req;
	if (!txn_req)
		return;
	ccreq = &txn_req->req.commit_cfg;

	/*
	 * If we are applying changes we need to return SUCCESS as there is no
	 * way to abort those. Slow backends that haven't replied yet will be
	 * disconnected. If we are still sending config for validate/prepare
	 * phase we return an error and abort the commit.
	 */
	if (ccreq->phase < MGMTD_COMMIT_PHASE_APPLY_CFG) {
		_log_err("Backend timeout validating txn-id: %Lu waiting: 0x%Lx aborting commit",
			 txn->txn_id, ccreq->clients_wait);
		txn_cfg_finish_commit(txn_req, MGMTD_INTERNAL_ERROR,
				      "Some backend clients taking too long to validate the changes.");
	} else {
		_log_warn("Backend timeout applying txn-id: %Lu waiting: 0x%Lx, applying commit",
			  txn->txn_id, ccreq->clients_wait);
		txn_cfg_finish_commit(txn_req, MGMTD_SUCCESS,
				      "Some backend clients taking too long to apply the changes.");
	}
}

/* ======================= */
/* INTERNAL CONFIG TXN API */
/* ======================= */

void mgmt_txn_cfg_cleanup(struct mgmt_txn_req *txn_req)
{
	struct mgmt_commit_cfg_req *ccreq = &txn_req->req.commit_cfg;
	struct mgmt_be_client_adapter *adapter;
	enum mgmt_be_client_id id;
	uint64_t txn_id = txn_req->txn->txn_id;
	uint64_t clients;

	_dbg("Deleting COMMITCFG req-id: %Lu txn-id: %Lu", txn_req->req_id, txn_id);

	XFREE(MTYPE_MGMTD_TXN_REQ, ccreq->edit);

	/* If we (still) had an internal nb transaction, abort it */
	if (ccreq->mgmtd_nb_txn) {
		nb_candidate_commit_abort(ccreq->mgmtd_nb_txn, NULL, 0);
		ccreq->mgmtd_nb_txn = NULL;
	}

	/*
	 * Non-error apply path: we are in Finish phase of commit, so we have
	 * already sent CFG_APPLY and received CFG_APPLY_REPLY from all clients
	 * or we have sent CFG_ABORT to all clients. Nothing left to do.
	 *
	 * Otherwise if we are in Apply phase, any clients that have not
	 * CFG_APPLY_REPLY'd yet (clients_wait) need to be disconnected as so
	 * they will resync config state.
	 *
	 * Otherwise we are in Send-config phase and clients will have cfg txn
	 * state. Send all clients CFG_ABORT to cleanup any transaction state.
	 * Even if clients have rejected the config and deleted txn state they
	 * are expected to handle receving CFG_ABORT gracefully. We can be here
	 * when we run into an error, but also if we were only doing validation
	 * (commit check).
	 */
	switch (ccreq->phase) {
	case MGMTD_COMMIT_PHASE_FINISH:
		break;
	case MGMTD_COMMIT_PHASE_APPLY_CFG:
		clients = ccreq->clients_wait;
		ccreq->clients_wait = 0;
		ccreq->clients = 0;
		FOREACH_BE_ADAPTER_BITS (id, adapter, clients) {
			_dbg("Disconnect client: %s for txn-id: %Lu resync required",
			     adapter->name, txn_id);
			msg_conn_disconnect(adapter->conn, false);
		}
		break;
	case MGMTD_COMMIT_PHASE_SEND_CFG:
		clients = ccreq->clients;
		ccreq->clients_wait = 0;
		ccreq->clients = 0;
		FOREACH_BE_ADAPTER_BITS (id, adapter, clients) {
			if (!txn_cfg_send_txn_delete(adapter, txn_id))
				continue;
			_dbg("Disconnect client: %s for txn-id: %Lu failed to send CFG_ABORT",
			     adapter->name, txn_id);
			msg_conn_disconnect(adapter->conn, false);
		}
		break;
	}
}

/*
 * NOTE: can disconnect (and delete) the backend.
 */
void mgmt_txn_cfg_handle_cfg_reply(uint64_t txn_id, struct mgmt_be_client_adapter *adapter)
{
	struct mgmt_txn_req *txn_req = txn_cfg_ensure_be_msg(txn_id, adapter, "CFG_REPLY");

	if (!txn_req)
		msg_conn_disconnect(adapter->conn, false);
	else
		txn_cfg_handle_cfg_reply(txn_req, true, NULL, adapter);
}

/*
 * NOTE: can disconnect (and delete) the backend.
 */
void mgmt_txn_cfg_handle_apply_reply(uint64_t txn_id, struct mgmt_be_client_adapter *adapter)
{
	struct mgmt_txn_req *txn_req = txn_cfg_ensure_be_msg(txn_id, adapter, "CFG_APPLY");

	if (!txn_req)
		msg_conn_disconnect(adapter->conn, false);
	else
		txn_cfg_adapter_acked(txn_req, adapter);
}

void mgmt_txn_cfg_handle_error(struct mgmt_be_client_adapter *adapter, uint64_t txn_id,
			       uint64_t req_id, int error, const char *errstr)
{
	struct mgmt_txn_req *txn_req;
	/*
	 * Handle an error during a configuration transaction.
	 */
	txn_req = txn_cfg_ensure_be_msg(txn_id, adapter, "ERROR");
	if (!txn_req) {
		msg_conn_disconnect(adapter->conn, false);
		return;
	}
	/*
	 * We only handle errors in reply to our CFG_REQ messages (due
	 * to validation/preparation). Otherwise, this is an error
	 * during some other phase of the commit process and we
	 * disconnect the client and start over.
	 */
	if (txn_req->req.commit_cfg.phase == MGMTD_COMMIT_PHASE_SEND_CFG)
		txn_cfg_handle_cfg_reply(txn_req, false, errstr, adapter);
	else
		/* Drop the connection these errors should never happen */
		msg_conn_disconnect(adapter->conn, false);
	return;
}

void mgmt_txn_cfg_client_disconnect(struct mgmt_be_client_adapter *adapter,
				    struct mgmt_txn_ctx *txn)
{
	struct mgmt_txn_req *txn_req = txn->commit_cfg_req;
	struct mgmt_commit_cfg_req *ccreq = txn_req ? &txn_req->req.commit_cfg : NULL;

	if (!ccreq)
		return;
	UNSET_IDBIT(ccreq->clients, adapter->id);
	if (IS_IDBIT_SET(ccreq->clients_wait, adapter->id))
		txn_cfg_adapter_acked(txn->commit_cfg_req, adapter);
}

/* ===================== */
/* PUBLIC CONFIG TXN API */
/* ===================== */

/*
 * Prepare and send config changes by comparing the source and destination
 * datastores.
 */
static int txn_cfg_get_changes(struct mgmt_txn_ctx *txn, struct nb_config_cbs *cfg_chgs)
{
	struct nb_config *nb_config;
	struct mgmt_txn_req *txn_req = txn->commit_cfg_req;
	int ret = 0;

	if (txn->commit_cfg_req->req.commit_cfg.src_ds_id != MGMTD_DS_CANDIDATE) {
		return txn_cfg_set_error(txn_req, MGMTD_INVALID_PARAM,
					 "Source DS cannot be any other than CANDIDATE!");
	}

	if (txn->commit_cfg_req->req.commit_cfg.dst_ds_id != MGMTD_DS_RUNNING) {
		return txn_cfg_set_error(txn_req, MGMTD_INVALID_PARAM,
					 "Destination DS cannot be any other than RUNNING!");
	}

	if (!txn->commit_cfg_req->req.commit_cfg.src_ds_ctx) {
		return txn_cfg_set_error(txn_req, MGMTD_INVALID_PARAM, "No such source datastore!");
	}

	if (!txn->commit_cfg_req->req.commit_cfg.dst_ds_ctx) {
		return txn_cfg_set_error(txn_req, MGMTD_INVALID_PARAM,
					 "No such destination datastore!");
	}

	if (txn->commit_cfg_req->req.commit_cfg.abort) {
		/*
		 * This is a commit abort request. Return back success.
		 * The reply routing special cases abort, this isn't pretty,
		 * fix in later cleanup.
		 */
		return txn_cfg_set_error(txn->commit_cfg_req, MGMTD_SUCCESS, "commit abort");
	}

	nb_config = mgmt_ds_get_nb_config(txn->commit_cfg_req->req.commit_cfg.src_ds_ctx);
	if (!nb_config) {
		return txn_cfg_set_error(txn_req, MGMTD_INTERNAL_ERROR,
					 "Unable to retrieve Commit DS Config Tree!");
	}

	/*
	 * Validate YANG contents of the source DS and get the diff
	 * between source and destination DS contents.
	 */
	char err_buf[BUFSIZ] = { 0 };

	ret = nb_candidate_validate_yang(nb_config, true, err_buf, sizeof(err_buf) - 1);
	if (ret != NB_OK) {
		if (strncmp(err_buf, " ", strlen(err_buf)) == 0)
			strlcpy(err_buf, "Validation failed", sizeof(err_buf));
		return txn_cfg_set_error(txn_req, MGMTD_INVALID_PARAM, err_buf);
	}

	nb_config_diff(mgmt_ds_get_nb_config(txn->commit_cfg_req->req.commit_cfg.dst_ds_ctx),
		       nb_config, cfg_chgs);
	if (RB_EMPTY(nb_config_cbs, cfg_chgs)) {
		return txn_cfg_set_error(txn_req, MGMTD_NO_CFG_CHANGES,
					 "No changes found to be committed!");
	}
	return 0;
}


/**
 * mgmt_txn_send_commit_config_req() - Send a commit config request
 * @txn_id - A config TXN which must exist.
 *
 * Return: -1 on setup failure -- should immediately handle error, Otherwise 0
 * and will reply to session with any downstream error.
 */
int mgmt_txn_send_commit_config_req(uint64_t txn_id, uint64_t req_id, enum mgmt_ds_id src_ds_id,
				    struct mgmt_ds_ctx *src_ds_ctx, enum mgmt_ds_id dst_ds_id,
				    struct mgmt_ds_ctx *dst_ds_ctx, bool validate_only, bool abort,
				    bool implicit, bool unlock, struct mgmt_edit_req *edit)
{
	struct mgmt_txn_ctx *txn;
	struct mgmt_txn_req *txn_req;
	struct nb_config_cbs changes = { 0 };

	txn = txn_lookup(txn_id);
	assert(txn && txn->type == MGMTD_TXN_TYPE_CONFIG && txn->commit_cfg_req == NULL);

	txn_req = mgmt_txn_req_alloc(txn, req_id, MGMTD_TXN_PROC_COMMITCFG);
	txn_req->req.commit_cfg.src_ds_id = src_ds_id;
	txn_req->req.commit_cfg.src_ds_ctx = src_ds_ctx;
	txn_req->req.commit_cfg.dst_ds_id = dst_ds_id;
	txn_req->req.commit_cfg.dst_ds_ctx = dst_ds_ctx;
	txn_req->req.commit_cfg.validate_only = validate_only;
	txn_req->req.commit_cfg.abort = abort;
	txn_req->req.commit_cfg.implicit = implicit; /* this is only true iff edit */
	txn_req->req.commit_cfg.unlock = unlock; /* this is true for implicit commit in front-end */
	txn_req->req.commit_cfg.edit = edit;
	txn_req->req.commit_cfg.cmt_stats = mgmt_fe_get_session_commit_stats(txn->session_id);

	int ret = txn_cfg_get_changes(txn, &changes);
	if (ret == 0)
		ret = txn_cfg_send_changes(txn, &changes, 0);
	if (ret)
		txn_cfg_finish_commit(txn_req, txn_req->error, txn_req->err_info);
	return 0;
}

int mgmt_txn_send_edit(uint64_t txn_id, uint64_t req_id, enum mgmt_ds_id ds_id,
		       struct mgmt_ds_ctx *ds_ctx, enum mgmt_ds_id commit_ds_id,
		       struct mgmt_ds_ctx *commit_ds_ctx, bool unlock, bool commit,
		       LYD_FORMAT request_type, uint8_t flags, uint8_t operation,
		       const char *xpath, const char *data)
{
	struct mgmt_txn_ctx *txn;
	struct mgmt_edit_req *edit;
	struct nb_config *nb_config;
	char errstr[BUFSIZ];
	int ret;

	txn = txn_lookup(txn_id);
	if (!txn)
		return -1;

	edit = XCALLOC(MTYPE_MGMTD_TXN_REQ, sizeof(struct mgmt_edit_req));

	nb_config = mgmt_ds_get_nb_config(ds_ctx);
	assert(nb_config);

	/* XXX Should we do locking here? */

	ret = nb_candidate_edit_tree(nb_config, operation, request_type, xpath, data,
				     &edit->created, edit->xpath_created, errstr, sizeof(errstr));
	if (ret)
		goto reply;

	if (commit) {
		edit->unlock = unlock;
		if (mgmt_txn_send_commit_config_req(txn_id, req_id, ds_id, ds_ctx, commit_ds_id,
						    commit_ds_ctx, false, false, true /*implicit*/,
						    false /*unlock*/, edit)) {
			ret = NB_ERR;
			goto reply;
		}
		return 0;
	}
reply:
	mgmt_fe_adapter_send_edit_reply(txn->session_id, txn->txn_id, req_id, unlock, commit,
					edit->created, edit->xpath_created,
					errno_from_nb_error(ret), errstr);

	XFREE(MTYPE_MGMTD_TXN_REQ, edit);

	return 0;
}

int mgmt_txn_cfg_client_connect(struct mgmt_be_client_adapter *adapter)
{
	struct mgmt_txn_ctx *txn;
	struct mgmt_txn_req *txn_req;
	struct nb_config_cbs *adapter_cfgs = NULL;
	struct mgmt_ds_ctx *ds_ctx;

	ds_ctx = mgmt_ds_get_ctx_by_id(mm, MGMTD_DS_RUNNING);
	assert(ds_ctx);

	/*
	 * Lock the running datastore to prevent any changes while we
	 * are initializing the backend.
	 */
	if (mgmt_ds_lock(ds_ctx, 0) != 0) {
		_dbg("Failed to lock DS:%s for init of BE adapter '%s'",
		     mgmt_ds_id2name(MGMTD_DS_RUNNING), adapter->name);
		return -1;
	}

	/* Get config for this single backend client */
	mgmt_be_get_adapter_config(adapter, &adapter_cfgs);
	if (!adapter_cfgs || RB_EMPTY(nb_config_cbs, adapter_cfgs)) {
		mgmt_ds_unlock(ds_ctx);
		return 0;
	}

	/*
	 * Create a CONFIG transaction to push the config changes
	 * provided to the backend client.
	 */
	txn = mgmt_txn_create_new(0, MGMTD_TXN_TYPE_CONFIG);
	if (!txn) {
		_log_err("Failed to create CONFIG Transaction for downloading CONFIGs for client '%s'",
			 adapter->name);
		mgmt_ds_unlock(ds_ctx);
		nb_config_diff_del_changes(adapter_cfgs);
		return -1;
	}

	_dbg("Created initial txn-id: %" PRIu64 " for BE client '%s'", txn->txn_id, adapter->name);
	/*
	 * Set the changeset for transaction to commit and trigger the
	 * commit request.
	 */
	memset(&adapter->cfg_stats, 0, sizeof(adapter->cfg_stats));
	txn_req = mgmt_txn_req_alloc(txn, 0, MGMTD_TXN_PROC_COMMITCFG);
	txn_req->req.commit_cfg.src_ds_id = MGMTD_DS_NONE;
	txn_req->req.commit_cfg.src_ds_ctx = 0;
	txn_req->req.commit_cfg.dst_ds_id = MGMTD_DS_RUNNING;
	txn_req->req.commit_cfg.dst_ds_ctx = ds_ctx;
	txn_req->req.commit_cfg.validate_only = false;
	txn_req->req.commit_cfg.abort = false;
	txn_req->req.commit_cfg.init = true;
	txn_req->req.commit_cfg.cmt_stats = &adapter->cfg_stats;

	/*
	 * Apply the initial changes.
	 */
	return txn_cfg_send_changes(txn, adapter_cfgs, 1ull << adapter->id);
}

int mgmt_txn_rollback_trigger_cfg_apply(struct mgmt_ds_ctx *src_ds_ctx,
					struct mgmt_ds_ctx *dst_ds_ctx)
{
	static struct nb_config_cbs changes;
	static struct mgmt_commit_stats dummy_stats;

	struct nb_config_cbs *cfg_chgs = NULL;
	struct mgmt_txn_ctx *txn;
	struct mgmt_txn_req *txn_req;
	int ret;

	memset(&changes, 0, sizeof(changes));
	memset(&dummy_stats, 0, sizeof(dummy_stats));
	/*
	 * This could be the case when the config is directly
	 * loaded onto the candidate DS from a file. Get the
	 * diff from a full comparison of the candidate and
	 * running DSs.
	 */
	nb_config_diff(mgmt_ds_get_nb_config(dst_ds_ctx), mgmt_ds_get_nb_config(src_ds_ctx),
		       &changes);
	cfg_chgs = &changes;

	if (RB_EMPTY(nb_config_cbs, cfg_chgs)) {
		/*
		 * This means there's no changes to commit whatsoever
		 * is the source of the changes in config.
		 */
		return -1;
	}

	/*
	 * Create a CONFIG transaction to push the config changes
	 * provided to the backend client.
	 */
	txn = mgmt_txn_create_new(0, MGMTD_TXN_TYPE_CONFIG);
	if (!txn) {
		_log_err("Failed to create CONFIG Transaction for downloading CONFIGs");
		nb_config_diff_del_changes(cfg_chgs);
		return -1;
	}

	_dbg("Created rollback txn-id: %" PRIu64, txn->txn_id);

	/*
	 * Set the changeset for transaction to commit and trigger the commit
	 * request.
	 */
	txn_req = mgmt_txn_req_alloc(txn, 0, MGMTD_TXN_PROC_COMMITCFG);
	txn_req->req.commit_cfg.src_ds_id = MGMTD_DS_CANDIDATE;
	txn_req->req.commit_cfg.src_ds_ctx = src_ds_ctx;
	txn_req->req.commit_cfg.dst_ds_id = MGMTD_DS_RUNNING;
	txn_req->req.commit_cfg.dst_ds_ctx = dst_ds_ctx;
	txn_req->req.commit_cfg.validate_only = false;
	txn_req->req.commit_cfg.abort = false;
	txn_req->req.commit_cfg.rollback = true;
	txn_req->req.commit_cfg.cmt_stats = &dummy_stats;

	/*
	 * Send the changes.
	 */
	ret = txn_cfg_send_changes(txn, cfg_chgs, 0);
	if (ret)
		txn_cfg_finish_commit(txn_req, txn_req->error, txn_req->err_info);
	return ret;
}
