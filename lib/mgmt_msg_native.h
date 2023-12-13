// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * June 29 2023, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2023, LabN Consulting, L.L.C.
 *
 */

#ifndef _FRR_MGMT_MSG_NATIVE_H_
#define _FRR_MGMT_MSG_NATIVE_H_

#ifdef __cplusplus
extern "C" {
#elif 0
}
#endif

#include <zebra.h>
#include "compiler.h"
#include "memory.h"
#include "mgmt_msg.h"
#include "mgmt_defines.h"

#include <stdalign.h>

DECLARE_MTYPE(MSG_NATIVE_MSG);
DECLARE_MTYPE(MSG_NATIVE_ERROR);

/*
 * Adding New Messages Types
 * -------------------------
 *
 * Native messages structs have 2 simple rules:
 *
 * 1) All fields should be naturally aligned.
 * 2) Any required padding should be explicitly reserved.
 *
 * This is so for all intents and purposes the messages may be read and written
 * direct from "the wire", easily, using common programming languages (e.g.,
 * C, rust, go, python, ...)
 *
 * Additionally by design fixed fields precede the variable length data which
 * comes at the end. The zero length arrays fields are aligned such that this is so:
 *
 *    sizeof(struct mgmt_msg_foo) == offsetof(struct mgmt_msg_foo, field)
 *
 * This allows things like `value = (HDR + 1)` to work.
 */

/*
 * Native message codes
 */
#define MGMT_MSG_CODE_ERROR	0
#define MGMT_MSG_CODE_GET_TREE	1
#define MGMT_MSG_CODE_TREE_DATA 2

/**
 * struct mgmt_msg_header - Header common to all native messages.
 *
 * @code: the actual type of the message.
 * @resv: Set to zero, ignore on receive.
 * @vsplit: If a variable section is split in 2, the length of first part.
 * @refer_id: the session, txn, conn, etc, this message is associated with.
 * @req_id: the request this message is for.
 */
struct mgmt_msg_header {
	uint16_t code;
	uint16_t resv;
	uint32_t vsplit;
	uint64_t refer_id;
	uint64_t req_id;
};
_Static_assert(sizeof(struct mgmt_msg_header) == 3 * 8, "Bad padding");
_Static_assert(sizeof(struct mgmt_msg_header) ==
		       offsetof(struct mgmt_msg_header, req_id) +
			       sizeof(((struct mgmt_msg_header *)0)->req_id),
	       "Size mismatch");

/**
 * struct mgmt_msg_error - Common error message.
 * @error: An error value.
 * @errst: Description of error can be 0 length.
 *
 * This common error message can be used for replies for many msg requests
 * (req_id).
 */
struct mgmt_msg_error {
	struct mgmt_msg_header;
	int16_t error;
	uint8_t resv2[6];

	alignas(8) char errstr[];
};
_Static_assert(sizeof(struct mgmt_msg_error) ==
		       offsetof(struct mgmt_msg_error, errstr),
	       "Size mismatch");

/**
 * struct mgmt_msg_get_tree - Message carrying xpath query request.
 * @result_type: ``LYD_FORMAT`` for the returned result.
 * @xpath: the query for the data to return.
 */
struct mgmt_msg_get_tree {
	struct mgmt_msg_header;
	uint8_t result_type;
	uint8_t resv2[7];

	alignas(8) char xpath[];
};
_Static_assert(sizeof(struct mgmt_msg_get_tree) ==
		       offsetof(struct mgmt_msg_get_tree, xpath),
	       "Size mismatch");

/**
 * struct mgmt_msg_tree_data - Message carrying tree data.
 * @partial_error: If the full result could not be returned do to this error.
 * @result_type: ``LYD_FORMAT`` for format of the @result value.
 * @more: if this is a partial return and there will be more coming.
 * @result: The tree data in @result_type format.
 *
 */
struct mgmt_msg_tree_data {
	struct mgmt_msg_header;
	int8_t partial_error;
	uint8_t result_type;
	uint8_t more;
	uint8_t resv2[5];

	alignas(8) uint8_t result[];
};
_Static_assert(sizeof(struct mgmt_msg_tree_data) ==
		       offsetof(struct mgmt_msg_tree_data, result),
	       "Size mismatch");

#define MGMT_MSG_VALIDATE_NUL_TERM(msgp, len)                                  \
	((len) >= sizeof(*msg) + 1 && ((char *)msgp)[(len)-1] == 0)


/**
 * Send a native message error to the other end of the connection.
 *
 * This function is normally used by the server-side to indicate a failure to
 * process a client request. For this server side handling of client messages
 * which expect a reply, either that reply or this error should be returned, as
 * closing the connection is not allowed during message handling.
 *
 * Args:
 *	conn: the connection.
 *	sess_or_txn_id: Session ID (to FE client) or Txn ID (from BE client)
 *	req_id: which req_id this error is associated with.
 *	short_circuit_ok: if short circuit sending is OK.
 *	error: the error value
 *	errfmt: vprintfrr style format string
 *	ap: the variable args for errfmt.
 *
 * Return:
 *	The return value of ``msg_conn_send_msg``.
 */
extern int vmgmt_msg_native_send_error(struct msg_conn *conn,
				       uint64_t sess_or_txn_id, uint64_t req_id,
				       bool short_circuit_ok, int16_t error,
				       const char *errfmt, va_list ap)
	PRINTFRR(6, 0);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_MGMT_MSG_NATIVE_H_ */
