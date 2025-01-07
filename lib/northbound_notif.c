// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * December 1 2024, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2024, LabN Consulting, L.L.C.
 *
 */
#include <zebra.h>
#include "debug.h"
#include "typesafe.h"
#include "northbound.h"
#include "mgmt_be_client.h"

#define __dbg(fmt, ...)	    DEBUGD(&nb_dbg_notif, "NB_OP_CHANGE: %s: " fmt, __func__, ##__VA_ARGS__)
#define __log_err(fmt, ...) zlog_err("NB_OP_CHANGE: %s: ERROR: " fmt, __func__, ##__VA_ARGS__)

#define NB_NOTIF_TIMER_MSEC (10 * 1000) /* 10 seconds for now, revert to 10msec later */

/*
 * ADDS:
 * - Less specific:
 *   - Any new add will cause more specific pending adds to be dropped and equal
 *     or more specific deletes to be dropped.
 * - More specific:
 *   - Ignore any new add that is the same or more specific than an existing add.
 *   - A new add that is more specific than a delete should change the delete
 *     into an add query (since adds are reported as a replace).
 *
 * DELETES:
 * - Less specific:
 *   - Any new delete will cause more specific pending deletes to be dropped and
 *     equal or more specific adds to be dropped.
 * - More specific:
 *   - Ignore new deletes that are the same or more specific than existing
 *     deletes.
 *   - A new delete that is more specific than an add can be dropped since we
 *     use replacement methodology for the add.
 *
 * One thing we have to pay close attention to is that the state is going to be
 * queried when the notification sent, not when we are told of the change.
 */

DEFINE_MTYPE_STATIC(LIB, OP_CHANGE, "NB Oper Change");
DEFINE_MTYPE_STATIC(LIB, OP_CHANGES_GROUP, "NB Oper Changes Group");
DEFINE_MTYPE_STATIC(LIB, NB_NOTIF_WALK_ARGS, "NB Notify Oper Walk");

struct op_change {
	RB_ENTRY(op_change) link;
	char path[];
};

/*
 * RB tree for op_change
 */
static int op_change_cmp(const struct op_change *e1, const struct op_change *e2);
RB_HEAD(op_changes, op_change);
RB_PROTOTYPE(op_changes, op_change, link, op_change_cmp)
RB_GENERATE(op_changes, op_change, link, op_change_cmp)

struct op_changes nb_notif_adds = RB_INITIALIZER(&nb_notif_adds);
struct op_changes nb_notif_dels = RB_INITIALIZER(&nb_notif_dels);
struct event_loop *nb_notif_master;
struct event *nb_notif_timer;
void *nb_notif_walk;

/*
 * We maintain a queue of change lists one entry per query and notification send
 * action
 */
PREDECL_LIST(op_changes_queue);
struct op_changes_group {
	struct op_changes_queue_item item;
	struct op_changes adds;
	struct op_changes dels;
	struct op_changes *cur_changes; /* used when walking */
	struct op_change *cur_change;	/* "    "     " */
};

DECLARE_LIST(op_changes_queue, struct op_changes_group, item);
static struct op_changes_queue_head op_changes_queue;

struct nb_notif_walk_args {
	struct op_changes_group *group;
	struct lyd_node *tree;
	// struct lyd_node *patch;
	// uint64_t patch_edit_id;
};

static void nb_notif_set_walk_timer(void);


static int pathncmp(const char *s1, const char *s2, size_t n)
{
	size_t i = 0;

	while (i < n && *s1 && *s2) {
		char c1 = *s1;
		char c2 = *s2;

		if ((c1 == '\'' && c2 == '\"') || (c1 == '\"' && c2 == '\'')) {
			s1++;
			s2++;
			i++;
			continue;
		}
		if (c1 != c2)
			return (unsigned char)c1 - (unsigned char)c2;
		s1++;
		s2++;
		i++;
	}
	if (i < n)
		return (unsigned char)*s1 - (unsigned char)*s2;
	return 0;
}

static int pathcmp(const char *s1, const char *s2)
{
	while (*s1 && *s2) {
		char c1 = *s1;
		char c2 = *s2;

		if ((c1 == '\'' && c2 == '\"') || (c1 == '\"' && c2 == '\'')) {
			s1++;
			s2++;
			continue;
		}
		if (c1 != c2)
			return (unsigned char)c1 - (unsigned char)c2;
		s1++;
		s2++;
	}
	return (unsigned char)*s1 - (unsigned char)*s2;
}


static int op_change_cmp(const struct op_change *e1, const struct op_change *e2)
{
	return pathcmp(e1->path, e2->path);
}

static struct op_change *op_change_alloc(const char *path)
{
	struct op_change *note;
	size_t ssize = strlen(path) + 1;

	note = XMALLOC(MTYPE_OP_CHANGE, sizeof(*note) + ssize);
	memset(note, 0, sizeof(*note));
	strlcpy(note->path, path, ssize);

	return note;
}

static void op_change_free(struct op_change *note)
{
	XFREE(MTYPE_OP_CHANGE, note);
}

/**
 * op_changes_group_push() - Save the current set of changes on the queue.
 *
 * This function will save the current set of changes on the queue and
 * initialize a new set of changes.
 */
static void op_changes_group_push(void)
{
	struct op_changes_group *changes;

	if (RB_EMPTY(op_changes, &nb_notif_adds) && RB_EMPTY(op_changes, &nb_notif_dels))
		return;

	__dbg("pushing current oper changes onto queue");

	changes = XCALLOC(MTYPE_OP_CHANGES_GROUP, sizeof(*changes));
	changes->adds = nb_notif_adds;
	changes->dels = nb_notif_dels;
	op_changes_queue_add_tail(&op_changes_queue, changes);

	RB_INIT(op_changes, &nb_notif_adds);
	RB_INIT(op_changes, &nb_notif_dels);
}

static void op_changes_group_free(struct op_changes_group *group)
{
	struct op_change *e, *next;

	RB_FOREACH_SAFE (e, op_changes, &group->adds, next) {
		RB_REMOVE(op_changes, &group->adds, e);
		op_change_free(e);
	}
	RB_FOREACH_SAFE (e, op_changes, &group->dels, next) {
		RB_REMOVE(op_changes, &group->dels, e);
		op_change_free(e);
	}
	XFREE(MTYPE_OP_CHANGES_GROUP, group);
}

static struct op_change *__find_less_specific(struct op_changes *head, struct op_change *note)
{
	struct op_change *e;
	size_t plen;

	/*
	 * RB_NFIND finds equal or greater (more specific) than the key,
	 * so the previous node will be a less specific or no match that
	 * sorts earlier. We want to find when we are a more specific
	 * match.
	 */
	e = RB_NFIND(op_changes, head, note);
	if (e)
		e = RB_PREV(op_changes, e);
	else
		e = RB_MAX(op_changes, head);
	if (!e)
		return NULL;
	plen = strlen(e->path);
	if (pathncmp(e->path, note->path, plen))
		return NULL;
	/* equal would have been returned from RB_NFIND() then we went RB_PREV */
	assert(strlen(note->path) != plen);
	return e;
}

static void __drop_eq_or_more_specific(struct op_changes *head, const char *path, int plen,
				       struct op_change *next)
{
	struct op_change *e;

	for (e = next; e != NULL; e = next) {
		/* if the prefix no longer matches we are done */
		if (pathncmp(path, e->path, plen))
			break;
		__dbg("dropping more specific %s: %s", head == &nb_notif_adds ? "add" : "delete",
		      e->path);
		next = RB_NEXT(op_changes, e);
		RB_REMOVE(op_changes, head, e);
		op_change_free(e);
	}
}

static void __op_change_add_del(const char *path, struct op_changes *this_head,
				struct op_changes *other_head)
{
	/* find out if this has been subsumed or will subsume */

	const char *op = this_head == &nb_notif_adds ? "add" : "delete";
	struct op_change *note = op_change_alloc(path);
	struct op_change *next, *e;
	int plen;

	__dbg("processing oper %s change path: %s", op, path);

	/*
	 * See if we are already covered by a more general `op`.
	 */
	e = __find_less_specific(this_head, note);
	if (e) {
		__dbg("%s path already covered by: %s", op, e->path);
		op_change_free(note);
		return;
	}

	/*
	 * Handle having a less-specific `other op`.
	 */
	e = __find_less_specific(other_head, note);
	if (e) {
		if (this_head == &nb_notif_dels) {
			/*
			 * If we have a less-specific add then drop this
			 * more-specific delete as the add-replace will remove
			 * this missing state.
			 */
			__dbg("delete path already covered add-replace: %s", e->path);
		} else {
			/*
			 * If we have a less-specific delete, convert the delete
			 * to an add, and drop this more-specific add. The new
			 * less-specific add will pick up the more specific add
			 * during the walk and as adds are processed as replaces
			 * any other existing state that was to be deleted will
			 * still be deleted (unless it also returns) by the replace.
			 */
			__dbg("add covered, converting covering delete to add-replace: %s", e->path);
			RB_REMOVE(op_changes, other_head, e);
			__op_change_add_del(e->path, &nb_notif_adds, &nb_notif_dels);
			op_change_free(e);
		}
		op_change_free(note);
		return;
	}

	e = RB_INSERT(op_changes, this_head, note);
	if (e) {
		__dbg("path already in %s tree: %s", op, path);
		op_change_free(note);
		return;
	}

	__dbg("scanning for subsumed or subsuming: %s", path);

	plen = strlen(path);

	next = RB_NEXT(op_changes, note);
	__drop_eq_or_more_specific(this_head, path, plen, next);

	/* Drop exact match or more specific `other op` */
	next = RB_NFIND(op_changes, other_head, note);
	__drop_eq_or_more_specific(other_head, path, plen, next);

	nb_notif_set_walk_timer();
}

static void nb_notif_add(const char *path)
{
	__op_change_add_del(path, &nb_notif_adds, &nb_notif_dels);
}


static void nb_notif_delete(const char *path)
{
	__op_change_add_del(path, &nb_notif_dels, &nb_notif_adds);
}

struct lyd_node *nb_op_update(struct lyd_node *tree, const char *path, const char *value)
{
	struct lyd_node *dnode;
	struct lyd_node *root = tree ?: running_state->dnode;
	const char *abs_path = NULL;


	__dbg("updating path: %s with value: %s", path, value);

	dnode = yang_state_new(root, path, value);

	if (path[0] == '/')
		abs_path = path;
	else {
		abs_path = lyd_path(dnode, LYD_PATH_STD, NULL, 0);
	}

	nb_notif_add(abs_path);

	if (abs_path != path)
		free((char *)abs_path);

	return dnode;
}

void nb_op_update_delete(struct lyd_node *tree, const char *path)
{
	struct lyd_node *root = tree ?: running_state->dnode;
	char *abs_path = NULL;

	__dbg("deleting path: %s", path);

	if (path && path[0] == '/')
		abs_path = (char *)path;
	else {
		assert(tree);
		abs_path = lyd_path(tree, LYD_PATH_STD, NULL, 0);
		if (path) {
			char *tmp = darr_strdup(abs_path);
			free(abs_path);
			abs_path = tmp;
			if (*darr_last(abs_path) != '/')
				darr_in_strcat(abs_path, "/");
			darr_in_strcat(abs_path, path);
		}
	}

	yang_state_delete(root, path);

	nb_notif_delete(abs_path);

	if (abs_path != path) {
		if (path)
			darr_free(abs_path);
		else
			free(abs_path);
	}
}

PRINTFRR(2, 0)
struct lyd_node *nb_op_update_vpathf(struct lyd_node *tree, const char *path_fmt, const char *value,
				     va_list ap)
{
	struct lyd_node *dnode;
	char *path;

	path = darr_vsprintf(path_fmt, ap);
	dnode = nb_op_update(tree, path, value);
	darr_free(path);

	return dnode;
}

struct lyd_node *nb_op_update_pathf(struct lyd_node *tree, const char *path_fmt, const char *value,
				    ...)
{
	struct lyd_node *dnode;
	va_list ap;

	if (tree == NULL)
		tree = running_state->dnode;

	va_start(ap, value);
	dnode = nb_op_update_vpathf(tree, path_fmt, value, ap);
	va_end(ap);

	return dnode;
}

PRINTFRR(2, 0)
void nb_op_update_delete_vpathf(struct lyd_node *tree, const char *path_fmt, va_list ap)
{
	char *path;

	path = darr_vsprintf(path_fmt, ap);
	nb_op_update_delete(tree, path);
	darr_free(path);
}

void nb_op_update_delete_pathf(struct lyd_node *tree, const char *path_fmt, ...)
{
	va_list ap;

	if (tree == NULL)
		tree = running_state->dnode;

	va_start(ap, path_fmt);
	nb_op_update_delete_vpathf(tree, path_fmt, ap);
	va_end(ap);
}


PRINTFRR(3, 0)
struct lyd_node *nb_op_vupdatef(struct lyd_node *tree, const char *path, const char *val_fmt,
				va_list ap)
{
	struct lyd_node *dnode;
	char *value;

	value = darr_vsprintf(val_fmt, ap);
	dnode = nb_op_update(tree, path, value);
	darr_free(value);

	return dnode;
}


struct lyd_node *nb_op_updatef(struct lyd_node *tree, const char *path, const char *val_fmt, ...)
{
	struct lyd_node *dnode;
	va_list ap;

	if (tree == NULL)
		tree = running_state->dnode;

	va_start(ap, val_fmt);
	dnode = nb_op_vupdatef(tree, path, val_fmt, ap);
	va_end(ap);

	return dnode;
}

static struct op_changes_group *op_changes_group_next(void)
{
	struct op_changes_group *group;

	group = op_changes_queue_pop(&op_changes_queue);
	if (!group) {
		op_changes_group_push();
		group = op_changes_queue_pop(&op_changes_queue);
	}
	if (!group)
		return NULL;
	group->cur_changes = &group->dels;
	group->cur_change = RB_MIN(op_changes, group->cur_changes);
	if (!group->cur_change) {
		group->cur_changes = &group->adds;
		group->cur_change = RB_MIN(op_changes, group->cur_changes);
		assert(group->cur_change);
	}
	return group;
}

/* ---------------------------- */
/* Query for changes and notify */
/* ---------------------------- */

static void timer_walk_continue(struct event *event);

#if 0
static int __send_patch_and_free(struct lyd_node **patchp, const char *path)
{
	int err = 0;
	if (*patchp) {
		err = mgmt_be_send_ds_patch_notification("/", *patchp);
		lyd_free_all(*patchp);
		*patchp = NULL;
	}
	return err;
}
#endif

static enum nb_error oper_walk_done(const struct lyd_node *tree, void *arg, enum nb_error ret)
{
	struct nb_notif_walk_args *args = arg;
	struct op_changes_group *group = args->group;
	const char *path = group->cur_change->path;
	const char *op = group->cur_changes == &group->adds ? "add" : "delete";
	// LY_ERR err;

	/* we don't send batches when yielding as we need completed edit in the patch */
	assert(ret != NB_YIELD);

	nb_notif_walk = NULL;

	/* Something went wrong with the walk */
	if (ret != NB_OK) {
error:
		__log_err("error walking oper tree to notify on path: %s: %s", path,
			  nb_err_name(ret));
		XFREE(MTYPE_NB_NOTIF_WALK_ARGS, args);
		/* XXX Need to inform mgmtd/front-ends things are out-of-sync */
		assert(!"Need out-of-sync code, aborting for now");
		return ret;
	}

	__dbg("done with oper-path collection for %s path: %s", op, path);

	/* Do we need this? */
	while (tree->parent)
		tree = lyd_parent(tree);

	/* Send the add (replace) notification */
	if (mgmt_be_send_ds_replace_notification(path, tree)) {
		ret = NB_ERR;
		goto error;
	}

	/*
	 * Advance to next change (either dels or adds or both).
	 */

	group->cur_change = RB_NEXT(op_changes, group->cur_change);
	if (!group->cur_change) {
		__dbg("done with oper-path collection for group");
		op_changes_group_free(group);

		group = op_changes_group_next();
		args->group = group;
		if (!group) {
			__dbg("done with ALL oper-path collection for notification");
			/* err = __send_patch_and_free(&args->patch); */
			/* assert(err == LY_SUCCESS); /\* XXX *\/ */
			XFREE(MTYPE_NB_NOTIF_WALK_ARGS, args);
			goto done;
		}
	}

	event_add_timer_msec(nb_notif_master, timer_walk_continue, args, 0, &nb_notif_timer);
done:
	/* Done with current walk and scheduled next one if there is more */
	nb_notif_walk = NULL;

	return NB_OK;
}

static LY_ERR nb_notify_delete_changes(struct nb_notif_walk_args *args)
{
	struct op_changes_group *group = args->group;
	LY_ERR err;

	group->cur_change = RB_MIN(op_changes, group->cur_changes);
	while (group->cur_change) {
		/* err = yang_patch_append_delete(args->patch, group->cur_change->path, */
		/* 			       &args->patch_edit_id); */
		/* if (err) */
		/*	return (err); */

		err = mgmt_be_send_ds_delete_notification(group->cur_change->path);
		assert(err == LY_SUCCESS); /* XXX */

		group->cur_change = RB_NEXT(op_changes, group->cur_change);
	}

	/* /\* Send the delete patch *\/ */
	/* err = __send_patch_and_free(&args->patch, "/"); */
	/* if (err) */
	/*	return (err); */
	/* err = yang_patch_new("Operational State Patch", &args->patch); */
	/* assert(err == LY_SUCCESS); XXX */
	return LY_SUCCESS;
}

static void timer_walk_continue(struct event *event)
{
	struct nb_notif_walk_args *args = EVENT_ARG(event);
	struct op_changes_group *group = args->group;
	const char *path;
	LY_ERR err;

	/*
	 * Notify about deletes until we have add changes to collect.
	 */
	while (group->cur_changes == &group->dels) {
		err = nb_notify_delete_changes(args);
		assert(err == LY_SUCCESS);  /* XXX */
		assert(!group->cur_change); /* we send all the deletes in one message */

		/* after deletes advance to adds */
		group->cur_changes = &group->adds;
		group->cur_change = RB_MIN(op_changes, group->cur_changes);
		if (group->cur_change)
			break;

		__dbg("done with oper-path change group");
		op_changes_group_free(group);

		group = op_changes_group_next();
		args->group = group;
		if (!group) {
			__dbg("done with ALL oper-path changes");
			/* err = __send_patch_and_free(&args->patch); */
			/* assert(err == LY_SUCCESS); /\* XXX *\/ */
			XFREE(MTYPE_NB_NOTIF_WALK_ARGS, args);
			return;
		}
	}

	path = group->cur_change->path;
	__dbg("starting next oper-path replace walk for path: %s", path);
	nb_notif_walk = nb_oper_walk(path, NULL, 0, false, NULL, NULL, oper_walk_done, args);
}

static void timer_walk_start(struct event *event)
{
	struct op_changes_group *group;
	struct nb_notif_walk_args *args;
	// LY_ERR err;

	__dbg("oper-state change notification timer fires");

	group = op_changes_group_next();
	if (!group) {
		__dbg("no oper changes to notify");
		return;
	}

	args = XCALLOC(MTYPE_NB_NOTIF_WALK_ARGS, sizeof(*args));
	args->group = group;

	/* err = yang_patch_new("Operational State Patch", &args->patch); */
	/* assert(err == LY_SUCCESS); */

	EVENT_ARG(event) = args;
	timer_walk_continue(event);
}

static void nb_notif_set_walk_timer(void)
{
	if (nb_notif_walk) {
		__dbg("oper-state walk already in progress.");
		return;
	}
	if (event_is_scheduled(nb_notif_timer)) {
		__dbg("oper-state notification timer already set.");
		return;
	}

	__dbg("oper-state notification setting timer to fire in: %d msec ", NB_NOTIF_TIMER_MSEC);
	event_add_timer_msec(nb_notif_master, timer_walk_start, NULL, NB_NOTIF_TIMER_MSEC,
			     &nb_notif_timer);
}

void nb_notif_init(struct event_loop *tm)
{
	nb_notif_master = tm;
	op_changes_queue_init(&op_changes_queue);
}

void nb_notif_terminate(void)
{
	struct nb_notif_walk_args *args;
	struct op_changes_group *group;

	EVENT_OFF(nb_notif_timer);

	if (nb_notif_walk) {
		nb_oper_cancel_walk(nb_notif_walk);
		/* need to free the group that's in the walk */
		args = nb_oper_walk_finish_arg(nb_notif_walk);
		if (args)
			op_changes_group_free(args->group);
		nb_notif_walk = NULL;
	}

	while ((group = op_changes_group_next()))
		op_changes_group_free(group);
}
