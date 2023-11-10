// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * October 14 2023, Christian Hopps <chopps@labn.net>
 *
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
 * Copyright (c) 2023, LabN Consulting, L.L.C.
 *
 */

#include <zebra.h>
#include "darr.h"
#include "debug.h"
#include "frrevent.h"
#include "frrstr.h"
#include "lib_errors.h"
#include "monotime.h"
#include "northbound.h"

/*
 * YANG model yielding design restrictions:
 *
 * In order to be able to yield and guarantee we have a valid data tree at the
 * point of yielding we must know that each parent has all it's siblings
 * collected to represent a complete element.
 *
 * Basically, there should be a only single branch in the schema tree that
 * supports yielding. In practice this means:
 *
 * list node schema with lookup next:
 * - must not have any lookup-next list node sibling schema
 * - must not have any list or container node siblings with lookup-next descendants.
 * - any parent list nodes must also be lookup-next list nodes
 *
 * We must also process containers with lookup-next descendants last.
 */

DEFINE_MTYPE_STATIC(LIB, NB_YIELD_STATE, "NB Yield State");
DEFINE_MTYPE_STATIC(LIB, NB_XPATH, "NB XPath String");

/* Amount of time allowed to spend constructing oper-state prior to yielding */
#define NB_OP_WALK_INTERVAL_MS 50
#define NB_OP_WALK_INTERVAL_US (NB_OP_WALK_INTERVAL_MS * 1000)

/* ---------- */
/* Data Types */
/* ---------- */
PREDECL_LIST(nb_op_walks);

/*
 * This is our information about a node on the branch we are looking at
 */
struct nb_op_node_info {
	struct lyd_node_inner *inner;
	const struct lysc_node *schema; /* inner schema in case we rm inner */
	struct yang_list_keys keys;	/* if list, keys to locate element */
	const void *list_entry;		/* opaque entry from user or NULL */
	uint xpath_len;		  /* length of the xpath string for this node */
	uint niters;		  /* # list elems create this iteration */
	uint nents;		  /* # list elems create so far */
	bool has_lookup_next : 1; /* if this node support lookup next */
	bool lookup_next_ok : 1;  /* if this and all previous support */
};

struct nb_op_yield_state {
	char *xpath;
	char *xpath_orig;
	struct nb_op_node_info *node_infos;
	int walk_root_level;
	bool query_list_entry; /* query was for a specific list entry */
	bool query_did_entry;  /* currently processing the entry */
	bool should_batch;
	struct timeval start_time;
	struct yang_translator *translator;
	uint32_t flags;
	nb_oper_data_cb cb;
	void *cb_arg;
	nb_oper_data_finish_cb finish;
	void *finish_arg;
	struct event *walk_ev;
	struct nb_op_walks_item link;
};

DECLARE_LIST(nb_op_walks, struct nb_op_yield_state, link);

/* ---------------- */
/* Global Variables */
/* ---------------- */

static struct event_loop *event_loop;
static struct nb_op_walks_head nb_op_walks;

/* --------------------- */
/* Function Declarations */
/* --------------------- */

static enum nb_error nb_op_yield(struct nb_op_yield_state *ys);
static struct lyd_node *ys_root_node(struct nb_op_yield_state *ys);

/* -------------------- */
/* Function Definitions */
/* -------------------- */

static inline struct nb_op_yield_state *
nb_op_create_yield_state(const char *xpath, struct yang_translator *translator,
			 uint32_t flags, bool should_batch, nb_oper_data_cb cb,
			 void *cb_arg, nb_oper_data_finish_cb finish,
			 void *finish_arg)
{
	struct nb_op_yield_state *ys;

	ys = XCALLOC(MTYPE_NB_YIELD_STATE, sizeof(*ys));
	ys->xpath = darr_strdup_cap(xpath, (size_t)XPATH_MAXLEN);
	ys->xpath_orig = XSTRDUP(MTYPE_NB_XPATH, xpath);
	ys->translator = translator;
	ys->flags = flags;
	ys->should_batch = should_batch;
	ys->cb = cb;
	ys->cb_arg = cb_arg;
	ys->finish = finish;
	ys->finish_arg = finish_arg;

	nb_op_walks_add_tail(&nb_op_walks, ys);

	return ys;
}

static inline void nb_op_free_yield_state(struct nb_op_yield_state *ys,
					  bool nofree_tree)
{
	if (ys) {
		EVENT_OFF(ys->walk_ev);
		nb_op_walks_del(&nb_op_walks, ys);
		/* if we have a branch then free up it's libyang tree */
		if (!nofree_tree && ys_root_node(ys))
			lyd_free_all(ys_root_node(ys));
		darr_free(ys->xpath);
		darr_free(ys->node_infos);
		XFREE(MTYPE_NB_XPATH, ys->xpath_orig);
		XFREE(MTYPE_NB_YIELD_STATE, ys);
	}
}

static const struct lysc_node *ys_base_schema_node(struct nb_op_yield_state *ys)
{
	if (ys->walk_root_level == -1)
		return NULL;
	return ys->node_infos[ys->walk_root_level].schema;
}

static struct lyd_node *ys_root_node(struct nb_op_yield_state *ys)
{
	if (!darr_len(ys->node_infos))
		return NULL;
	return &ys->node_infos[0].inner->node;
}

static void ys_trim_xpath(struct nb_op_yield_state *ys)
{
	uint len = darr_len(ys->node_infos);

	if (len == 0)
		darr_setlen(ys->xpath, 1);
	else
		darr_setlen(ys->xpath, darr_last(ys->node_infos)->xpath_len + 1);
	ys->xpath[darr_len(ys->xpath) - 1] = 0;
}

static void ys_pop_inner(struct nb_op_yield_state *ys)
{
	uint len = darr_len(ys->node_infos);

	assert(len);
	darr_setlen(ys->node_infos, len - 1);
	ys_trim_xpath(ys);
}

static void nb_op_get_keys(struct lyd_node_inner *list_node,
			   struct yang_list_keys *keys)
{
	struct lyd_node *child;
	uint n = 0;

	keys->num = 0;
	LY_LIST_FOR (list_node->child, child) {
		if (!lysc_is_key(child->schema))
			break;
		strlcpy(keys->key[n], yang_dnode_get_string(child, NULL),
			sizeof(keys->key[n]));
		n++;
	}

	keys->num = n;
}

/**
 * __move_back_to_next() - move back to the next lookup-next schema
 */
static bool __move_back_to_next(struct nb_op_yield_state *ys, int i)
{
	struct nb_op_node_info *ni;
	int j;

	/*
	 * We will free the subtree we are trimming back to, or we will be done
	 * with the walk and will free the root on cleanup.
	 */

	/* pop any node_info we dropped below on entry */
	for (j = darr_ilen(ys->node_infos) - 1; j > i; j--)
		ys_pop_inner(ys);

	for (; i >= ys->walk_root_level; i--) {
		if (ys->node_infos[i].has_lookup_next)
			break;
		ys_pop_inner(ys);
	}

	if (i < ys->walk_root_level)
		return false;

	ni = &ys->node_infos[i];

	/*
	 * The i'th node has been lost after a yield so trim it from the tree
	 * now.
	 */
	lyd_free_tree(&ni->inner->node);
	ni->inner = NULL;
	ni->list_entry = NULL;

	/*
	 * Leave the empty-of-data node_info on top, __walk will deal with
	 * this, by doing a lookup-next with the keys which we still have.
	 */

	return true;
}

static void __free_siblings(struct lyd_node *this)
{
	struct lyd_node *next, *sib;
	uint count = 0;

	LY_LIST_FOR_SAFE(lyd_first_sibling(this), next, sib)
	{
		if (lysc_is_key(sib->schema))
			continue;
		if (sib == this)
			continue;
		lyd_free_tree(sib);
		count++;
	}
	DEBUGD(&nb_dbg_events, "NB oper-state: deleted %u siblings", count);
}

/*
 * Trim Algorithm:
 *
 * Delete final lookup-next list node and subtree, leave stack slot with keys.
 *
 * Then walking up the stack, delete all siblings except:
 * 1. right-most container or list node (must be lookup-next by design)
 * 2. keys supporting existing parent list node.
 *
 * NOTE the topmost node on the stack will be the final lookup-nexxt list node,
 * as we only yield on lookup-next list nodes.
 *
 */
static void nb_op_trim_yield_state(struct nb_op_yield_state *ys)
{
	struct nb_op_node_info *ni;
	int i = darr_lasti(ys->node_infos);

	assert(i >= 0);

	DEBUGD(&nb_dbg_events, "NB oper-state: start trimming: top: %d", i);

	ni = &ys->node_infos[i];
	assert(ni->has_lookup_next);

	DEBUGD(&nb_dbg_events, "NB oper-state: deleting tree at level %d", i);
	__free_siblings(&ni->inner->node);
	lyd_free_tree(&ni->inner->node);
	ni->inner = NULL;

	while (--i > 0) {
		DEBUGD(&nb_dbg_events, "NB oper-state: deleting siblings at level: %d", i);
		__free_siblings(&ys->node_infos[i].inner->node);

	}
	DEBUGD(&nb_dbg_events, "NB oper-state: stop trimming: new top: %d",
	       (int)darr_lasti(ys->node_infos));
}

static void nb_op_resume_data_tree(struct nb_op_yield_state *ys)
{
	struct nb_op_node_info *ni;
	struct nb_node *nn;
	const void *parent_entry;
	const void *list_entry;
	uint i;

	/*
	 * IMPORTANT: On yielding: we always yield after the initial list
	 * element has been created and handled, so the top of the yield stack
	 * will always point at a list node.
	 *
	 * Additionally, that list node has been processed and was in the
	 * process of being "get_next"d when we yielded. We process the
	 * lookup-next list node last so all the rest of the data (to the left)
	 * has been gotten. NOTE: To keep this simple we will require only a
	 * single lookup-next sibling in any parents list of children.
	 *
	 * Walk the rightmost branch from base to tip verifying all list nodes
	 * are still present. If not we backup to the node which has a lookup
	 * next, and we prune the branch to this node. If the list node that
	 * went away is the topmost we will be using lookup_next, but if it's a
	 * parent then our list_item was restored.
	 */

	/* XXX: batching support, if we sent a batch during the previous yield,
	 * then we need to prune all list entries prior to the topmost one when
	 * restoring the walk.
	 */
	darr_foreach_i (ys->node_infos, i) {
		ni = &ys->node_infos[i];
		nn = ni->schema->priv;

		if (CHECK_FLAG(ni->schema->nodetype, LYS_CONTAINER))
			continue;

		assert (ni->list_entry != NULL ||
			ni == darr_last(ys->node_infos));

		/* Verify the entry is still present */
		parent_entry = (i == 0 ? NULL : ni[-1].list_entry);
		list_entry = nb_callback_lookup_entry(nn, parent_entry,
						      &ni->keys);
		if (!list_entry || list_entry != ni->list_entry) {
			/* May be NULL or a different pointer
			 * move back to first of
			 * container with last lookup_next list node
			 * (which may be this one) and get next.
			 */
			if (!__move_back_to_next(ys, i))
				DEBUGD(&nb_dbg_events,
				       "%s: Nothing to resume after delete during walk (yield)",
				       __func__);
			return;
		}
	}
}

/*
 * Can only yield if all list nodes to root have lookup_next() callbacks
 *
 * In order to support lookup_next() the list_node get_next() callback
 * needs to return ordered (i.e., sorted) results.
 */

static int nb_op_xpath_dirname(char *xpath)
{
	int len = strlen(xpath);
	bool abs = xpath[0] == '/';
	char *slash;

	/* "//" or "/" => NULL */
	if (abs && (len == 1 || (len = 2 && xpath[1] == '/')))
		return NB_ERR_NOT_FOUND;
	slash = (char *)frrstr_back_to_char(xpath, '/');
	/* "/foo/bar/" or "/foo/bar//" => "/foo " */
	if (slash && slash == &xpath[len - 1]) {
		xpath[--len] = 0;
		slash = (char *)frrstr_back_to_char(xpath, '/');
		if (slash && slash == &xpath[len - 1]) {
			xpath[--len] = 0;
			slash = (char *)frrstr_back_to_char(xpath, '/');
		}
	}
	if (!slash)
		return NB_ERR_NOT_FOUND;
	*slash = 0;
	return NB_OK;
}

static enum nb_error nb_op_xpath_to_tree(const char *xpath_in,
					 struct lyd_node **dnode,
					 bool is_top_node_list)
{
	/* Eventually this function will loop until it finds a concrete path */
	char *xpath;
	LY_ERR err;
	enum nb_error ret;

	err = lyd_new_path2(NULL, ly_native_ctx, xpath_in, NULL, 0, 0,
			    LYD_NEW_PATH_UPDATE, NULL, dnode);
	if (err == LY_SUCCESS)
		return NB_OK;
	if (!is_top_node_list)
		return NB_ERR_NOT_FOUND;

	xpath = XSTRDUP(MTYPE_TMP, xpath_in);
	ret = nb_op_xpath_dirname(xpath);
	if (ret != NB_OK)
		goto done;

	err = lyd_new_path2(NULL, ly_native_ctx, xpath, NULL, 0, 0,
			    LYD_NEW_PATH_UPDATE, NULL, dnode);
	if (err != LY_SUCCESS)
		ret = NB_ERR_NOT_FOUND;
done:
	XFREE(MTYPE_TMP, xpath);
	return ret;
}

/*
 * XXX If we don't find a specific list entry, fine move on. The first time this
 * happens record the walk base there.
 */

static enum nb_error nb_op_init_data_tree(const char *xpath,
					  struct nb_op_node_info **ninfop,
					  bool last_snode_is_list, bool yield_ok)
{
	char tmp[XPATH_MAXLEN];
	struct nb_op_node_info *ninfo = NULL;
	struct nb_op_node_info *ni;
	struct lyd_node_inner *inner;
	struct lyd_node *node;
	enum nb_error ret;
	uint i, len;

	ret = nb_op_xpath_to_tree(xpath, &node, last_snode_is_list);
	if (ret || !node) {
		flog_warn(EC_LIB_LIBYANG,
			  "%s: can't instantiate concrete path using xpath: %s",
			  __func__, xpath);
		if (!ret)
			ret = NB_ERR_NOT_FOUND;
		return ret;
	}
	assert(CHECK_FLAG(node->schema->nodetype, LYS_CONTAINER | LYS_LIST));

	/*
	 * We want to walk the rightmost branch from base to tip.
	 */

	inner = (struct lyd_node_inner *)node;
	for (len = 1; inner->parent; len++)
		inner = inner->parent;

	inner = (struct lyd_node_inner *)node;
	darr_ensure_i(ninfo, len - 1);
	for (i = len; i > 0; i--, inner = inner->parent) {
		ni = &ninfo[i - 1];
		memset(ni, 0, sizeof(*ni));
		ni->inner = inner;
		ni->schema = inner->schema;
		/*
		 * NOTE: we could build this by hand with a litte more effort,
		 * but this simple implementation works and won't be expensive
		 * since the number of nodes is small and only done once per
		 * query.
		 */
		yang_dnode_get_path(&inner->node, tmp, sizeof(tmp));
		ni->xpath_len = strlen(tmp);
	}

	darr_foreach_i (ninfo, i) {
		struct nb_node *nn;

		ni = &ninfo[i];
		inner = ni->inner;
		nn = ni->schema->priv;

		ni->has_lookup_next = nn->cbs.lookup_next != NULL;
		ni->list_entry = i == 0 ? NULL : ni[-1].list_entry;

		/* Assert that we are walking the rightmost branch */
		assert(!inner->parent ||
		       &inner->node == inner->parent->child->prev);

		if (CHECK_FLAG(inner->schema->nodetype, LYS_CONTAINER)) {
			/* containers have only zero or one child on a branch of a tree */
			inner = (struct lyd_node_inner *)inner->child;
			assert(!inner || inner->prev == &inner->node);
			ni->lookup_next_ok = yield_ok &&
					     (i == 0 ||
					      (i > 0 && ni[-1].lookup_next_ok));
			continue;
		}
		assert(CHECK_FLAG(inner->schema->nodetype, LYS_LIST));

		ni->lookup_next_ok = yield_ok &&
				     (ni->has_lookup_next || i == 0 ||
				      (i > 0 && ni[-1].lookup_next_ok));

		nb_op_get_keys(inner, &ni->keys);
		if (ni->keys.num != yang_snode_num_keys(inner->schema)) {
			flog_warn(EC_LIB_NB_OPERATIONAL_DATA,
				  "%s: internal list entry '%s' missing required key values predicates in xpath: %s",
				  __func__, inner->schema->name, xpath);
			ret = NB_ERR_NOT_FOUND;
			goto fail;
		}

		/* Get the opaque list entry pointer -- XX what about keyless lists? */

		if (!nn->cbs.lookup_entry) {
			flog_warn(EC_LIB_NB_OPERATIONAL_DATA,
				  "%s: data path doesn't support iteration over operational data: %s",
				  __func__, xpath);
			ret = NB_ERR_NOT_FOUND;
			goto fail;
		}
		ni->list_entry = nb_callback_lookup_entry(nn, ni->list_entry,
							  &ni->keys);
		if (ni->list_entry == NULL) {
			flog_warn(EC_LIB_NB_OPERATIONAL_DATA,
				  "%s: list entry lookup failed", __func__);
			ret = NB_ERR_NOT_FOUND;
			goto fail;
		}
	}

	*ninfop = ninfo;
	return NB_OK;
fail:
	darr_free(ninfo);
	*ninfop = NULL;
	return ret;
}

/**
 * nb_op_add_leaf() - Add leaf data to the get tree results
 * @ys - the yield state for this tree walk.
 * @nb_node - the northbound node representing this leaf.
 * @xpath - the xpath (with key predicates) to this leaf value.
 *
 * Return: northbound return value (enum nb_error)
 */
static enum nb_error nb_op_iter_leaf(struct nb_op_yield_state *ys,
				     const struct nb_node *nb_node,
				     const char *xpath)
{
	const struct lysc_node *snode = nb_node->snode;
	struct nb_op_node_info *ni = darr_last(ys->node_infos);
	struct yang_data *data;
	enum nb_error ret = NB_OK;
	LY_ERR err;

	if (CHECK_FLAG(snode->flags, LYS_CONFIG_W))
		return NB_OK;

	/* Ignore list keys. */
	if (lysc_is_key(snode))
		return NB_OK;

	data = nb_callback_get_elem(nb_node, xpath, ni->list_entry);
	if (data == NULL)
		return NB_OK;

	/* Add a dnode to our tree */
	err = lyd_new_term(&ni->inner->node, snode->module, snode->name,
			   data->value, false, NULL);
	if (err) {
		yang_data_free(data);
		return NB_ERR_RESOURCE;
	}

	if (ys->cb)
		ret = (*ys->cb)(nb_node->snode, ys->translator, data,
				ys->cb_arg);
	yang_data_free(data);

	return ret;
}

static enum nb_error nb_op_iter_leaflist(struct nb_op_yield_state *ys,
					 const struct nb_node *nb_node,
					 const char *xpath)
{
	const struct lysc_node *snode = nb_node->snode;
	struct nb_op_node_info *ni = darr_last(ys->node_infos);
	const void *list_entry = NULL;
	enum nb_error ret = NB_OK;
	LY_ERR err;

	if (CHECK_FLAG(snode->flags, LYS_CONFIG_W))
		return NB_OK;

	do {
		struct yang_data *data;

		list_entry = nb_callback_get_next(nb_node, ni->list_entry,
						  list_entry);
		if (!list_entry)
			/* End of the list. */
			break;

		data = nb_callback_get_elem(nb_node, xpath, list_entry);
		if (data == NULL)
			continue;

		/* Add a dnode to our tree */
		err = lyd_new_term(&ni->inner->node, snode->module, snode->name,
				   data->value, false, NULL);
		if (err) {
			yang_data_free(data);
			return NB_ERR_RESOURCE;
		}

		if (ys->cb)
			ret = (*ys->cb)(nb_node->snode, ys->translator, data,
					ys->cb_arg);
		yang_data_free(data);
	} while (ret == NB_OK && list_entry);

	return ret;
}

/** nb_op_empty_container_ok() - determine if should keep empty container node.
 *
 * Return: true if the empty container should be kept.
 */
static bool nb_op_empty_container_ok(const struct lysc_node *snode,
				     const char *xpath, const void *list_entry)
{
	struct nb_node *nn = snode->priv;
	struct yang_data *data;

	if (!CHECK_FLAG(snode->flags, LYS_PRESENCE))
		return false;

	if (!nn->cbs.get_elem)
		return false;

	data = nb_callback_get_elem(nn, xpath, list_entry);
	if (data) {
		yang_data_free(data);
		return true;
	}
	return false;
}

/**
 * nb_op_get_child_path() - add child node name to the xpath.
 * @xpath_parent - a darr string for the parent node.
 * @schild - the child schema node.
 * @xpath_child - a previous return value from this function to reuse.
 */
static char *nb_op_get_child_path(const char *xpath_parent,
				  const struct lysc_node *schild,
				  char *xpath_child)
{
	/* "/childname" */
	uint space, extra = strlen(schild->name) + 1;
	bool new_mod = (!schild->parent ||
			schild->parent->module != schild->module);
	int n;

	if (new_mod)
		/* "modulename:" */
		extra += strlen(schild->module->name) + 1;
	space = darr_len(xpath_parent) + extra;

	darr_in_strdup_cap(xpath_child, xpath_parent, space);
	if (new_mod)
		n = snprintf(darr_strnul(xpath_child), extra + 1, "/%s:%s",
			     schild->module->name, schild->name);
	else
		n = snprintf(darr_strnul(xpath_child), extra + 1, "/%s",
			     schild->name);
	assert(n == (int)extra);
	_darr_len(xpath_child) += extra;
	return xpath_child;
}

static bool __is_yielding_node(const struct lysc_node *snode)
{
	struct nb_node *nn = snode->priv;
	return nn->cbs.lookup_next != NULL;
}

static const struct lysc_node *__sib_next(bool yn, const struct lysc_node *sib)
{
	for (; sib; sib = sib->next)
		if (yn == __is_yielding_node(sib))
			return sib;
	return NULL;
}

/*
 * Walk all non-yielding siblings, before the yielding one[s].
 */
static const struct lysc_node *nb_op_sib_next(const struct lysc_node *sib)
{
	struct lysc_node *parent = sib->parent;
	bool yn = __is_yielding_node(sib);

	sib = sib->next;
	while (true) {
		sib = __sib_next(yn, sib);
		if (sib)
			return sib;
		if (yn)
			return NULL;
		yn = true;
		sib = lysc_node_child(parent);
	}
	/*NOTREACHED*/
	return NULL;
}

static const struct lysc_node *nb_op_sib_first(struct nb_op_yield_state *ys,
					       const struct lysc_node *parent,
					       bool skip_keys)
{
	const struct lysc_node *sib = lysc_node_child(parent);
	const struct lysc_node *first_sib;
	bool yn;

	/* Simple case the user has narrowed the path selection. */
	if (darr_len(ys->schema_path) > darr_len(ys->node_infos))
		return ys->schema_path[darr_len(ys->node_infos)];

	if (skip_keys)
		while (sib && lysc_is_key(sib))
			sib = sib->next;
	if (!sib)
		return NULL;

	first_sib = sib;
	yn = __is_yielding_node(sib);
	while (true) {
		sib = __sib_next(yn, first_sib);
		if (sib)
			return sib;
		if (yn)
			return NULL;
		yn = true;
	}
	/*NOTREACHED*/
	return NULL;
}

/*
 * "3-dimensional" walk from base of the tree to the tip in-order.
 *
 * The actual tree is only 2-dimensional as list nodes are organized as adjacent
 * siblings under a common parent perhaps with other siblings to each side;
 * however, the method of fetching list entries using callbacks lends itself to the
 * 3d view.
 *
 * We visit all leaf as well as list node children that lack lookup_next
 * before we visit/descend on list children with lookup_next(). That way
 * we have the fullest tree possible even when something is deleted during
 * yielding.
 *                             --- child/parent descendant pointers
 *                             ... next/prev sibling pointers
 *                             o.o list entries pointers
 *                             ~~~ diagram extension connector
 *          1
 *         / \
 *        /   \         o~~~~12
 *       /     \      .      / \
 *      2.......5   o~~~9  13...14
 *     / \      | .    / \
 *    3...4     6    10...11      Cont Nodes: 1,2,5
 *             / \                List Nodes: 6,9,12
 *            7...8               Leaf Nodes: 3,4,7,8,10,11,13,14
 *                             Schema Leaf A: 3
 *                             Schema Leaf B: 4
 *                             Schema Leaf C: 7,10,13
 *                             Schema Leaf D: 8,11,14
 */
static enum nb_error __walk(struct nb_op_yield_state *ys, bool is_resume)
{
	const struct lysc_node *walk_base_snode = ys_base_schema_node(ys);
	const struct lysc_node *sib;
	const void *parent_list_entry = NULL;
	const void *list_entry = NULL;
	struct nb_op_node_info *ni, *pni;
	struct lyd_node *node;
	struct nb_node *nn;
	bool at_base_level, list_start;
	enum nb_error ret = NB_OK;
	LY_ERR err;
	uint len;


	monotime(&ys->start_time);

	/* Don't currently support walking all root nodes */
	if (!walk_base_snode)
		return NB_ERR_NOT_FOUND;

	/*
	 * If we are resuming then start with the list container on top.
	 * Otherwise if this is a direct query of a list element
	 * start with it. Otherwise get the first child of the container we are
	 * walking, starting with non-yielding children.
	 */
	if (is_resume)
		sib = darr_last(ys->node_infos)->schema;
	else if (ys->query_list_entry)
		sib = walk_base_snode;
	else {
		/* Start with non-yielding children first. */
		sib = lysc_node_child(walk_base_snode);
		sib = __sib_next(false, sib);
		if (!sib)
			sib = lysc_node_child(walk_base_snode);
	}

	char *xpath_child = NULL;
	while (true) {
		/* Grab the top container/list/uses node info on the stack */
		ni = darr_last(ys->node_infos);

		at_base_level = (darr_ilen(ys->node_infos) - 1) ==
				ys->walk_root_level;

		if (!sib) {
			/*
			 * We've reached the end of the siblings inside a
			 * containing node; either a container or a specific
			 * list node entry.
			 *
			 * We handle container node inline; however, for lists
			 * we are only done with a specific entry and need to
			 * move to the next element on the list so we drop down
			 * into the switch for that case.
			 */

			/* Grab the containing node. */
			sib = ni->schema;

			if (sib->nodetype == LYS_CONTAINER) {
				/* If we added an empty container node (no
				 * children) and it's not a presence container
				 * or it's not backed by the get_elem callback,
				 * remove the node from the tree.
				 */
				if (!lyd_child(&ni->inner->node) &&
				    !nb_op_empty_container_ok(sib, ys->xpath,
							      ni->list_entry))
					lyd_free_tree(&ni->inner->node);

				/* If we have returned to our original walk base,
				 * then we are done.
				 */
				if (at_base_level) {
					ret = NB_OK;
					goto done;
				}
				/*
				 * Grab the sibling of the container we are
				 * about to pop, so we will be mid-walk on the
				 * parent containers children.
				 */
				sib = nb_op_sib_next(sib);

				/* Pop container node to the parent container */
				ys_pop_inner(ys);

				/*
				 * If are were working on a user narrowed path
				 * then we are done with these siblings.
				 */
				if (darr_len(ys->schema_path) >
				    darr_len(ys->node_infos))
					sib = NULL;

				/* Start over */
				continue;
			}
			/*
			 * If we are here we have reached the end of the
			 * children of a list entry node. sib points
			 * at the list node info.
			 */
		}

		/* TODO: old code checked for "first" here and skipped if set */
		if (CHECK_FLAG(sib->nodetype,
			       LYS_LEAF | LYS_LEAFLIST | LYS_CONTAINER))
			xpath_child = nb_op_get_child_path(ys->xpath, sib,
							   xpath_child);
		nn = sib->priv;

		switch (sib->nodetype) {
		case LYS_LEAF:
			ret = nb_op_iter_leaf(ys, nn, xpath_child);
			sib = nb_op_sib_next(sib);
			continue;
		case LYS_LEAFLIST:
			ret = nb_op_iter_leaflist(ys, nn, xpath_child);
			sib = nb_op_sib_next(sib);
			continue;
		case LYS_CONTAINER:
			if (CHECK_FLAG(nn->flags, F_NB_NODE_CONFIG_ONLY)) {
				sib = nb_op_sib_next(sib);
				continue;
			}

			node = NULL;
			err = lyd_new_inner(&ni->inner->node, sib->module,
					    sib->name, false, &node);
			if (err) {
				ret = NB_ERR_RESOURCE;
				goto done;
			}

			/* push this container node on top of the stack */
			ni = darr_append(ys->node_infos);
			ni->inner = (struct lyd_node_inner *)node;
			ni->schema = node->schema;
			ni->niters = 0;
			ni->nents = 0;
			ni->has_lookup_next = false;
			ni->lookup_next_ok = ni[-1].lookup_next_ok;
			ni->list_entry = ni[-1].list_entry;

			darr_in_strdup(ys->xpath, xpath_child);
			ni->xpath_len = darr_strlen(ys->xpath);

			sib = nb_op_sib_first(ys, sib, false);
			continue;
		case LYS_LIST:
			/*
			 * ni->inner may be NULL here if we resumed and it was
			 * gone. ni->schema and ni->keys will still be valid.
			 */
			list_start = ni->schema != sib;
			if (list_start) {
				/*
				 * Our node info wasn't on top so this is a new
				 * list iteration, we will push our node info
				 * below. The top is our parent.
				 */
				if (CHECK_FLAG(nn->flags,
					       F_NB_NODE_CONFIG_ONLY)) {
					sib = nb_op_sib_next(sib);
					continue;
				}
				pni = ni;
				ni = NULL;
			} else {
				/*
				 * This is the case where `sib == NULL` at the
				 * top of the loop, so, we just completed the
				 * walking the children of the list entry.
				 *
				 * Additionally, `sib` was reset to point at the
				 * our list node at the top of node_infos.
				 * Within this node_info, `ys->xpath`, `inner`,
				 * `list_entry`, and `xpath_len` are for the
				 * previous entry.
				 */
				pni = darr_len(ys->node_infos) > 1 ? &ni[-1]
								   : NULL;
			}
			parent_list_entry = pni ? pni->list_entry : NULL;
			list_entry = ni ? ni->list_entry : NULL;

			if (ys->query_list_entry && at_base_level &&
			    !list_start) {
				/* Handle query for a specific list entry.
				 * list_start will always be false for the
				 * specific entry b/c the top node and the sib
				 * be the same. When we visit the children of
				 * this node any list node children will start
				 * off with at_base_level == true b/c they are
				 * about to push a new node; however in this
				 * case `list_start` will be true b/c the sib
				 * will point at the child while `ni` wll point
				 * at the parent (specific entry).
				 */
				if (ys->query_did_entry)
					list_entry = NULL;
				else {
					assert(ni->list_entry);
					list_entry = ni->list_entry;
					ys->query_did_entry = true;
					goto query_entry_skip_keys;
				}
			} else if (ni && ni->lookup_next_ok &&
				   // make sure we advance, if the interval is
				   // fast and we are very slow.
				   ((monotime_since(&ys->start_time, NULL) >
					     NB_OP_WALK_INTERVAL_US &&
				     ni->niters) ||
				    (ni->niters + 1) % 10000 == 0)) {
				/* This is a yield supporting list node and
				 * we've been running at least our yield
				 * interval, so yield.
				 *
				 * NOTE: we never yield on list_start, and we
				 * are always about to be doing a get_next.
				 */
				DEBUGD(&nb_dbg_events,
				       "%s: yielding after %u iterations",
				       __func__, ni->niters);

				ni->niters = 0;
				return NB_YIELD;
			} else if (!list_start && !list_entry &&
				   ni->has_lookup_next) {
				/* We don't have the previous object, but we have
				 * the previous keys, lookup next.
				 */
				list_entry =
					nb_callback_lookup_next(nn,
								parent_list_entry,
								&ni->keys);
			} else {
				/* Obtain [next] list entry. */
				list_entry =
					nb_callback_get_next(nn,
							     parent_list_entry,
							     list_entry);
			}

			if (!list_entry) {
				/* End of list iteration. */
				if (ys->query_list_entry && at_base_level) {
					ret = NB_OK;
					goto done;
				}

				/* Grab this list nodes sibling */
				sib = nb_op_sib_next(sib);

				/* Pop the list node up to our parent, but
				 * only if we've already pushed a node for the
				 * current list schema. For `list_start` this
				 * hasn't happened yet, as would have happened
				 * below. So basically we processed an empty
				 * list.
				 */
				if (!list_start)
					ys_pop_inner(ys);

				if (!sib)
					assert(darr_ilen(ys->node_infos) - 1 >=
					       ys->walk_root_level);

				if (!sib && darr_ilen(ys->node_infos) - 1 ==
						    ys->walk_root_level) {
					ret = NB_OK;
					goto done;
				}

				/* Move on to the sibling of the list node */
				continue;
			}

			if (list_start) {
				/*
				 * Starting a list iteration, push the list
				 * node_info on stack.
				 */
				ni = darr_append(ys->node_infos);
				pni = &ni[-1]; /* memory may have moved */
				ni->has_lookup_next = nn->cbs.lookup_next !=
						      NULL;
				ni->lookup_next_ok = ((!pni && ys->finish) ||
						      pni->lookup_next_ok) &&
						     ni->has_lookup_next;
				ni->niters = 0;
				ni->nents = 0;

				/* this will be our predicate-less xpath */
				darr_in_strcat(ys->xpath, "/");
				darr_in_strcat(ys->xpath, sib->name);
			} else {
				/*
				 * Reset our xpath to the list node (i.e.,
				 * remove the entry predicates)
				 */
				len = strlen(sib->name) + 1; /* "/sibname" */
				if (pni)
					len += pni->xpath_len;
				darr_setlen(ys->xpath, len + 1);
				ys->xpath[len] = 0;
				ni->xpath_len = len;
			}

			/* Need to get keys. */

			if (!CHECK_FLAG(nn->flags, F_NB_NODE_KEYLESS_LIST)) {
				ret = nb_callback_get_keys(nn, list_entry,
							   &ni->keys);
				if (ret) {
					darr_pop(ys->node_infos);
					ret = NB_ERR_RESOURCE;
					goto done;
				}
			}
			/*
			 * Append predicates to xpath.
			 */
			len = darr_strlen(ys->xpath);
			if (ni->keys.num) {
				yang_get_key_preds(ys->xpath + len, sib,
						   &ni->keys,
						   darr_cap(ys->xpath) - len);
			} else {
				/* add a position predicate (1s based?) */
				darr_ensure_avail(ys->xpath, 10);
				snprintf(ys->xpath + len,
					 darr_cap(ys->xpath) - len + 1, "[%u]",
					 ni->nents + 1);
			}
			darr_setlen(ys->xpath,
				    strlen(ys->xpath + len) + len + 1);
			ni->xpath_len = darr_strlen(ys->xpath);

			/*
			 * Create the new list entry node.
			 */
#if 0					   
			err = lyd_new_list2(&ni[-1].inner->node, sib->module,
					    sib->name, ys->xpath + len, false,
					    &node);
#endif
			err = yang_lyd_new_list(ni[-1].inner, sib, &ni->keys,
						(struct lyd_node_inner **)&node);
			if (err) {
				darr_pop(ys->node_infos);
				ret = NB_ERR_RESOURCE;
				goto done;
			}
			/*
			 * Save the new list entry with the list node info
			 */
			ni->inner = (struct lyd_node_inner *)node;
			ni->schema = node->schema;
			ni->list_entry = list_entry;
			ni->niters += 1;
			ni->nents += 1;

			/* Skip over the key children, they've been created. */
query_entry_skip_keys:
			sib = nb_op_sib_first(ys, sib, true);
			continue;

		default:
			/*FALLTHROUGH*/
		case LYS_ANYXML:
		case LYS_ANYDATA:
		case LYS_CHOICE:
		case LYS_CASE:
			/* These schema types are not currently handled */
			flog_warn(EC_LIB_NB_OPERATIONAL_DATA,
				  "%s: unsupported schema node type: %s",
				  __func__, lys_nodetype2str(sib->nodetype));
			sib = nb_op_sib_next(ys, sib);
			continue;
		}
	}

done:
	darr_free(xpath_child);
	return ret;
}

static void nb_op_walk_cb(struct event *thread)
{
	struct nb_op_yield_state *ys = EVENT_ARG(thread);
	enum nb_error ret = NB_OK;

	DEBUGD(&nb_dbg_cbs_state, "northbound oper-state: resuming %s",
	       ys->xpath);

	nb_op_resume_data_tree(ys);

	/* if we've popped past the walk start level we're done */
	if (darr_lasti(ys->node_infos) < ys->walk_root_level)
		goto finish;

	/* otherwise we are at a resumable node */
	assert(darr_last(ys->node_infos)->has_lookup_next);

	ret = __walk(ys, true);
	if (ret == NB_YIELD) {
		if (nb_op_yield(ys) != NB_OK) {
			if (ys->should_batch)
				goto stopped;
			else
				goto finish;
		}
		return;
	}
finish:
	(*ys->finish)(ys_root_node(ys), ys->finish_arg, ret);
stopped:
	nb_op_free_yield_state(ys, false);
}

static enum nb_error nb_op_yield(struct nb_op_yield_state *ys)
{
	enum nb_error ret;
	ulong min_us = MAX(1, NB_OP_WALK_INTERVAL_US / 50000);
	struct timeval tv = { .tv_sec = 0, .tv_usec = min_us };

	DEBUGD(&nb_dbg_events, "NB oper-state: yielding %s for %lus (should_batch %d)",
	       ys->xpath, tv.tv_usec, ys->should_batch);

	if (ys->should_batch) {
		/*
		 * TODO: add ability of finish to influence the timer.
		 * This will allow, for example, flow control based on how long
		 * it takes finish to process the batch.
		 */
		ret = (*ys->finish)(ys_root_node(ys), ys->finish_arg, NB_YIELD);
		if (ret != NB_OK)
			return ret;
		/* now trim out that data we just "finished" */
		nb_op_trim_yield_state(ys);

	}

	event_add_timer_tv(event_loop, nb_op_walk_cb, ys, &tv, &ys->walk_ev);
	return NB_OK;
}

static enum nb_error nb_op_singleton(const char *xpath, struct nb_node *nn,
				     struct nb_op_yield_state *ys)
{
	char *xpath_p = XSTRDUP(MTYPE_NB_XPATH, xpath);
	enum nb_error ret;

	ret = nb_op_xpath_dirname(xpath_p);
	if (ret)
		goto done;

	ret = nb_op_init_data_tree(xpath_p, &ys->node_infos, false, false);
	if (ret)
		goto done;

	switch (nn->snode->nodetype) {
	case LYS_LEAF:
		ret = nb_op_iter_leaf(ys, nn, xpath);
		break;
	case LYS_LEAFLIST:
		ret = nb_op_iter_leaflist(ys, nn, xpath);
		break;
	default:
		/*FALLTHROUGH*/
	case LYS_CHOICE:
	case LYS_CASE:
		/* These schema types are not currently handled */
		flog_warn(EC_LIB_NB_OPERATIONAL_DATA,
			  "%s: unsupported schema node type: %s", __func__,
			  lys_nodetype2str(nn->snode->nodetype));
		break;
	}
done:
	XFREE(MTYPE_NB_XPATH, xpath_p);
	return ret;
}


static enum nb_error nb_op_walk_start(const char *xpath,
				      struct nb_op_yield_state *ys)
{
	struct nb_op_node_info *ni;
	struct nb_node *nn;
	enum nb_error ret;

	nn = nb_node_find(xpath);
	if (!nn) {
		flog_warn(EC_LIB_YANG_UNKNOWN_DATA_PATH,
			  "%s: unknown data path: %s", __func__, xpath);
		return NB_ERR;
	}
	/* XXX create darr array of schema node branch in ys->schema_path */

	if (!CHECK_FLAG(nn->snode->nodetype, LYS_CONTAINER | LYS_LIST))
		return nb_op_singleton(xpath, nn, ys);

	/* XXX this function should set ys->walk_root_level */

	ret = nb_op_init_data_tree(xpath, &ys->node_infos,
				   nn->snode->nodetype == LYS_LIST,
				   ys->finish != NULL);
	if (ret != NB_OK)
		return ret;

	ni = darr_last(ys->node_infos);

	/* XXX actually we should have a flag per entry for this add later */
	/* XXX need to check this each time we get to this point in our walk,
	 * not just here at the start to cover generic cases
	 */
	if (ys->walk_root_level == darr_ilen(ys->node_infos) - 1 &&
	    (ni->inner->schema->nodetype == LYS_LIST && ni->list_entry))
		ys->query_list_entry = true;

	/* XXX this should be removed */
	ys->walk_root_level = darr_len(ys->node_infos) - 1;

	return __walk(ys, false);
}


void *nb_op_walk(const char *xpath, struct yang_translator *translator,
		 uint32_t flags, bool should_batch, nb_oper_data_cb cb,
		 void *cb_arg, nb_oper_data_finish_cb finish, void *finish_arg)
{
	struct nb_op_yield_state *ys;
	enum nb_error ret;

	ys = nb_op_create_yield_state(xpath, translator, flags, should_batch,
				      cb, cb_arg, finish, finish_arg);

	ret = nb_op_walk_start(xpath, ys);
	if (ret == NB_YIELD) {
		if (nb_op_yield(ys) != NB_OK) {
			if (ys->should_batch)
				goto stopped;
			else
				goto finish;
		}
		return ys;
	}
finish:
	(void)(*ys->finish)(ys_root_node(ys), ys->finish_arg, ret);
stopped:
	nb_op_free_yield_state(ys, false);
	return NULL;
}


void nb_op_cancel_walk(void *walk)
{
	if (walk)
		nb_op_free_yield_state(walk, false);
}


void nb_op_cancel_all_walks(void)
{
	struct nb_op_yield_state *ys;

	frr_each_safe (nb_op_walks, &nb_op_walks, ys)
		nb_op_cancel_walk(ys);
}


/*
 * The old API -- remove when we've update the users to yielding.
 */
enum nb_error nb_op_iterate_legacy(const char *xpath,
				   struct yang_translator *translator,
				   uint32_t flags, nb_oper_data_cb cb,
				   void *cb_arg, struct lyd_node **tree)
{
	struct nb_op_yield_state *ys;
	enum nb_error ret;

	ys = nb_op_create_yield_state(xpath, translator, flags, false, cb,
				      cb_arg, NULL, NULL);

	ret = nb_op_walk_start(xpath, ys);
	assert(ret != NB_YIELD);

	if (tree && ret == NB_OK)
		*tree = ys_root_node(ys);
	else {
		if (ys_root_node(ys))
			yang_dnode_free(ys_root_node(ys));
		if (tree)
			*tree = NULL;
	}

	nb_op_free_yield_state(ys, true);
	return ret;
}

void nb_op_init(struct event_loop *loop)
{
	event_loop = loop;
	nb_op_walks_init(&nb_op_walks);
}

void nb_op_terminate(void)
{
	nb_op_cancel_all_walks();
}
