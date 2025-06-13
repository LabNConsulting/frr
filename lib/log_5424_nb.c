/*
  * June 11 2025, Christian Hopps <chopps@labn.net>
  *
  * Copyright (c) 2025, LabN Consulting, L.L.C.
  *
  */

#include <zebra.h>
#include "lib/command.h"
#include "lib/northbound.h"
#include "lib/lib_errors.h"
#include "lib/log.h"
#include "lib/log_vty.h"
#include "lib/vty.h"
// #include "lib/zlog_targets.h"
#include "lib/zlog_5424.h"
#include "lib/log_5424_nb.h"

#define ZLOG_MAXLVL(a, b) MAX(a, b)

DEFINE_MTYPE_STATIC(LOG, LOG_5424_CONFIG, "extended syslog config");
DEFINE_MTYPE_STATIC(LOG, LOG_5424_DATA, "extended syslog config items");

struct targets_head targets = INIT_RBTREE_UNIQ(targets);

/* clang-format off */
struct log_option log_opts[] = {
	{ "code-location",	offsetof(struct zlog_cfg_5424, kw_location) },
	{ "version",		offsetof(struct zlog_cfg_5424, kw_version) },
	{ "unique-id",		offsetof(struct zlog_cfg_5424, kw_uid), true },
	{ "error-category",	offsetof(struct zlog_cfg_5424, kw_ec), true },
	{ "format-args",	offsetof(struct zlog_cfg_5424, kw_args) },
	{},
};

/* clang-format on */

struct event_loop *log_5424_master;
static void clear_dst(struct zlog_cfg_5424_user *cfg);

static struct zlog_cfg_5424_user *log_5424_alloc(const char *name)
{
	struct zlog_cfg_5424_user *cfg;

	cfg = XCALLOC(MTYPE_LOG_5424_CONFIG, sizeof(*cfg));
	cfg->name = XSTRDUP(MTYPE_LOG_5424_DATA, name);

	cfg->cfg.master = log_5424_master;
	cfg->cfg.kw_location = true;
	cfg->cfg.kw_version = false;
	cfg->cfg.facility = DFLT_FACILITY;
	cfg->cfg.prio_min = DFLT_PRIO_MIN;
	cfg->cfg.ts_flags = DFLT_TS_FLAGS;
	clear_dst(cfg);

	for (struct log_option *opt = log_opts; opt->name; opt++) {
		bool *ptr = (bool *)(((char *)&cfg->cfg) + opt->offs);
		*ptr = opt->dflt;
	}

	zlog_5424_init(&cfg->cfg);

	QOBJ_REG(cfg, zlog_cfg_5424_user);
	targets_add(&targets, cfg);
	return cfg;
}

void log_5424_free(struct zlog_cfg_5424_user *cfg, bool keepopen)
{
	targets_del(&targets, cfg);
	QOBJ_UNREG(cfg);

	zlog_5424_fini(&cfg->cfg, keepopen);
	clear_dst(cfg);

	XFREE(MTYPE_LOG_5424_DATA, cfg->filename);
	XFREE(MTYPE_LOG_5424_DATA, cfg->name);
	XFREE(MTYPE_LOG_5424_CONFIG, cfg);
}

static void clear_dst(struct zlog_cfg_5424_user *cfg)
{
	XFREE(MTYPE_LOG_5424_DATA, cfg->filename);
	cfg->cfg.filename = cfg->filename;

	XFREE(MTYPE_LOG_5424_DATA, cfg->file_user);
	XFREE(MTYPE_LOG_5424_DATA, cfg->file_group);
	XFREE(MTYPE_LOG_5424_DATA, cfg->envvar);

	cfg->cfg.fd = -1;
	cfg->cfg.file_uid = -1;
	cfg->cfg.file_gid = -1;
	cfg->cfg.file_mode = LOGFILE_MASK & 0666;
	cfg->cfg.file_nocreate = false;
	cfg->cfg.dst = ZLOG_5424_DST_NONE;
}

static int reconf_dst(struct zlog_cfg_5424_user *cfg, struct vty *vty)
{
	if (!cfg->reconf_dst && !cfg->reconf_meta && vty->type != VTY_FILE)
		vty_out(vty,
			"%% Changes will be applied when exiting this config block\n");

	cfg->reconf_dst = true;
	return CMD_SUCCESS;
}

static int reconf_meta(struct zlog_cfg_5424_user *cfg, struct vty *vty)
{
	if (!cfg->reconf_dst && !cfg->reconf_meta && vty->type != VTY_FILE)
		vty_out(vty,
			"%% Changes will be applied when exiting this config block\n");

	cfg->reconf_meta = true;
	return CMD_SUCCESS;
}

static int reconf_clear_dst(struct zlog_cfg_5424_user *cfg, struct vty *vty)
{
	if (cfg->cfg.dst == ZLOG_5424_DST_NONE)
		return CMD_SUCCESS;

	clear_dst(cfg);
	return reconf_dst(cfg, vty);
}

static void log_5424_autocomplete(vector comps, struct cmd_token *token)
{
	struct zlog_cfg_5424_user *cfg;

	frr_each (targets, &targets, cfg)
		vector_set(comps, XSTRDUP(MTYPE_COMPLETION, cfg->name));
}


static const struct cmd_variable_handler log_5424_var_handlers[] = {
	{.tokenname = "EXTLOGNAME", .completions = log_5424_autocomplete},
	{.completions = NULL},
};


struct zlog_cfg_5424_user *_get_cfg(const struct lyd_node *dnode, const char *name_path)
{
	const char *extlogname = yang_dnode_get_string(args->dnode, name_path);
	struct zlog_cfg_5424_user *cfg, ref;

	assert(extlogname);
	ref.name = (char *)extlogname;
	return targets_find(&targets, &ref);
}

/*
 * XPath: /frr-logging:logging/extended-syslog
 */
int logging_extended_syslog_create(struct nb_cb_create_args *args)
{
	const char *extlogname;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	assert(!_get_cfg(args->dnode, "name"));

	extlogname = yang_dnode_get_string(args->dnode, "name");
	(void)log_5424_alloc(extlogname);

	return NB_OK;
}

int logging_extended_syslog_destroy(struct nb_cb_destroy_args *args)
{
	struct zlog_cfg_5424_user *cfg;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	cfg = _get_cfg(args->dnode, "name");
	if (!cfg) {
		flog_err(EC_LIB_NB_CB_CONFIG_APPLY,
			 "Failed to find extended syslog target named '%s'",
			 yang_dnode_get_string(args->dnode, "name"));
		assert(false);
		// return NB_ERR_INCONSISTENCY;
	}
	log_5424_free(cfg, false);

	return NB_OK;
}

/*
 * XPath: /frr-logging:logging/extended-syslog/destination/file
 */
int logging_extended_syslog_destination_file_create(struct nb_cb_create_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}


int logging_extended_syslog_destination_file_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}

/*
 * XPath: /frr-logging:logging/extended-syslog/destination/file/path
 */
int logging_extended_syslog_destination_file_path_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}


/*
 * XPath: /frr-logging:logging/extended-syslog/destination/file/user
 */
int logging_extended_syslog_destination_file_user_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}


int logging_extended_syslog_destination_file_user_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}

/*
 * XPath: /frr-logging:logging/extended-syslog/destination/file/group
 */
int logging_extended_syslog_destination_file_group_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}


int logging_extended_syslog_destination_file_group_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}

/*
 * XPath: /frr-logging:logging/extended-syslog/destination/file/mode
 */
int logging_extended_syslog_destination_file_mode_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}


int logging_extended_syslog_destination_file_mode_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}

/*
 * XPath: /frr-logging:logging/extended-syslog/destination/file/no-create
 */
int logging_extended_syslog_destination_file_no_create_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}


/*
 * XPath: /frr-logging:logging/extended-syslog/destination/file/format
 */
int logging_extended_syslog_destination_file_format_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}


/*
 * XPath: /frr-logging:logging/extended-syslog/destination/fifo
 */
int logging_extended_syslog_destination_fifo_create(struct nb_cb_create_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}


int logging_extended_syslog_destination_fifo_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}

/*
 * XPath: /frr-logging:logging/extended-syslog/destination/fifo/path
 */
int logging_extended_syslog_destination_fifo_path_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}


/*
 * XPath: /frr-logging:logging/extended-syslog/destination/fifo/user
 */
int logging_extended_syslog_destination_fifo_user_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}


int logging_extended_syslog_destination_fifo_user_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}

/*
 * XPath: /frr-logging:logging/extended-syslog/destination/fifo/group
 */
int logging_extended_syslog_destination_fifo_group_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}


int logging_extended_syslog_destination_fifo_group_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}

/*
 * XPath: /frr-logging:logging/extended-syslog/destination/fifo/mode
 */
int logging_extended_syslog_destination_fifo_mode_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}


int logging_extended_syslog_destination_fifo_mode_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}

/*
 * XPath: /frr-logging:logging/extended-syslog/destination/fifo/no-create
 */
int logging_extended_syslog_destination_fifo_no_create_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}


/*
 * XPath: /frr-logging:logging/extended-syslog/destination/fifo/format
 */
int logging_extended_syslog_destination_fifo_format_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}


/*
 * XPath: /frr-logging:logging/extended-syslog/destination/unix
 */
int logging_extended_syslog_destination_unix_create(struct nb_cb_create_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}


int logging_extended_syslog_destination_unix_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}

/*
 * XPath: /frr-logging:logging/extended-syslog/destination/unix/path
 */
int logging_extended_syslog_destination_unix_path_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}


/*
 * XPath: /frr-logging:logging/extended-syslog/destination/unix/format
 */
int logging_extended_syslog_destination_unix_format_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}


/*
 * XPath: /frr-logging:logging/extended-syslog/destination/journald
 */
int logging_extended_syslog_destination_journald_create(struct nb_cb_create_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}


int logging_extended_syslog_destination_journald_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}

/*
 * XPath: /frr-logging:logging/extended-syslog/destination/syslog
 */
int logging_extended_syslog_destination_syslog_create(struct nb_cb_create_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}


int logging_extended_syslog_destination_syslog_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}

/*
 * XPath: /frr-logging:logging/extended-syslog/destination/syslog/supports-rfc5424
 */
int logging_extended_syslog_destination_syslog_supports_rfc5424_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}


/*
 * XPath: /frr-logging:logging/extended-syslog/destination/fd
 */
int logging_extended_syslog_destination_fd_create(struct nb_cb_create_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}


int logging_extended_syslog_destination_fd_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}

/*
 * XPath: /frr-logging:logging/extended-syslog/destination/fd/number
 */
int logging_extended_syslog_destination_fd_number_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}


int logging_extended_syslog_destination_fd_number_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}

/*
 * XPath: /frr-logging:logging/extended-syslog/destination/fd/envvar
 */
int logging_extended_syslog_destination_fd_envvar_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}


int logging_extended_syslog_destination_fd_envvar_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}

/*
 * XPath: /frr-logging:logging/extended-syslog/destination/fd/stdout
 */
int logging_extended_syslog_destination_fd_stdout_create(struct nb_cb_create_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}


int logging_extended_syslog_destination_fd_stdout_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}

/*
 * XPath: /frr-logging:logging/extended-syslog/destination/fd/stderr
 */
int logging_extended_syslog_destination_fd_stderr_create(struct nb_cb_create_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}


int logging_extended_syslog_destination_fd_stderr_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}

/*
 * XPath: /frr-logging:logging/extended-syslog/destination/fd/format
 */
int logging_extended_syslog_destination_fd_format_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}


/*
 * XPath: /frr-logging:logging/extended-syslog/destination/none
 */
int logging_extended_syslog_destination_none_create(struct nb_cb_create_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}


int logging_extended_syslog_destination_none_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* TODO: implement me. */

	return NB_OK;
}

/*
 * XPath: /frr-logging:logging/extended-syslog/level
 */
int logging_extended_syslog_level_modify(struct nb_cb_modify_args *args)
{
	struct zlog_cfg_5424_user *cfg;
	int level;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	cfg = _get_cfg(args->dnode, "../name");

	level = log_nb_get_level(args->dnode, NULL);
	if (level == cfg->cfg.prio_min)
		return NB_OK;
	cfg->cfg.prio_min = level;

	/* XXX How can we only call this once? */
	zlog_5424_apply_meta(&cfg->cfg);
	return NB_OK;
}

/*
 * XPath: /frr-logging:logging/extended-syslog/facility
 */
int logging_extended_syslog_facility_modify(struct nb_cb_modify_args *args)
{
	struct zlog_cfg_5424_user *cfg;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	cfg = _get_cfg(args->dnode, "../name");

	zlog_5424_apply_meta(&cfg->cfg);
	return NB_OK;
}


/*
 * XPath: /frr-logging:logging/extended-syslog/code-location
 */
int logging_extended_syslog_code_location_modify(struct nb_cb_modify_args *args)
{
	struct zlog_cfg_5424_user *cfg;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	cfg = _get_cfg(args->dnode, "../name");

	zlog_5424_apply_meta(&cfg->cfg);
	return NB_OK;
}


/*
 * XPath: /frr-logging:logging/extended-syslog/version
 */
int logging_extended_syslog_version_modify(struct nb_cb_modify_args *args)
{
	struct zlog_cfg_5424_user *cfg;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	cfg = _get_cfg(args->dnode, "../name");

	zlog_5424_apply_meta(&cfg->cfg);
	return NB_OK;
}


/*
 * XPath: /frr-logging:logging/extended-syslog/error-category
 */
int logging_extended_syslog_error_category_modify(struct nb_cb_modify_args *args)
{
	struct zlog_cfg_5424_user *cfg;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	cfg = _get_cfg(args->dnode, "../name");

	zlog_5424_apply_meta(&cfg->cfg);
	return NB_OK;
}


/*
 * XPath: /frr-logging:logging/extended-syslog/unique-id
 */
int logging_extended_syslog_unique_id_modify(struct nb_cb_modify_args *args)
{
	struct zlog_cfg_5424_user *cfg;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	cfg = _get_cfg(args->dnode, "../name");

	zlog_5424_apply_meta(&cfg->cfg);
	return NB_OK;
}


/*
 * XPath: /frr-logging:logging/extended-syslog/format-args
 */
int logging_extended_syslog_format_args_modify(struct nb_cb_modify_args *args)
{
	struct zlog_cfg_5424_user *cfg;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	cfg = _get_cfg(args->dnode, "../name");

	zlog_5424_apply_meta(&cfg->cfg);
	return NB_OK;
}


/*
 * XPath: /frr-logging:logging/extended-syslog/timestamp-precision
 */
int logging_extended_syslog_timestamp_precision_modify(struct nb_cb_modify_args *args)
{
	struct zlog_cfg_5424_user *cfg;
	uint32_t ts_flags;
	uint8_t precision;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	cfg = _get_cfg(args->dnode, "../name");
	precision = yang_dnode_get_uint8(args->dnode, NULL);

	ts_flags = cfg->cfg.ts_flags;
	ts_flags &= ~ZLOG_TS_PREC;
	ts_flags |= precision;

	if (ts_flags == cfg->cfg.ts_flags)
		return NB_OK;

	cfg->cfg.ts_flags = ts_flags;
	zlog_5424_apply_meta(&cfg->cfg);

	return NB_OK;
}


/*
 * XPath: /frr-logging:logging/extended-syslog/timestamp-local-time
 */
int logging_extended_syslog_timestamp_local_time_modify(struct nb_cb_modify_args *args)
{
	struct zlog_cfg_5424_user *cfg;
	uint32_t ts_flags;
	bool enable;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	cfg = _get_cfg(args->dnode, "../name");
	enable = yang_dnode_get_bool(args->dnode, NULL);

	ts_flags = cfg->cfg.ts_flags;
	ts_flags &= ~ZLOG_TS_UTC;
	if (!enable)
		ts_flags |= ZLOG_TS_UTC;

	if (ts_flags == cfg->cfg.ts_flags)
		return NB_OK;

	cfg->cfg.ts_flags = ts_flags;
	zlog_5424_apply_meta(&cfg->cfg);

	return NB_OK;
}
