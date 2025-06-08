// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * June 8 2025, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2025, LabN Consulting, L.L.C.
 */
#include <zebra.h>
#include <pwd.h>
#include <grp.h>
#include "command.h"
#include "log.h"
#include "log_vty.h"
#include "northbound.h"
#include "northbound_cli.h"
#include "lib/vtysh_daemons.h"
#include "zlog_5424.h"

#include "lib/log_cli_clippy.c"

/* ======================= */
/* Basic logging CLI code. */
/* ======================= */

DEFPY_YANG (config_log_stdout,
	    config_log_stdout_cmd,
	    "log stdout [<emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>$levelarg]",
	    "Logging control\n"
	    "Set stdout logging level\n"
	    LOG_LEVEL_DESC)
{
	nb_cli_enqueue_change(vty, "/frr-logging:logging/stdout", NB_OP_CREATE, NULL);
	if (levelarg)
		nb_cli_enqueue_change(vty, "/frr-logging:logging/stdout/level", NB_OP_MODIFY,
				      levelarg);
	else
		nb_cli_enqueue_change(vty, "/frr-logging:logging/stdout/level", NB_OP_DESTROY,
				      NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN (no_config_log_stdout,
       no_config_log_stdout_cmd,
       "no log stdout [<emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>]",
       NO_STR
       "Logging control\n"
       "Cancel logging to stdout\n"
       LOG_LEVEL_DESC)
{
	nb_cli_enqueue_change(vty, "/frr-logging:logging/stdout", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_HIDDEN (config_log_monitor,
       config_log_monitor_cmd,
       "log monitor [<emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>]",
       "Logging control\n"
       "Set terminal line (monitor) logging level\n"
       LOG_LEVEL_DESC)
{
	vty_out(vty, "%% \"log monitor\" is deprecated and does nothing.\n");
	return CMD_SUCCESS;
}

DEFUN_HIDDEN (no_config_log_monitor,
       no_config_log_monitor_cmd,
       "no log monitor [<emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>]",
       NO_STR
       "Logging control\n"
       "Disable terminal line (monitor) logging\n"
       LOG_LEVEL_DESC)
{
	return CMD_SUCCESS;
}

DEFPY_YANG_NOSH (debug_uid_backtrace,
            debug_uid_backtrace_cmd,
            "[no] debug unique-id UID backtrace",
            NO_STR
            DEBUG_STR
            "Options per individual log message, by unique ID\n"
            "Log message unique ID (XXXXX-XXXXX)\n"
            "Add backtrace to log when message is printed\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "/frr-logging:logging/uid-backtrace[uid='%s']", uid);
	nb_cli_enqueue_change(vty, xpath, no ? NB_OP_DESTROY : NB_OP_CREATE, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

/* Per-daemon log file config */
DEFPY_YANG (config_log_dmn_file,
	    config_log_dmn_file_cmd,
	    "log daemon <zebra|mgmtd|bgpd|ripd|ripngd|ospfd|ospf6d|isisd|fabricd|nhrpd|ldpd|babeld|eigrpd|sharpd|pimd|pim6d|pbrd|staticd|bfdd|vrrpd|pathd>$daemon file FILENAME [<emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>$levelarg]",
	    "Logging control\n"
	    "Specific daemon\n"
	    DAEMONS_STR
	    "Logging to file\n"
	    "Logging filename\n"
	    LOG_LEVEL_DESC)
{
	char xpath[XPATH_MAXLEN];
	char buf[XPATH_MAXLEN];

	if (!strmatch(daemon, frr_get_progname()))
		return CMD_SUCCESS;

	snprintf(xpath, sizeof(xpath), "/frr-logging:logging/daemon-file[daemon='%s']/filename",
		 daemon);
	nb_cli_enqueue_change(vty, buf, NB_OP_MODIFY, filename);
	snprintf(xpath, sizeof(xpath), "/frr-logging:logging/daemon-file[daemon='%s']/level",
		 daemon);
	if (levelarg)
		nb_cli_enqueue_change(vty, buf, NB_OP_MODIFY, levelarg);
	else
		nb_cli_enqueue_change(vty, buf, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/* Per-daemon no log file */
DEFPY_YANG (no_config_log_dmn_file,
	    no_config_log_dmn_file_cmd,
	    "no log daemon <zebra|mgmtd|bgpd|ripd|ripngd|ospfd|ospf6d|isisd|fabricd|nhrpd|ldpd|babeld|eigrpd|sharpd|pimd|pim6d|pbrd|staticd|bfdd|vrrpd|pathd>$daemon file [FILENAME [LEVEL]]",
       NO_STR
       "Logging control\n"
       "Specific daemon\n"
       DAEMONS_STR
       "Cancel logging to file\n"
       "Logging file name\n"
       "Logging level\n")
{
	char xpath[XPATH_MAXLEN];

	if (!strmatch(daemon, frr_get_progname()))
		return CMD_SUCCESS;

	snprintf(xpath, sizeof(xpath), "/frr-logging:logging/daemon-file[daemon='%s']", daemon);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (config_log_file,
       config_log_file_cmd,
       "log file FILENAME [<emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>$levelarg]",
       "Logging control\n"
       "Logging to file\n"
       "Logging filename\n"
       LOG_LEVEL_DESC)
{
	nb_cli_enqueue_change(vty, "/frr-logging:logging/file/filename", NB_OP_MODIFY, filename);
	if (levelarg)
		nb_cli_enqueue_change(vty, "/frr-logging:logging/file/level", NB_OP_MODIFY,
				      levelarg);
	else
		nb_cli_enqueue_change(vty, "/frr-logging:logging/file/level", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN (no_config_log_file,
       no_config_log_file_cmd,
       "no log file [FILENAME [LEVEL]]",
       NO_STR
       "Logging control\n"
       "Cancel logging to file\n"
       "Logging file name\n"
       "Logging level\n")
{
	nb_cli_enqueue_change(vty, "/frr-logging:logging/file", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (config_log_syslog,
       config_log_syslog_cmd,
       "log syslog [<emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>$levelarg]",
       "Logging control\n"
       "Set syslog logging level\n"
       LOG_LEVEL_DESC)
{
	nb_cli_enqueue_change(vty, "/frr-logging:logging/syslog", NB_OP_CREATE, NULL);
	if (levelarg)
		nb_cli_enqueue_change(vty, "/frr-logging:logging/syslog/level", NB_OP_MODIFY,
				      levelarg);
	else
		nb_cli_enqueue_change(vty, "/frr-logging:logging/syslog/level", NB_OP_DESTROY,
				      NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (no_config_log_syslog,
       no_config_log_syslog_cmd,
       "no log syslog [<kern|user|mail|daemon|auth|syslog|lpr|news|uucp|cron|local0|local1|local2|local3|local4|local5|local6|local7>] [<emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>]",
       NO_STR
       "Logging control\n"
       "Cancel logging to syslog\n"
       LOG_FACILITY_DESC
       LOG_LEVEL_DESC)
{
	nb_cli_enqueue_change(vty, "/frr-logging:logging/syslog", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (config_log_facility,
       config_log_facility_cmd,
       "log facility <kern|user|mail|daemon|auth|syslog|lpr|news|uucp|cron|local0|local1|local2|local3|local4|local5|local6|local7>$facilityarg",
       "Logging control\n"
       "Facility parameter for syslog messages\n"
       LOG_FACILITY_DESC)
{
	nb_cli_enqueue_change(vty, "/frr-logging:logging/facility", NB_OP_MODIFY, facilityarg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (no_config_log_facility,
       no_config_log_facility_cmd,
       "no log facility [<kern|user|mail|daemon|auth|syslog|lpr|news|uucp|cron|local0|local1|local2|local3|local4|local5|local6|local7>]",
       NO_STR
       "Logging control\n"
       "Reset syslog facility to default (daemon)\n"
       LOG_FACILITY_DESC)
{
	nb_cli_enqueue_change(vty, "/frr-logging:logging/facility", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (config_log_record_priority,
       config_log_record_priority_cmd,
       "log record-priority",
       "Logging control\n"
       "Log the priority of the message within the message\n")
{
	nb_cli_enqueue_change(vty, "/frr-logging:logging/record-priority", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (no_config_log_record_priority,
       no_config_log_record_priority_cmd,
       "no log record-priority",
       NO_STR
       "Logging control\n"
       "Do not log the priority of the message within the message\n")
{
	nb_cli_enqueue_change(vty, "/frr-logging:logging/record-priority", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (config_log_timestamp_precision,
       config_log_timestamp_precision_cmd,
       "log timestamp precision (0-6)",
       "Logging control\n"
       "Timestamp configuration\n"
       "Set the timestamp precision\n"
       "Number of subsecond digits\n")
{
	char buf[8];
	snprintf(buf, sizeof(buf), "%u", (uint)precision);
	nb_cli_enqueue_change(vty, "/frr-logging:logging/timestamp-precision", NB_OP_MODIFY, buf);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (no_config_log_timestamp_precision,
       no_config_log_timestamp_precision_cmd,
       "no log timestamp precision [(0-6)]",
       NO_STR
       "Logging control\n"
       "Timestamp configuration\n"
       "Reset the timestamp precision to the default value of 0\n"
       "Number of subsecond digits\n")
{
	nb_cli_enqueue_change(vty, "/frr-logging:logging/timestamp-precision", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (config_log_ec,
       config_log_ec_cmd,
       "[no] log error-category",
       NO_STR
       "Logging control\n"
       "Prefix log message text with [EC 9999] code\n")
{
	nb_cli_enqueue_change(vty, "/frr-logging:logging/error-category", NB_OP_MODIFY,
			      no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (config_log_xid,
       config_log_xid_cmd,
       "[no] log unique-id",
       NO_STR
       "Logging control\n"
       "Prefix log message text with [XXXXX-XXXXX] identifier\n")
{
	nb_cli_enqueue_change(vty, "/frr-logging:logging/unique-id", NB_OP_MODIFY,
			      no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (config_log_filterfile,
       config_log_filterfile_cmd,
       "log filtered-file FILENAME [<emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>$levelarg]",
       "Logging control\n"
       "Logging to file with string filter\n"
       "Logging filename\n"
       LOG_LEVEL_DESC)
{
	nb_cli_enqueue_change(vty, "/frr-logging:logging/filtered-file", NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, "/frr-logging:logging/filtered-file/filename", NB_OP_MODIFY,
			      filename);
	if (levelarg)
		nb_cli_enqueue_change(vty, "/frr-logging:logging/filtered-file/level",
				      NB_OP_MODIFY, levelarg);
	else
		nb_cli_enqueue_change(vty, "/frr-logging:logging/filtered-file/level",
				      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (no_config_log_filterfile,
       no_config_log_filterfile_cmd,
       "no log filtered-file [FILENAME [LEVEL]]",
       NO_STR
       "Logging control\n"
       "Cancel logging to file with string filter\n"
       "Logging file name\n"
       "Logging level\n")
{
	nb_cli_enqueue_change(vty, "/frr-logging:logging/filtered-file", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (log_filter,
       log_filter_cmd,
       "[no] log filter-text WORD$filter",
       NO_STR
       "Logging control\n"
       FILTER_LOG_STR
       "String to filter by\n")
{
	nb_cli_enqueue_change(vty, "/frr-logging:logging/filter-text",
			      no ? NB_OP_DESTROY : NB_OP_CREATE, filter);
	return nb_cli_apply_changes(vty, NULL);
}

/* Clear all log filters */
DEFPY_YANG (log_filter_clear,
       log_filter_clear_cmd,
       "clear log filter-text",
       CLEAR_STR
       "Logging control\n"
       FILTER_LOG_STR)
{
	nb_cli_enqueue_change(vty, "/frr-logging:logging/filter-text", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
	/* zlog_filter_clear(); */
	return CMD_SUCCESS;
}

/* Enable/disable 'immediate' mode, with no output buffering */
DEFPY_YANG (log_immediate_mode,
       log_immediate_mode_cmd,
       "[no] log immediate-mode",
       NO_STR
       "Logging control\n"
       "Output immediately, without buffering\n")
{
	nb_cli_enqueue_change(vty, "/frr-logging:logging/immediate-mode", NB_OP_MODIFY,
			      no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}


extern void log_5424_cmd_init(void);
extern void log_cli_cmd_init(void);

/* ========================= */
/* ZLOG_5424 extended syslog */
/* ========================= */

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


DEFPY_NOSH(log_5424_target,
	   log_5424_target_cmd,
	   "log extended-syslog EXTLOGNAME",
	   "Logging control\n"
	   "Extended RFC5424 syslog (including file targets)\n"
	   "Name identifying this syslog target\n")
{
	struct zlog_cfg_5424_user *cfg, ref;

	ref.name = (char *)extlogname;
	cfg = targets_find(&targets, &ref);

	if (!cfg)
		cfg = log_5424_alloc(extlogname);

	VTY_PUSH_CONTEXT(EXTLOG_NODE, cfg);
	return CMD_SUCCESS;
}

DEFPY(no_log_5424_target,
      no_log_5424_target_cmd,
      "no log extended-syslog EXTLOGNAME",
      NO_STR
      "Logging control\n"
      "Extended RFC5424 syslog (including file targets)\n"
      "Name identifying this syslog target\n")
{
	struct zlog_cfg_5424_user *cfg, ref;

	ref.name = (char *)extlogname;
	cfg = targets_find(&targets, &ref);

	if (!cfg) {
		vty_out(vty, "%% No extended syslog target named \"%s\"\n",
			extlogname);
		return CMD_WARNING;
	}

	log_5424_free(cfg, false);
	return CMD_SUCCESS;
}

/*    "format <rfc3164|rfc5424|local-syslogd|journald>$fmt" */
#define FORMAT_HELP                                                            \
	"Select log message formatting\n"                                      \
	"RFC3164 (legacy) syslog\n"                                            \
	"RFC5424 (modern) syslog, supports structured data (default)\n"        \
	"modified RFC3164 without hostname for local syslogd (/dev/log)\n"     \
	"journald (systemd log) native format\n"                               \
	/* end */

static enum zlog_5424_format log_5424_fmt(const char *fmt,
					  enum zlog_5424_format dflt)
{
	if (!fmt)
		return dflt;
	else if (!strcmp(fmt, "rfc5424"))
		return ZLOG_FMT_5424;
	else if (!strcmp(fmt, "rfc3164"))
		return ZLOG_FMT_3164;
	else if (!strcmp(fmt, "local-syslogd"))
		return ZLOG_FMT_LOCAL;
	else if (!strcmp(fmt, "journald"))
		return ZLOG_FMT_JOURNALD;

	return dflt;
}

DEFPY(log_5424_destination_file,
      log_5424_destination_file_cmd,
      "[no] destination file$type PATH "
		"[create$create [{user WORD|group WORD|mode PERMS}]"
		"|no-create$nocreate] "
		"[format <rfc3164|rfc5424|local-syslogd|journald>$fmt]",
      NO_STR
      "Log destination setup\n"
      "Log to file\n"
      "Path to destination\n"
      "Create file if it does not exist\n"
      "Set file owner\n"
      "User name\n"
      "Set file group\n"
      "Group name\n"
      "Set permissions\n"
      "File permissions (octal)\n"
      "Do not create file if it does not exist\n"
      FORMAT_HELP)
{
	VTY_DECLVAR_CONTEXT(zlog_cfg_5424_user, cfg);
	enum zlog_5424_dst dst;
	bool reconf = true, warn_perm = false;
	char *prev_user, *prev_group;
	mode_t perm_val = LOGFILE_MASK & 0666;
	enum zlog_5424_format fmtv;

	if (no)
		return reconf_clear_dst(cfg, vty);

	fmtv = log_5424_fmt(fmt, ZLOG_FMT_5424);

	if (perms) {
		char *errp = (char *)perms;

		perm_val = strtoul(perms, &errp, 8);
		if (*errp || errp == perms || perm_val == 0 ||
		    (perm_val & ~0666)) {
			vty_out(vty, "%% Invalid permissions value \"%s\"\n",
				perms);
			return CMD_WARNING;
		}
	}

	dst = (strcmp(type, "fifo") == 0) ? ZLOG_5424_DST_FIFO
					  : ZLOG_5424_DST_FILE;

	if (cfg->filename && !strcmp(path, cfg->filename) &&
	    dst == cfg->cfg.dst && cfg->cfg.active && cfg->cfg.fmt == fmtv)
		reconf = false;

	/* keep for compare below */
	prev_user = cfg->file_user;
	prev_group = cfg->file_group;
	cfg->file_user = NULL;
	cfg->file_group = NULL;

	clear_dst(cfg);

	cfg->filename = XSTRDUP(MTYPE_LOG_5424_DATA, path);
	cfg->cfg.dst = dst;
	cfg->cfg.filename = cfg->filename;
	cfg->cfg.fmt = fmtv;

	if (nocreate)
		cfg->cfg.file_nocreate = true;
	else {
		if (user) {
			struct passwd *pwent;

			warn_perm |= (prev_user && strcmp(user, prev_user));
			cfg->file_user = XSTRDUP(MTYPE_LOG_5424_DATA, user);

			errno = 0;
			pwent = getpwnam(user);
			if (!pwent)
				vty_out(vty,
					"%% Could not look up user \"%s\" (%s), file owner will be left untouched!\n",
					user,
					errno ? safe_strerror(errno)
					      : "No entry by this user name");
			else
				cfg->cfg.file_uid = pwent->pw_uid;
		}
		if (group) {
			struct group *grent;

			warn_perm |= (prev_group && strcmp(group, prev_group));
			cfg->file_group = XSTRDUP(MTYPE_LOG_5424_DATA, group);

			errno = 0;
			grent = getgrnam(group);
			if (!grent)
				vty_out(vty,
					"%% Could not look up group \"%s\" (%s), file group will be left untouched!\n",
					group,
					errno ? safe_strerror(errno)
					      : "No entry by this group name");
			else
				cfg->cfg.file_gid = grent->gr_gid;
		}
	}
	XFREE(MTYPE_LOG_5424_DATA, prev_user);
	XFREE(MTYPE_LOG_5424_DATA, prev_group);

	if (cfg->cfg.file_uid != (uid_t)-1 || cfg->cfg.file_gid != (gid_t)-1) {
		struct stat st;

		if (stat(cfg->filename, &st) == 0) {
			warn_perm |= (st.st_uid != cfg->cfg.file_uid);
			warn_perm |= (st.st_gid != cfg->cfg.file_gid);
		}
	}
	if (warn_perm)
		vty_out(vty,
			"%% Warning: ownership and permission bits are only applied when creating\n"
			"%%          log files.  Use system tools to change existing files.\n"
			"%%          FRR may also be missing necessary privileges to set these.\n");

	if (reconf)
		return reconf_dst(cfg, vty);

	return CMD_SUCCESS;
}

/* FIFOs are for legacy /dev/log implementations;  using this is very much not
 * recommended since it can unexpectedly block in logging calls.  Also the fd
 * would need to be reopened when the process at the other end restarts.  None
 * of this is handled - use at your own caution.  It's _HIDDEN for a purpose.
 */
ALIAS_HIDDEN(log_5424_destination_file,
	     log_5424_destination_fifo_cmd,
      "[no] destination fifo$type PATH "
		"[create$create [{owner WORD|group WORD|permissions PERMS}]"
		"|no-create$nocreate] "
		"[format <rfc3164|rfc5424|local-syslogd|journald>$fmt]",
      NO_STR
      "Log destination setup\n"
      "Log to filesystem FIFO\n"
      "Path to destination\n"
      "Create file if it does not exist\n"
      "Set file owner\n"
      "User name\n"
      "Set file group\n"
      "Group name\n"
      "Set permissions\n"
      "File permissions (octal)\n"
      "Do not create file if it does not exist\n"
      FORMAT_HELP)

static int dst_unix(struct vty *vty, const char *no, const char *path,
		    enum zlog_5424_format fmt, enum unix_special special)
{
	VTY_DECLVAR_CONTEXT(zlog_cfg_5424_user, cfg);

	if (no)
		return reconf_clear_dst(cfg, vty);

	cfg->unix_special = special;

	if (cfg->cfg.dst == ZLOG_5424_DST_UNIX && cfg->filename &&
	    !strcmp(path, cfg->filename) && cfg->cfg.active &&
	    cfg->cfg.fmt == fmt)
		return CMD_SUCCESS;

	clear_dst(cfg);

	cfg->filename = XSTRDUP(MTYPE_LOG_5424_DATA, path);
	cfg->cfg.dst = ZLOG_5424_DST_UNIX;
	cfg->cfg.filename = cfg->filename;
	cfg->cfg.fmt = fmt;

	cfg->cfg.reconn_backoff = 25;
	cfg->cfg.reconn_backoff_cur = 25;
	cfg->cfg.reconn_backoff_max = 10000;
	return reconf_dst(cfg, vty);
}

DEFPY(log_5424_destination_unix,
      log_5424_destination_unix_cmd,
      "[no] destination unix PATH "
		 "[format <rfc3164|rfc5424|local-syslogd|journald>$fmt]",
      NO_STR
      "Log destination setup\n"
      "Log to unix socket\n"
      "Unix socket path\n"
      FORMAT_HELP)
{
	VTY_DECLVAR_CONTEXT(zlog_cfg_5424_user, cfg);
	enum zlog_5424_format fmtv = log_5424_fmt(fmt, ZLOG_FMT_5424);

	return dst_unix(vty, no, path, fmtv, SPECIAL_NONE);
}

DEFPY(log_5424_destination_journald,
      log_5424_destination_journald_cmd,
      "[no] destination journald",
      NO_STR
      "Log destination setup\n"
      "Log directly to systemd's journald\n")
{
	return dst_unix(vty, no, "/run/systemd/journal/socket",
			ZLOG_FMT_JOURNALD, SPECIAL_JOURNALD);
}

#if defined(__FreeBSD_version) && (__FreeBSD_version >= 1200061)
#define ZLOG_FMT_DEV_LOG	ZLOG_FMT_5424
#elif defined(__NetBSD_Version__) && (__NetBSD_Version__ >= 500000000)
#define ZLOG_FMT_DEV_LOG	ZLOG_FMT_5424
#else
#define ZLOG_FMT_DEV_LOG	ZLOG_FMT_LOCAL
#endif

DEFPY(log_5424_destination_syslog,
      log_5424_destination_syslog_cmd,
      "[no] destination syslog [supports-rfc5424]$supp5424",
      NO_STR
      "Log destination setup\n"
      "Log directly to syslog\n"
      "Use RFC5424 format (please refer to documentation)\n")
{
	int format = supp5424 ? ZLOG_FMT_5424 : ZLOG_FMT_DEV_LOG;

	/* unfortunately, there is no way to detect 5424 support */
	return dst_unix(vty, no, "/dev/log", format, SPECIAL_SYSLOG);
}

/* could add something like
 *   "destination <udp|tcp>$proto <A.B.C.D|X:X::X:X> (1-65535)$port"
 * here, but there are 2 reasons not to do that:
 *
 *  - each FRR daemon would open its own connection, there's no system level
 *    aggregation.  That's the system's syslogd's job.  It likely also
 *    supports directing & filtering log messages with configurable rules.
 *  - we're likely not going to support DTLS or TLS for more secure logging;
 *    adding this would require a considerable amount of additional config
 *    and an entire TLS library to begin with.  A proper syslogd implements
 *    all of this, why reinvent the wheel?
 */

DEFPY(log_5424_destination_fd,
      log_5424_destination_fd_cmd,
      "[no] destination <fd <(0-63)$fd|envvar WORD>|stdout$fd1|stderr$fd2>"
		 "[format <rfc3164|rfc5424|local-syslogd|journald>$fmt]",
      NO_STR
      "Log destination setup\n"
      "Log to pre-opened file descriptor\n"
      "File descriptor number (must be open at startup)\n"
      "Read file descriptor number from environment variable\n"
      "Environment variable name\n"
      "Log to standard output\n"
      "Log to standard error output\n"
      FORMAT_HELP)
{
	VTY_DECLVAR_CONTEXT(zlog_cfg_5424_user, cfg);
	bool envvar_problem = false;
	enum zlog_5424_format fmtv;

	if (no)
		return reconf_clear_dst(cfg, vty);

	fmtv = log_5424_fmt(fmt, ZLOG_FMT_5424);

	if (envvar) {
		char *envval;

		envval = getenv(envvar);
		if (!envval)
			envvar_problem = true;
		else {
			char *errp = envval;

			fd = strtoul(envval, &errp, 0);
			if (errp == envval || *errp)
				envvar_problem = true;
		}

		if (envvar_problem)
			fd = -1;
	} else if (fd1)
		fd = 1;
	else if (fd2)
		fd = 2;

	if (cfg->cfg.dst == ZLOG_5424_DST_FD && cfg->cfg.fd == fd &&
	    cfg->cfg.active && cfg->cfg.fmt == fmtv)
		return CMD_SUCCESS;

	clear_dst(cfg);

	cfg->cfg.dst = ZLOG_5424_DST_FD;
	cfg->cfg.fd = fd;
	cfg->cfg.fmt = fmtv;
	if (envvar)
		cfg->envvar = XSTRDUP(MTYPE_LOG_5424_DATA, envvar);

	if (envvar_problem)
		vty_out(vty,
			"%% environment variable \"%s\" not present or invalid.\n",
			envvar);
	if (!frr_is_startup_fd(fd))
		vty_out(vty,
			"%% file descriptor %d was not open when this process was started\n",
			(int)fd);
	if (envvar_problem || !frr_is_startup_fd(fd))
		vty_out(vty,
			"%% configuration will be saved but has no effect currently\n");

	return reconf_dst(cfg, vty);
}

DEFPY(log_5424_destination_none,
      log_5424_destination_none_cmd,
      "[no] destination [none]",
      NO_STR
      "Log destination setup\n"
      "Deconfigure destination\n")
{
	VTY_DECLVAR_CONTEXT(zlog_cfg_5424_user, cfg);

	return reconf_clear_dst(cfg, vty);
}

/* end of destinations */

DEFPY(log_5424_prio,
      log_5424_prio_cmd,
      "[no] priority <emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>$levelarg",
      NO_STR
      "Set minimum message priority to include for this target\n"
      LOG_LEVEL_DESC)
{
	VTY_DECLVAR_CONTEXT(zlog_cfg_5424_user, cfg);
	int prio_min = log_level_match(levelarg);

	if (prio_min == cfg->cfg.prio_min)
		return CMD_SUCCESS;

	cfg->cfg.prio_min = prio_min;
	return reconf_meta(cfg, vty);
}

DEFPY(log_5424_facility,
      log_5424_facility_cmd,
      "[no] facility <kern|user|mail|daemon|auth|syslog|lpr|news|uucp|cron|local0|local1|local2|local3|local4|local5|local6|local7>$facilityarg",
      NO_STR
      "Set syslog facility to use\n"
      LOG_FACILITY_DESC)
{
	VTY_DECLVAR_CONTEXT(zlog_cfg_5424_user, cfg);
	int facility = facility_match(facilityarg);

	if (cfg->cfg.facility == facility)
		return CMD_SUCCESS;

	cfg->cfg.facility = facility;
	return reconf_meta(cfg, vty);
}

DEFPY(log_5424_meta,
      log_5424_meta_cmd,
      "[no] structured-data <code-location|version|unique-id|error-category|format-args>$option",
      NO_STR
      "Select structured data (key/value pairs) to include in each message\n"
      "FRR source code location\n"
      "FRR version\n"
      "Unique message identifier (XXXXX-XXXXX)\n"
      "Error category (EC numeric)\n"
      "Individual formatted log message arguments\n")
{
	VTY_DECLVAR_CONTEXT(zlog_cfg_5424_user, cfg);
	bool val = !no, *ptr;
	struct log_option *opt = log_opts;

	while (opt->name && strcmp(opt->name, option))
		opt++;
	if (!opt->name)
		return CMD_WARNING;

	ptr = (bool *)(((char *)&cfg->cfg) + opt->offs);
	if (*ptr == val)
		return CMD_SUCCESS;

	*ptr = val;
	return reconf_meta(cfg, vty);
}

DEFPY(log_5424_ts_prec,
      log_5424_ts_prec_cmd,
      "[no] timestamp precision (0-9)",
      NO_STR
      "Timestamp options\n"
      "Number of sub-second digits to include\n"
      "Number of sub-second digits to include\n")
{
	VTY_DECLVAR_CONTEXT(zlog_cfg_5424_user, cfg);
	uint32_t ts_flags = cfg->cfg.ts_flags;

	ts_flags &= ~ZLOG_TS_PREC;
	if (no)
		ts_flags |= DFLT_TS_FLAGS & ZLOG_TS_PREC;
	else
		ts_flags |= precision;

	if (ts_flags == cfg->cfg.ts_flags)
		return CMD_SUCCESS;

	cfg->cfg.ts_flags = ts_flags;
	return reconf_meta(cfg, vty);
}

DEFPY(log_5424_ts_local,
      log_5424_ts_local_cmd,
      "[no] timestamp local-time",
      NO_STR
      "Timestamp options\n"
      "Use local system time zone rather than UTC\n")
{
	VTY_DECLVAR_CONTEXT(zlog_cfg_5424_user, cfg);
	uint32_t ts_flags = cfg->cfg.ts_flags;

	ts_flags &= ~ZLOG_TS_UTC;
	if (no)
		ts_flags |= DFLT_TS_FLAGS & ZLOG_TS_UTC;
	else
		ts_flags |= (~DFLT_TS_FLAGS) & ZLOG_TS_UTC;

	if (ts_flags == cfg->cfg.ts_flags)
		return CMD_SUCCESS;

	cfg->cfg.ts_flags = ts_flags;
	return reconf_meta(cfg, vty);
}

void log_cli_cmd_init(void)
{
	install_element(CONFIG_NODE, &config_log_stdout_cmd);
	install_element(CONFIG_NODE, &no_config_log_stdout_cmd);
	install_element(CONFIG_NODE, &config_log_monitor_cmd);
	install_element(CONFIG_NODE, &no_config_log_monitor_cmd);
	install_element(CONFIG_NODE, &config_log_file_cmd);
	install_element(CONFIG_NODE, &config_log_dmn_file_cmd);
	install_element(CONFIG_NODE, &no_config_log_dmn_file_cmd);
	install_element(CONFIG_NODE, &no_config_log_file_cmd);
	install_element(CONFIG_NODE, &config_log_syslog_cmd);
	install_element(CONFIG_NODE, &no_config_log_syslog_cmd);
	install_element(CONFIG_NODE, &config_log_facility_cmd);
	install_element(CONFIG_NODE, &no_config_log_facility_cmd);
	install_element(CONFIG_NODE, &config_log_record_priority_cmd);
	install_element(CONFIG_NODE, &no_config_log_record_priority_cmd);
	install_element(CONFIG_NODE, &config_log_timestamp_precision_cmd);
	install_element(CONFIG_NODE, &no_config_log_timestamp_precision_cmd);
	install_element(CONFIG_NODE, &config_log_ec_cmd);
	install_element(CONFIG_NODE, &config_log_xid_cmd);

	install_element(CONFIG_NODE, &log_filter_cmd);
	install_element(CONFIG_NODE, &log_filter_clear_cmd);
	install_element(CONFIG_NODE, &config_log_filterfile_cmd);
	install_element(CONFIG_NODE, &no_config_log_filterfile_cmd);
	install_element(CONFIG_NODE, &log_immediate_mode_cmd);

	install_element(CONFIG_NODE, &debug_uid_backtrace_cmd);

	/* log_5424_cmd_init(); */
	cmd_variable_handler_register(log_5424_var_handlers);

	/* CLI commands. */
	install_node(&extlog_node);
	install_default(EXTLOG_NODE);

	install_element(CONFIG_NODE, &log_5424_target_cmd);
	install_element(CONFIG_NODE, &no_log_5424_target_cmd);

	install_element(EXTLOG_NODE, &log_5424_destination_file_cmd);
	install_element(EXTLOG_NODE, &log_5424_destination_fifo_cmd);
	install_element(EXTLOG_NODE, &log_5424_destination_unix_cmd);
	install_element(EXTLOG_NODE, &log_5424_destination_journald_cmd);
	install_element(EXTLOG_NODE, &log_5424_destination_syslog_cmd);
	install_element(EXTLOG_NODE, &log_5424_destination_fd_cmd);

	install_element(EXTLOG_NODE, &log_5424_meta_cmd);
	install_element(EXTLOG_NODE, &log_5424_prio_cmd);
	install_element(EXTLOG_NODE, &log_5424_facility_cmd);
	install_element(EXTLOG_NODE, &log_5424_ts_prec_cmd);
	install_element(EXTLOG_NODE, &log_5424_ts_local_cmd);
}


/* clang-format off */
static void logging_stdout_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_stdout_level_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_syslog_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_syslog_level_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_file_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_file_filename_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_file_level_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_filtered_file_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_filtered_file_filename_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_filtered_file_level_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_filter_text_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_daemon_file_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_daemon_file_filename_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_daemon_file_level_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_facility_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_record_priority_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_timestamp_precision_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_error_category_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_unique_id_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_immediate_mode_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_uid_backtrace_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_destination_file_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_destination_file_path_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_destination_file_user_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_destination_file_group_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_destination_file_mode_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_destination_file_no_create_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_destination_file_format_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_destination_fifo_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_destination_fifo_path_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_destination_fifo_user_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_destination_fifo_group_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_destination_fifo_mode_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_destination_fifo_no_create_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_destination_fifo_format_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_destination_unix_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_destination_unix_path_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_destination_unix_format_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_destination_journald_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_destination_syslog_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_destination_syslog_supports_rfc5424_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_destination_fd_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_destination_fd_number_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_destination_fd_envvar_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_destination_fd_stdout_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_destination_fd_stderr_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_destination_fd_format_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_destination_none_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_level_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_facility_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_code_location_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_version_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_error_category_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_unique_id_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_format_args_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_timestamp_precision_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
static void logging_extended_syslog_timestamp_local_time_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
const struct frr_yang_module_info frr_logging_cli_info = {
	.name = "frr-logging",
	.nodes = {
		{
			.xpath = "/frr-logging:logging/stdout",
			.cbs = {
				.cli_show = logging_stdout_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/stdout/level",
			.cbs = {
				.cli_show = logging_stdout_level_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/syslog",
			.cbs = {
				.cli_show = logging_syslog_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/syslog/level",
			.cbs = {
				.cli_show = logging_syslog_level_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/file",
			.cbs = {
				.cli_show = logging_file_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/file/filename",
			.cbs = {
				.cli_show = logging_file_filename_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/file/level",
			.cbs = {
				.cli_show = logging_file_level_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/filtered-file",
			.cbs = {
				.cli_show = logging_filtered_file_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/filtered-file/filename",
			.cbs = {
				.cli_show = logging_filtered_file_filename_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/filtered-file/level",
			.cbs = {
				.cli_show = logging_filtered_file_level_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/filter-text",
			.cbs = {
				.cli_show = logging_filter_text_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/daemon-file",
			.cbs = {
				.cli_show = logging_daemon_file_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/daemon-file/filename",
			.cbs = {
				.cli_show = logging_daemon_file_filename_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/daemon-file/level",
			.cbs = {
				.cli_show = logging_daemon_file_level_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/facility",
			.cbs = {
				.cli_show = logging_facility_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/record-priority",
			.cbs = {
				.cli_show = logging_record_priority_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/timestamp-precision",
			.cbs = {
				.cli_show = logging_timestamp_precision_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/error-category",
			.cbs = {
				.cli_show = logging_error_category_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/unique-id",
			.cbs = {
				.cli_show = logging_unique_id_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/immediate-mode",
			.cbs = {
				.cli_show = logging_immediate_mode_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/uid-backtrace",
			.cbs = {
				.cli_show = logging_uid_backtrace_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog",
			.cbs = {
				.cli_show = logging_extended_syslog_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/destination/file",
			.cbs = {
				.cli_show = logging_extended_syslog_destination_file_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/destination/file/path",
			.cbs = {
				.cli_show = logging_extended_syslog_destination_file_path_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/destination/file/user",
			.cbs = {
				.cli_show = logging_extended_syslog_destination_file_user_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/destination/file/group",
			.cbs = {
				.cli_show = logging_extended_syslog_destination_file_group_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/destination/file/mode",
			.cbs = {
				.cli_show = logging_extended_syslog_destination_file_mode_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/destination/file/no-create",
			.cbs = {
				.cli_show = logging_extended_syslog_destination_file_no_create_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/destination/file/format",
			.cbs = {
				.cli_show = logging_extended_syslog_destination_file_format_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/destination/fifo",
			.cbs = {
				.cli_show = logging_extended_syslog_destination_fifo_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/destination/fifo/path",
			.cbs = {
				.cli_show = logging_extended_syslog_destination_fifo_path_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/destination/fifo/user",
			.cbs = {
				.cli_show = logging_extended_syslog_destination_fifo_user_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/destination/fifo/group",
			.cbs = {
				.cli_show = logging_extended_syslog_destination_fifo_group_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/destination/fifo/mode",
			.cbs = {
				.cli_show = logging_extended_syslog_destination_fifo_mode_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/destination/fifo/no-create",
			.cbs = {
				.cli_show = logging_extended_syslog_destination_fifo_no_create_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/destination/fifo/format",
			.cbs = {
				.cli_show = logging_extended_syslog_destination_fifo_format_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/destination/unix",
			.cbs = {
				.cli_show = logging_extended_syslog_destination_unix_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/destination/unix/path",
			.cbs = {
				.cli_show = logging_extended_syslog_destination_unix_path_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/destination/unix/format",
			.cbs = {
				.cli_show = logging_extended_syslog_destination_unix_format_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/destination/journald",
			.cbs = {
				.cli_show = logging_extended_syslog_destination_journald_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/destination/syslog",
			.cbs = {
				.cli_show = logging_extended_syslog_destination_syslog_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/destination/syslog/supports-rfc5424",
			.cbs = {
				.cli_show = logging_extended_syslog_destination_syslog_supports_rfc5424_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/destination/fd",
			.cbs = {
				.cli_show = logging_extended_syslog_destination_fd_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/destination/fd/number",
			.cbs = {
				.cli_show = logging_extended_syslog_destination_fd_number_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/destination/fd/envvar",
			.cbs = {
				.cli_show = logging_extended_syslog_destination_fd_envvar_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/destination/fd/stdout",
			.cbs = {
				.cli_show = logging_extended_syslog_destination_fd_stdout_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/destination/fd/stderr",
			.cbs = {
				.cli_show = logging_extended_syslog_destination_fd_stderr_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/destination/fd/format",
			.cbs = {
				.cli_show = logging_extended_syslog_destination_fd_format_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/destination/none",
			.cbs = {
				.cli_show = logging_extended_syslog_destination_none_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/level",
			.cbs = {
				.cli_show = logging_extended_syslog_level_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/facility",
			.cbs = {
				.cli_show = logging_extended_syslog_facility_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/code-location",
			.cbs = {
				.cli_show = logging_extended_syslog_code_location_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/version",
			.cbs = {
				.cli_show = logging_extended_syslog_version_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/error-category",
			.cbs = {
				.cli_show = logging_extended_syslog_error_category_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/unique-id",
			.cbs = {
				.cli_show = logging_extended_syslog_unique_id_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/format-args",
			.cbs = {
				.cli_show = logging_extended_syslog_format_args_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/timestamp-precision",
			.cbs = {
				.cli_show = logging_extended_syslog_timestamp_precision_cli_write,
			}
		},
		{
			.xpath = "/frr-logging:logging/extended-syslog/timestamp-local-time",
			.cbs = {
				.cli_show = logging_extended_syslog_timestamp_local_time_cli_write,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
