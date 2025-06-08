// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2021  David Lamparter for NetDEF, Inc.
 */

#include "zebra.h"
#include "zlog_5424.h"

#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

#include "lib/command.h"
#include "lib/libfrr.h"
#include "lib/log_vty.h"


int target_cmp(const struct zlog_cfg_5424_user *a, const struct zlog_cfg_5424_user *b)
{
	return strcmp(a->name, b->name);
}

DEFINE_QOBJ_TYPE(zlog_cfg_5424_user);

#include "lib/zlog_5424_cli_clippy.c"

static int log_5424_node_exit(struct vty *vty)
{
	VTY_DECLVAR_CONTEXT(zlog_cfg_5424_user, cfg);

	if ((cfg->reconf_dst || cfg->reconf_meta) && vty->type != VTY_FILE)
		vty_out(vty, "%% applying changes.\n");

	if (cfg->reconf_dst)
		zlog_5424_apply_dst(&cfg->cfg);
	else if (cfg->reconf_meta)
		zlog_5424_apply_meta(&cfg->cfg);

	cfg->reconf_dst = cfg->reconf_meta = false;
	return 1;
}

#if defined(__FreeBSD_version) && (__FreeBSD_version >= 1200061)
#define ZLOG_FMT_DEV_LOG ZLOG_FMT_5424
#elif defined(__NetBSD_Version__) && (__NetBSD_Version__ >= 500000000)
#define ZLOG_FMT_DEV_LOG ZLOG_FMT_5424
#else
#define ZLOG_FMT_DEV_LOG ZLOG_FMT_LOCAL
#endif

static int log_5424_config_write(struct vty *vty)
{
	struct zlog_cfg_5424_user *cfg;

	frr_each (targets, &targets, cfg) {
		const char *fmt_str = "";

		vty_out(vty, "log extended %s\n", cfg->name);

		(void)fmt_str; /* clang-SA */
		switch (cfg->cfg.fmt) {
		case ZLOG_FMT_5424:
			fmt_str = " format rfc5424";
			break;
		case ZLOG_FMT_3164:
			fmt_str = " format rfc3164";
			break;
		case ZLOG_FMT_LOCAL:
			fmt_str = " format local-syslogd";
			break;
		case ZLOG_FMT_JOURNALD:
			fmt_str = " format journald";
			break;
		}

		switch (cfg->cfg.dst) {
		case ZLOG_5424_DST_NONE:
			vty_out(vty, " ! no destination configured\n");
			break;

		case ZLOG_5424_DST_FD:
			if (cfg->cfg.fmt == ZLOG_FMT_5424)
				fmt_str = "";

			if (cfg->envvar)
				vty_out(vty, " destination fd envvar %s%s\n",
					cfg->envvar, fmt_str);
			else if (cfg->cfg.fd == 1)
				vty_out(vty, " destination stdout%s\n",
					fmt_str);
			else if (cfg->cfg.fd == 2)
				vty_out(vty, " destination stderr%s\n",
					fmt_str);
			else
				vty_out(vty, " destination fd %d%s\n",
					cfg->cfg.fd, fmt_str);
			break;

		case ZLOG_5424_DST_FILE:
		case ZLOG_5424_DST_FIFO:
			if (cfg->cfg.fmt == ZLOG_FMT_5424)
				fmt_str = "";

			vty_out(vty, " destination %s %s",
				(cfg->cfg.dst == ZLOG_5424_DST_FIFO) ? "fifo"
								     : "file",
				cfg->filename);

			if (cfg->cfg.file_nocreate)
				vty_out(vty, " no-create");
			else if (cfg->file_user || cfg->file_group ||
				 cfg->cfg.file_mode != (LOGFILE_MASK & 0666)) {
				vty_out(vty, " create");

				if (cfg->file_user)
					vty_out(vty, " user %s",
						cfg->file_user);
				if (cfg->file_group)
					vty_out(vty, " group %s",
						cfg->file_group);
				if (cfg->cfg.file_mode != (LOGFILE_MASK & 0666))
					vty_out(vty, " mode %04o",
						cfg->cfg.file_mode);
			}
			vty_out(vty, "%s\n", fmt_str);
			break;

		case ZLOG_5424_DST_UNIX:
			switch (cfg->unix_special) {
			case SPECIAL_NONE:
				vty_out(vty, " destination unix %s%s\n",
					cfg->filename, fmt_str);
				break;
			case SPECIAL_SYSLOG:
				if (cfg->cfg.fmt == ZLOG_FMT_DEV_LOG)
					vty_out(vty, " destination syslog\n");
				else
					vty_out(vty,
						" destination syslog supports-rfc5424\n");
				break;
			case SPECIAL_JOURNALD:
				vty_out(vty, " destination journald\n");
				break;
			}
			break;
		}

		if (cfg->cfg.prio_min != LOG_DEBUG)
			vty_out(vty, " priority %s\n",
				zlog_priority_str(cfg->cfg.prio_min));
		if (cfg->cfg.facility != DFLT_FACILITY)
			vty_out(vty, " facility %s\n",
				facility_name(cfg->cfg.facility));

		for (struct log_option *opt = log_opts; opt->name; opt++) {
			bool *ptr = (bool *)(((char *)&cfg->cfg) + opt->offs);

			if (*ptr != opt->dflt)
				vty_out(vty, " %sstructured-data %s\n",
					*ptr ? "" : "no ", opt->name);
		}

		if ((cfg->cfg.ts_flags ^ DFLT_TS_FLAGS) & ZLOG_TS_PREC)
			vty_out(vty, " timestamp precision %u\n",
				cfg->cfg.ts_flags & ZLOG_TS_PREC);

		if ((cfg->cfg.ts_flags ^ DFLT_TS_FLAGS) & ZLOG_TS_UTC) {
			if (cfg->cfg.ts_flags & ZLOG_TS_UTC)
				vty_out(vty, " no timestamp local-time\n");
			else
				vty_out(vty, " timestamp local-time\n");
		}

		vty_out(vty, "!\n");
	}
	return 0;
}

static int log_5424_show(struct vty *vty)
{
	struct zlog_cfg_5424_user *cfg;

	frr_each (targets, &targets, cfg) {
		vty_out(vty, "\nExtended log target %pSQq\n", cfg->name);

		switch (cfg->cfg.dst) {
		case ZLOG_5424_DST_NONE:
			vty_out(vty,
				"  Inactive (no destination configured)\n");
			break;

		case ZLOG_5424_DST_FD:
			if (cfg->envvar)
				vty_out(vty,
					"  logging to fd %d from environment variable %pSE\n",
					cfg->cfg.fd, cfg->envvar);
			else if (cfg->cfg.fd == 1)
				vty_out(vty, "  logging to stdout\n");
			else if (cfg->cfg.fd == 2)
				vty_out(vty, "  logging to stderr\n");
			else
				vty_out(vty, "  logging to fd %d\n",
					cfg->cfg.fd);
			break;

		case ZLOG_5424_DST_FILE:
		case ZLOG_5424_DST_FIFO:
		case ZLOG_5424_DST_UNIX:
			vty_out(vty, "  logging to %s: %pSE\n",
				(cfg->cfg.dst == ZLOG_5424_DST_FIFO) ? "fifo"
				: (cfg->cfg.dst == ZLOG_5424_DST_UNIX)
					? "unix socket"
					: "file",
				cfg->filename);
			break;
		}

		vty_out(vty, "  log level: %s, facility: %s\n",
			zlog_priority_str(cfg->cfg.prio_min),
			facility_name(cfg->cfg.facility));

		bool any_meta = false, first = true;

		for (struct log_option *opt = log_opts; opt->name; opt++) {
			bool *ptr = (bool *)(((char *)&cfg->cfg) + opt->offs);

			any_meta |= *ptr;
		}

		if (!any_meta)
			continue;

		switch (cfg->cfg.fmt) {
		case ZLOG_FMT_5424:
		case ZLOG_FMT_JOURNALD:
			vty_out(vty, "  structured data: ");

			for (struct log_option *opt = log_opts; opt->name;
			     opt++) {
				bool *ptr = (bool *)(((char *)&cfg->cfg) +
						     opt->offs);

				if (*ptr) {
					vty_out(vty, "%s%s", first ? "" : ", ",
						opt->name);
					first = false;
				}
			}
			break;

		case ZLOG_FMT_3164:
		case ZLOG_FMT_LOCAL:
			vty_out(vty,
				"  structured data is not supported by the selected format\n");
			break;
		}

		vty_out(vty, "\n");

		size_t lost_msgs;
		int last_errno;
		bool stale_errno;
		struct timeval err_ts;
		int64_t since;

		zlog_5424_state(&cfg->cfg, &lost_msgs, &last_errno,
				&stale_errno, &err_ts);
		vty_out(vty, "  number of lost messages: %zu\n", lost_msgs);

		if (last_errno == 0)
			since = 0;
		else
			since = monotime_since(&err_ts, NULL);
		vty_out(vty,
			"  last error: %s (%lld.%06llds ago, currently %s)\n",
			last_errno ? safe_strerror(last_errno) : "none",
			since / 1000000LL, since % 1000000LL,
			stale_errno ? "OK" : "erroring");
	}
	return 0;
}

struct cmd_node extlog_node = {
	.name = "extended",
	.node = EXTLOG_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-ext-log)# ",

	.config_write = log_5424_config_write,
	.node_exit = log_5424_node_exit,
};

/* hooks */

static int log_5424_early_init(struct event_loop *master);
static int log_5424_rotate(void);
static int log_5424_fini(void);

__attribute__((_CONSTRUCTOR(475))) static void zlog_5424_startup_init(void)
{
	hook_register(frr_early_init, log_5424_early_init);
	hook_register(zlog_rotate, log_5424_rotate);
	hook_register(frr_fini, log_5424_fini);
}

static int log_5424_early_init(struct event_loop *master)
{
	log_5424_master = master;

	return 0;
}

static int log_5424_rotate(void)
{
	struct zlog_cfg_5424_user *cfg;

	frr_each (targets, &targets, cfg)
		if (!zlog_5424_rotate(&cfg->cfg))
			zlog_err(
				"log rotation on extended log target %s failed",
				cfg->name);

	return 0;
}

static int log_5424_fini(void)
{
	struct zlog_cfg_5424_user *cfg;

	while ((cfg = targets_pop(&targets)))
		log_5424_free(cfg, true);

	log_5424_master = NULL;

	return 0;
}

void log_5424_cmd_init(void)
{
	hook_register(zlog_cli_show, log_5424_show);
}
