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

extern void log_5425_cli_cmd_init(void);

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

	log_5424_cmd_init();
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
