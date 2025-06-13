/*
 * June 11 2025, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2025, LabN Consulting, L.L.C.
 *
 */
#include <zebra.h>
#include "northbound.h"
extern int log_nb_get_level(const struct lyd_node *dnode, const char *xpath);

extern int logging_extended_syslog_create(struct nb_cb_create_args *args);
extern int logging_extended_syslog_destroy(struct nb_cb_destroy_args *args);
extern int logging_extended_syslog_destination_file_create(struct nb_cb_create_args *args);
extern int logging_extended_syslog_destination_file_destroy(struct nb_cb_destroy_args *args);
extern int logging_extended_syslog_destination_file_path_modify(struct nb_cb_modify_args *args);
extern int logging_extended_syslog_destination_file_user_modify(struct nb_cb_modify_args *args);
extern int logging_extended_syslog_destination_file_user_destroy(struct nb_cb_destroy_args *args);
extern int logging_extended_syslog_destination_file_group_modify(struct nb_cb_modify_args *args);
extern int logging_extended_syslog_destination_file_group_destroy(struct nb_cb_destroy_args *args);
extern int logging_extended_syslog_destination_file_mode_modify(struct nb_cb_modify_args *args);
extern int logging_extended_syslog_destination_file_mode_destroy(struct nb_cb_destroy_args *args);
extern int logging_extended_syslog_destination_file_no_create_modify(struct nb_cb_modify_args *args);
extern int logging_extended_syslog_destination_file_format_modify(struct nb_cb_modify_args *args);
extern int logging_extended_syslog_destination_fifo_create(struct nb_cb_create_args *args);
extern int logging_extended_syslog_destination_fifo_destroy(struct nb_cb_destroy_args *args);
extern int logging_extended_syslog_destination_fifo_path_modify(struct nb_cb_modify_args *args);
extern int logging_extended_syslog_destination_fifo_user_modify(struct nb_cb_modify_args *args);
extern int logging_extended_syslog_destination_fifo_user_destroy(struct nb_cb_destroy_args *args);
extern int logging_extended_syslog_destination_fifo_group_modify(struct nb_cb_modify_args *args);
extern int logging_extended_syslog_destination_fifo_group_destroy(struct nb_cb_destroy_args *args);
extern int logging_extended_syslog_destination_fifo_mode_modify(struct nb_cb_modify_args *args);
extern int logging_extended_syslog_destination_fifo_mode_destroy(struct nb_cb_destroy_args *args);
extern int logging_extended_syslog_destination_fifo_no_create_modify(struct nb_cb_modify_args *args);
extern int logging_extended_syslog_destination_fifo_format_modify(struct nb_cb_modify_args *args);
extern int logging_extended_syslog_destination_unix_create(struct nb_cb_create_args *args);
extern int logging_extended_syslog_destination_unix_destroy(struct nb_cb_destroy_args *args);
extern int logging_extended_syslog_destination_unix_path_modify(struct nb_cb_modify_args *args);
extern int logging_extended_syslog_destination_unix_format_modify(struct nb_cb_modify_args *args);
extern int logging_extended_syslog_destination_journald_create(struct nb_cb_create_args *args);
extern int logging_extended_syslog_destination_journald_destroy(struct nb_cb_destroy_args *args);
extern int logging_extended_syslog_destination_syslog_create(struct nb_cb_create_args *args);
extern int logging_extended_syslog_destination_syslog_destroy(struct nb_cb_destroy_args *args);
extern int logging_extended_syslog_destination_syslog_supports_rfc5424_modify(struct nb_cb_modify_args *args);
extern int logging_extended_syslog_destination_fd_create(struct nb_cb_create_args *args);
extern int logging_extended_syslog_destination_fd_destroy(struct nb_cb_destroy_args *args);
extern int logging_extended_syslog_destination_fd_number_modify(struct nb_cb_modify_args *args);
extern int logging_extended_syslog_destination_fd_number_destroy(struct nb_cb_destroy_args *args);
extern int logging_extended_syslog_destination_fd_envvar_modify(struct nb_cb_modify_args *args);
extern int logging_extended_syslog_destination_fd_envvar_destroy(struct nb_cb_destroy_args *args);
extern int logging_extended_syslog_destination_fd_stdout_create(struct nb_cb_create_args *args);
extern int logging_extended_syslog_destination_fd_stdout_destroy(struct nb_cb_destroy_args *args);
extern int logging_extended_syslog_destination_fd_stderr_create(struct nb_cb_create_args *args);
extern int logging_extended_syslog_destination_fd_stderr_destroy(struct nb_cb_destroy_args *args);
extern int logging_extended_syslog_destination_fd_format_modify(struct nb_cb_modify_args *args);
extern int logging_extended_syslog_destination_none_create(struct nb_cb_create_args *args);
extern int logging_extended_syslog_destination_none_destroy(struct nb_cb_destroy_args *args);
extern int logging_extended_syslog_level_modify(struct nb_cb_modify_args *args);
extern int logging_extended_syslog_facility_modify(struct nb_cb_modify_args *args);
extern int logging_extended_syslog_code_location_modify(struct nb_cb_modify_args *args);
extern int logging_extended_syslog_version_modify(struct nb_cb_modify_args *args);
extern int logging_extended_syslog_error_category_modify(struct nb_cb_modify_args *args);
extern int logging_extended_syslog_unique_id_modify(struct nb_cb_modify_args *args);
extern int logging_extended_syslog_format_args_modify(struct nb_cb_modify_args *args);
extern int logging_extended_syslog_timestamp_precision_modify(struct nb_cb_modify_args *args);
extern int logging_extended_syslog_timestamp_local_time_modify(struct nb_cb_modify_args *args);
