// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * September 9 2024, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2024, LabN Consulting, L.L.C.
 */

#include <lib/libfrr.h>
#include <lib/zebra.h>
#include <lib/privs.h>
#include <lib/version.h>
#include "mgmt_be_client.h"

zebra_capabilities_t _caps_p[] = {ZCAP_NET_RAW, ZCAP_BIND, ZCAP_SYS_ADMIN};

struct zebra_privs_t rustlibd_privs = {
#if defined(FRR_USER)
	.user = FRR_USER,
#endif
#if defined FRR_GROUP
	.group = FRR_GROUP,
#endif
#ifdef VTY_GROUP
	.vty_group = VTY_GROUP,
#endif
	.caps_p = _caps_p,
	.cap_num_p = array_size(_caps_p),
	.cap_num_i = 0
};


static const struct frr_yang_module_info *const rustlibd_yang_modules[] = {};

/* clang-format off */
FRR_DAEMON_INFO(rustlibd, RUST,
		.vty_port = RUSTLIBD_VTY_PORT,
		.proghelp = "Implementation of the RUST daemon template.",

		.privs = &rustlibd_privs,

		.yang_modules = rustlibd_yang_modules,
		.n_yang_modules = array_size(rustlibd_yang_modules),

		/* mgmtd will load the per-daemon config file now */
		.flags = FRR_NO_SPLIT_CONFIG,
	);
/* clang-format on */

struct event_loop *master;
struct mgmt_be_client *mgmt_be_client;

extern struct frr_daemon_info *rust_get_daemon_info(void);
struct frr_daemon_info *rust_get_daemon_info(void)
{
	return &rustlibd_di;
}

static struct option longopts[] = { { 0 } };

extern void _rust_preinit(struct frr_daemon_info *daemon);
extern void _rust_init(struct event_loop *master);
extern void _rust_prerun(struct event_loop *master);

/* Main routine of ripd. */
int main(int argc, char **argv)
{
	frr_preinit(&rustlibd_di, argc, argv);
	_rust_preinit(&rustlibd_di);

	frr_opt_add("", longopts, "");

	/* Command line option parse. */
	while (1) {
		int opt;

		opt = frr_getopt(argc, argv, NULL);
		if (opt == EOF)
			break;

		switch (opt) {
		case 0:
			break;
		default:
			frr_help_exit(1);
		}
	}

	/* Prepare master thread. */
	master = frr_init();
	_rust_init(master);
	mgmt_be_client = mgmt_be_client_create("rustlibd", NULL, 0, master);

	frr_config_fork();

	_rust_prerun(master);
	frr_run(master);

	/* Not reached. */
	return 0;
}
