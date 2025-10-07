// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * October 10 2025, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2025, LabN Consulting, L.L.C.
 *
 */
#include <zebra.h>
#include "command.h"
#include "darr.h"
#include "vrf.h"
#include "vty.h"
#include "yang_cli_custom.h"

int yang_frr_backend_client_finish_show(struct vty *vty, LYD_FORMAT format, const char *result, int len)
{
	if (format == LYD_JSON || format == LYD_XML) {
		vty_out(vty, "FINISHING:\n");
		vty_out(vty, "%.*s\n", (int)len - 1, (const char *)result);
		return CMD_SUCCESS;
	}

	vty_out(vty, "%s\n", "*libyang-binary-value*");
	return CMD_SUCCESS;
}
