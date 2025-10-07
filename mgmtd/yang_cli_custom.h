// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * October 10 2025, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2025, LabN Consulting, L.L.C.
 *
 */
#ifndef _FRR_YANG_CLI_CUSTOM_H
#define _FRR_YANG_CLI_CUSTOM_H

#include <zebra.h>
#include "vty.h"

extern int yang_frr_backend_client_finish_show(struct vty *, LYD_FORMAT, const char *, int);

#endif /* _FRR_YANG_CLI_CUSTOM_H */
