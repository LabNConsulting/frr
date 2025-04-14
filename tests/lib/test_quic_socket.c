// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Title/Function of file
 * Copyright (C) 2025  LabN Consulting, L.L.C.
 */

#include <zebra.h>
#include <string.h>

#include "memory.h"
#include "frr_pthread.h"
#include "frr_socket.h"

struct frr_pthread *pth_shared;

static void test_noop (void) {
	printf("Noop test\n");
}

void (*tests[])(void) = {
	test_noop,
};

int main(int argc, char **argv)
{
	struct frr_pthread_attr shared = {
		.start = frr_pthread_attr_default.start,
		.stop = frr_pthread_attr_default.stop,
	};

	printf("Starting\n");
	frr_pthread_init();
	pth_shared = frr_pthread_new(&shared, "FRR socket shared pthread", "frrsock shared");
	frr_pthread_run(pth_shared, NULL);
	frr_pthread_wait_running(pth_shared);
	rcu_read_unlock();

	printf("Setting up FRR socket library\n");
	assert(frr_socket_lib_init(pth_shared->master) == 0);

	for (unsigned int i = 0; i < array_size(tests); i++)
		tests[i]();

	printf("Cleaning up FRR socket library\n");
	frr_socket_lib_finish();

	printf("Finishing\n");
	frr_pthread_stop(pth_shared, NULL);
	frr_pthread_finish();
	rcu_read_lock();
	rcu_shutdown();

	printf("Done\n");
	return 0;
}
