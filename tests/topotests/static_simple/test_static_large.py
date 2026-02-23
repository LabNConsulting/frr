# SPDX-License-Identifier: ISC
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# December 31 2025, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2025, LabN Consulting, L.L.C.
#
"""
Test static route functionality
"""

import datetime
import logging
import re
import time

import pytest
from lib.common_config import step
from lib.topogen import Topogen
from munet.base import Timeout
from munet.watchlog import WatchLog
from staticutil import check_kernel, do_config_inner, get_config

pytestmark = [pytest.mark.staticd]


@pytest.fixture(scope="function")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {
        "s1": ("r1",),
    }

    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config("frr.conf")

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


def scan_for_match(wl, regex, timeout=60):
    regex = re.compile(regex)
    to = Timeout(timeout)
    logging.debug("scanning %s for %s", wl.path, regex)
    while not to:
        content = wl.snapshot_refresh()
        if m := regex.search(content):
            logging.debug("found '%s' in %s", m.group(0), wl.path)
            return m
        time.sleep(0.5)
    raise TimeoutError(f"timeout waiting for {regex} in {wl.path}")


def guts(tgen, use_cli):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1g = tgen.gears["r1"]
    r1 = r1g.net
    wl = WatchLog(r1.rundir / "mgmtd.log")

    # Get a config file with `count` static IPv4 routes
    count = 50 * 1024
    config_file, suppfx, srcpfx, via = get_config(r1, count, add=True, use_cli=use_cli)

    step(f"add {count} via gateway", reset=True)
    if use_cli:
        load_command = 'vtysh < "{}"'.format(config_file)
    else:
        load_command = 'vtysh -f "{}"'.format(config_file)
    tstamp = datetime.datetime.now()

    wl.snapshot()
    config_proc = r1.popen(load_command)

    # Wait for part of the configuration to be applied
    scan_for_match(wl, re.escape(r"ip route 10.0.4.0/24 101.0.0.2"), timeout=300)
    logging.info("partial config applied, waiting for completion")

    # # Now stop the router to see if we get any core files
    # r1.stopRouter(False)

    # # Wait for the configuration to complete
    status = config_proc.wait()
    delta = (datetime.datetime.now() - tstamp).total_seconds()
    logging.debug(
        "All %s routes in FRR. status %s elapsed %s",
        count,
        status,
        delta.total_seconds(),
    )

    delta = (datetime.datetime.now() - tstamp).total_seconds()
    check_kernel(
        r1,
        suppfx,
        srcpfx,
        count,
        True,
        via == "blackhole",
        None,
        via,
        retry_timeout=300.0,
    )

    logging.info("All %s routes in kernel. elapsed: %ss", count, delta.total_seconds())

    showmem = r1.cmd_raises("show memory")
    logging.deubg("memory use: %s", showmem)


def test_static_file(tgen):
    guts(tgen, False)


def test_static_cli(tgen):
    guts(tgen, True)
