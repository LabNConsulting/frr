# SPDX-License-Identifier: GPL-2.0-or-later
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# September 14 2024, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2024, LabN Consulting, L.L.C.
#

"""
Test autogen YANG show commands
"""
import pytest
from lib.topogen import Topogen

pytestmark = [pytest.mark.staticd, pytest.mark.ripd]


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {
        "net1": ("r1:eth0", "r2:eth0"),
        "net2": ("r1:eth1", "r2:eth1"),
        "net3": ("r2:eth2", "r3:eth0"),
    }
    tgen = Topogen(topodef, request.module.__name__)

    tgen.start_topology()
    for router in tgen.routers().values():
        router.load_frr_config("frr.conf")

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


def test_restconf_options_op(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"].net
    r1.cmd_raises("ls -l")
