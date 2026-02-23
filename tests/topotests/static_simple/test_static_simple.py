#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2021, LabN Consulting, L.L.C.
# Copyright (c) 2019-2020 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#
"""
Test static route functionality
"""

import pytest
from lib.common_config import step
from lib.topogen import Topogen, TopoRouter
from staticutil import do_config_inner

pytestmark = [pytest.mark.staticd]


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {"s1": ("r1",), "s2": ("r1",)}

    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        # Setup VRF red
        router.net.add_l3vrf("red", 10)
        router.net.add_loop("lo-red")
        router.net.attach_iface_to_l3vrf("lo-red", "red")
        router.net.attach_iface_to_l3vrf(rname + "-eth1", "red")
        #
        # router.load_frr_config("frr.conf")
        # and select daemons to run
        router.load_config(TopoRouter.RD_ZEBRA, "zebra.conf")
        router.load_config(TopoRouter.RD_MGMTD)
        router.load_config(TopoRouter.RD_STATIC)

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


def enable_debug(router):
    router.vtysh_cmd("debug northbound callbacks configuration")


def disable_debug(router):
    router.vtysh_cmd("no debug northbound callbacks configuration")


def do_config(*args, **kwargs):
    do_config_inner(*args, do_ipv6=False, do_sadr=False, **kwargs)
    do_config_inner(*args, do_ipv6=False, do_ipv6_nexthop=True, **kwargs)
    do_config_inner(*args, do_ipv6=True, do_sadr=False, **kwargs)
    do_config_inner(*args, do_ipv6=True, do_sadr=True, **kwargs)


def guts(tgen, vrf, use_cli):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.routers()["r1"]

    count = 10
    step(f"add {count} via gateway", reset=True)
    do_config(r1, count, True, vrf=vrf, use_cli=use_cli)
    step(f"remove {count} via gateway")
    do_config(r1, count, False, vrf=vrf, use_cli=use_cli)

    via = f"lo-{vrf}" if vrf else "lo"
    step("add via loopback")
    do_config(r1, 1, True, via=via, vrf=vrf, use_cli=use_cli)
    step("remove via loopback")
    do_config(r1, 1, False, via=via, vrf=vrf, use_cli=use_cli)

    step("add via blackhole")
    do_config(r1, 1, True, via="blackhole", vrf=vrf, use_cli=use_cli)
    step("remove via blackhole")
    do_config(r1, 1, False, via="blackhole", vrf=vrf, use_cli=use_cli)


def test_static_cli(tgen):
    guts(tgen, "", True)


def test_static_file(tgen):
    guts(tgen, "", False)


def test_static_vrf_cli(tgen):
    guts(tgen, "red", True)


def test_static_vrf_file(tgen):
    guts(tgen, "red", False)
