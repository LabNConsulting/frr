#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2021, LabN Consulting, L.L.C.
# Copyright (c) 2019-2020 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#
# noqa: E501
#
"""
Test static route functionality
"""
import pytest
from lib.topogen import Topogen
from oper import check_kernel_32, do_oper_test

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
        router.load_frr_config("frr-simple.conf")

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


def test_oper_simple(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    query_results = [
        ("/frr-vrf:lib", "simple-results/result-lib.json"),
        ("/frr-vrf:lib/vrf", "simple-results/result-lib-vrf-nokey.json"),
        (
            '/frr-vrf:lib/vrf[name="default"]',
            "simple-results/result-lib-vrf-default.json",
        ),
        ('/frr-vrf:lib/vrf[name="red"]', "simple-results/result-lib-vrf-red.json"),
        (
            '/frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra',
            "simple-results/result-lib-vrf-zebra.json",
        ),
        (
            '/frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs',
            "simple-results/result-lib-vrf-zebra-ribs.json",
        ),
        (
            '/frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/rib',
            "simple-results/result-ribs-rib-nokeys.json",
        ),
        (
            '/frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/'
            'rib[afi-safi-name="frr-routing:ipv4-unicast"][table-id="254"]',
            "simple-results/result-ribs-rib-ipv4-unicast.json",
        ),
        (
            '/frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/'
            'rib[afi-safi-name="frr-routing:ipv4-unicast"][table-id="254"]/route',
            "simple-results/result-ribs-rib-route-nokey.json",
        ),
        # Missing entry
        (
            '/frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/'
            'rib[afi-safi-name="frr-routing:ipv4-unicast"][table-id="254"]/'
            'route[prefix="1.1.0.0/24"]',
            "simple-results/result-empty.json",
        ),
        (
            '/frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/'
            'rib[afi-safi-name="frr-routing:ipv4-unicast"][table-id="254"]/'
            'route[prefix="1.1.1.0/24"]',
            "simple-results/result-ribs-rib-route-prefix.json",
        ),
        # Leaf reference
        (
            '/frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/'
            'rib[afi-safi-name="frr-routing:ipv4-unicast"][table-id="254"]/'
            'route[prefix="1.1.1.0/24"]/route-entry[protocol="connected"]/metric',
            "simple-results/result-singleton-metric.json",
        ),
    ]

    r1 = tgen.gears["r1"].net
    check_kernel_32(r1, "11.11.11.11", 1, "")
    do_oper_test(tgen, query_results)

    # To scrub new results from the system
    # for f in result-*; do
    #    sed -i -e 's,"uptime": ".*","uptime": "rubout",;s,"id": [0-9]*,"id": "rubout",' $f # noqa: E501
    #    sed -i -e 's,"vrf": "[0-9]*","vrf": "rubout",' $f # noqa
    # done

    # show mgmt get-data /frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/rib[afi-safi-name="frr-routing:ipv4-unicast"][table-id="254"]/route[prefix="1.1.0.0/24"] # noqa: E501
    # show mgmt get-data /frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/rib[afi-safi-name="frr-routing:ipv4-unicast"][table-id="254"]/route[prefix="1.1.1.0/24"] # noqa: E501
