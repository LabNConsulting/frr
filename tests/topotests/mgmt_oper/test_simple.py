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

import json
import logging
import pprint

import pytest
from lib.common_config import step
from lib.topogen import Topogen
from lib.topotest import json_cmp as tt_json_cmp

try:
    from deepdiff import DeepDiff as dd_json_cmp
except ImportError:
    dd_json_cmp = None

pytestmark = [pytest.mark.staticd]


def json_cmp(got, expect, exact_match):
    if dd_json_cmp:
        if exact_match:
            deep_diff = dd_json_cmp(expect, got)
            # Convert DeepDiff completely into dicts or lists at all levels
            json_diff = json.loads(deep_diff.to_json())
        else:
            json_diff = dd_json_cmp(expect, got, ignore_order=True)
            # Convert DeepDiff completely into dicts or lists at all levels
            # json_diff = json.loads(deep_diff.to_json())
            # Remove new fields in json object from diff
            if json_diff.get("dictionary_item_added") is not None:
                del json_diff["dictionary_item_added"]
            # Remove new json objects in json array from diff
            if (new_items := json_diff.get("iterable_item_added")) is not None:
                new_item_paths = list(new_items.keys())
                for path in new_item_paths:
                    if type(new_items[path]) is dict:
                        del new_items[path]
                if len(new_items) == 0:
                    del json_diff["iterable_item_added"]
        if not json_diff:
            json_diff = None
    else:
        json_diff = tt_json_cmp(got, expect, exact_match)
        json_diff = str(json_diff)
    return json_diff


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


def enable_debug(router):
    router.vtysh_cmd("debug northbound callbacks configuration")


def disable_debug(router):
    router.vtysh_cmd("no debug northbound callbacks configuration")


def test_oper_simple(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"].net

    query_results = [
        ("/frr-vrf:lib", "result-lib.json"),
        ("/frr-vrf:lib/vrf", "result-lib-vrf-nokey.json"),
        ('/frr-vrf:lib/vrf[name="default"]', "result-lib-vrf-default.json"),
        ('/frr-vrf:lib/vrf[name="red"]', "result-lib-vrf-red.json"),
        (
            '/frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra',
            "result-lib-vrf-zebra.json",
        ),
        (
            '/frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs',
            "result-lib-vrf-zebra-ribs.json",
        ),
        (
            '/frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/rib',
            "result-ribs-rib-nokeys.json",
        ),
        (
            '/frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/'
            'rib[afi-safi-name="frr-routing:ipv4-unicast"][table-id="254"]',
            "result-ribs-rib-ipv4-unicast.json",
        ),
        (
            '/frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/'
            'rib[afi-safi-name="frr-routing:ipv4-unicast"][table-id="254"]/route',
            "result-ribs-rib-route-nokey.json",
        ),
        # Missing entry
        (
            '/frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/'
            'rib[afi-safi-name="frr-routing:ipv4-unicast"][table-id="254"]/'
            'route[prefix="1.1.0.0/24"]',
            "result-empty.json",
        ),
        (
            '/frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/'
            'rib[afi-safi-name="frr-routing:ipv4-unicast"][table-id="254"]/'
            'route[prefix="1.1.1.0/24"]',
            "result-ribs-rib-route-prefix.json",
        ),
        # Leaf reference
        (
            '/frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/'
            'rib[afi-safi-name="frr-routing:ipv4-unicast"][table-id="254"]/'
            'route[prefix="1.1.1.0/24"]/route-entry[protocol="connected"]/metric',
            "result-singleton-metric.json",
        ),
    ]

    # To scrub new results from the system
    # for f in result-*; do
    #    sed -i -e 's,"uptime": ".*","uptime": "rubout",;s,"id": [0-9]*,"id": "rubout",' $f # noqa: E501
    #    sed -i -e 's,"vrf": "[0-9]*","vrf": "rubout",' $f # noqa
    # done

    # show mgmt get-data-tree /frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/rib[afi-safi-name="frr-routing:ipv4-unicast"][table-id="254"]/route[prefix="1.1.0.0/24"] # noqa: E501
    # show mgmt get-data-tree /frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/rib[afi-safi-name="frr-routing:ipv4-unicast"][table-id="254"]/route[prefix="1.1.1.0/24"] # noqa: E501

    qcmd = (
        r"vtysh -c 'show mgmt get-data-tree {}' "
        r"""| sed -e 's/"uptime": ".*"/"uptime": "rubout"/'"""
        r"""| sed -e 's/"vrf": "[0-9]*"/"vrf": "rubout"/'"""
        r"""| sed -e 's/"id": [0-9]*/"id": "rubout"/'"""
    )
    doreset = True
    dd_json_cmp = None
    for qr in query_results:
        step(f"Perform query '{qr[0]}'", reset=doreset)
        if doreset:
            doreset = False
        expected = open("simple-results/" + qr[1], encoding="ascii").read()
        output = r1.cmd_nostatus(qcmd.format(qr[0]))
        try:
            ojson = json.loads(output)
        except json.decoder.JSONDecodeError as error:
            logging.error("Error decoding json: %s\noutput:\n%s", error, output)
            raise
        ejson = json.loads(expected)
        if dd_json_cmp:
            cmpout = json_cmp(ojson, ejson, exact_match=True)
            if cmpout:
                logging.warning(
                    "-------DIFF---------\n%s\n---------DIFF----------",
                    pprint.pformat(cmpout),
                )
        else:
            cmpout = tt_json_cmp(ojson, ejson, exact=True)
            if cmpout:
                logging.warning(
                    "-------EXPECT--------\n%s\n------END-EXPECT------",
                    pprint.pformat(ejson),
                )
                logging.warning(
                    "--------GOT----------\n%s\n-------END-GOT--------",
                    pprint.pformat(ojson),
                )

        assert cmpout is None
