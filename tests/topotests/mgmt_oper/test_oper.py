#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2021, LabN Consulting, L.L.C.
# Copyright (c) 2019-2020 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#
"""
Test static route functionality
"""

import datetime
import ipaddress
import json
import logging
import math
import os
import pprint
import re
import time

import pytest
from lib.common_config import retry, step
from lib.topogen import Topogen
from lib.topolog import logger
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

    topodef = {"s1": ("r1",), "s2": ("r1",), "s3": ("r1",), "s4": ("r1",)}

    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        # Setup VRF red
        router.net.add_l3vrf("red", 10)
        router.net.add_loop("lo-red")
        router.net.attach_iface_to_l3vrf("lo-red", "red")
        router.net.attach_iface_to_l3vrf(rname + "-eth2", "red")
        router.net.attach_iface_to_l3vrf(rname + "-eth3", "red")
        router.load_frr_config("frr.conf")

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


def get_ip_networks(super_prefix, count):
    count_log2 = math.log(count, 2)
    if count_log2 != int(count_log2):
        count_log2 = int(count_log2) + 1
    else:
        count_log2 = int(count_log2)
    network = ipaddress.ip_network(super_prefix)
    return tuple(network.subnets(count_log2))[0:count]


def enable_debug(router):
    router.vtysh_cmd("debug northbound callbacks configuration")


def disable_debug(router):
    router.vtysh_cmd("no debug northbound callbacks configuration")


@retry(retry_timeout=30, initial_wait=0.1)
def check_kernel(r1, super_prefix, count, add, is_blackhole, vrf, matchvia):
    network = ipaddress.ip_network(super_prefix)
    vrfstr = f" vrf {vrf}" if vrf else ""
    if network.version == 6:
        kernel = r1.run(f"ip -6 route show{vrfstr}")
    else:
        kernel = r1.run(f"ip -4 route show{vrfstr}")

    logger.debug("checking kernel routing table%s:\n%s", vrfstr, kernel)
    for i, net in enumerate(get_ip_networks(super_prefix, count)):
        if not add:
            assert str(net) not in kernel
            continue

        if is_blackhole:
            route = f"blackhole {str(net)} proto (static|196) metric 20"
        else:
            route = (
                f"{str(net)}(?: nhid [0-9]+)? {matchvia} "
                "proto (static|196) metric 20"
            )
        assert re.search(route, kernel), f"Failed to find \n'{route}'\n in \n'{kernel}'"


def do_config(
    r1,
    count,
    add=True,
    do_ipv6=False,
    via=None,
    vrf=None,
    use_cli=False,
):
    optype = "adding" if add else "removing"
    iptype = "IPv6" if do_ipv6 else "IPv4"

    #
    # Set the route details
    #

    if vrf:
        super_prefix = "2111::/48" if do_ipv6 else "111.0.0.0/8"
    else:
        super_prefix = "2055::/48" if do_ipv6 else "55.0.0.0/8"

    matchvia = ""
    if via == "blackhole":
        pass
    elif via:
        matchvia = f"dev {via}"
    else:
        if vrf:
            via = "2102::2" if do_ipv6 else "3.3.3.2"
            matchvia = f"via {via} dev r1-eth1"
        else:
            via = "2101::2" if do_ipv6 else "1.1.1.2"
            matchvia = f"via {via} dev r1-eth0"

    vrfdbg = " in vrf {}".format(vrf) if vrf else ""
    logger.debug("{} {} static {} routes{}".format(optype, count, iptype, vrfdbg))

    #
    # Generate config file in a retrievable place
    #

    config_file = os.path.join(
        r1.logdir, r1.name, "{}-routes-{}.conf".format(iptype.lower(), optype)
    )
    with open(config_file, "w") as f:
        if use_cli:
            f.write("configure terminal\n")
        if vrf:
            f.write("vrf {}\n".format(vrf))

        for i, net in enumerate(get_ip_networks(super_prefix, count)):
            if add:
                f.write("ip route {} {}\n".format(net, via))
            else:
                f.write("no ip route {} {}\n".format(net, via))

    #
    # Load config file.
    #

    if use_cli:
        load_command = 'vtysh < "{}"'.format(config_file)
    else:
        load_command = 'vtysh -f "{}"'.format(config_file)
    tstamp = datetime.datetime.now()
    output = r1.cmd_raises(load_command)
    delta = (datetime.datetime.now() - tstamp).total_seconds()

    #
    # Verify the results are in the kernel
    #
    check_kernel(r1, super_prefix, count, add, via == "blackhole", vrf, matchvia)

    optyped = "added" if add else "removed"
    logger.debug(
        "{} {} {} static routes under {}{} in {}s".format(
            optyped, count, iptype.lower(), super_prefix, vrfdbg, delta
        )
    )


def test_oper(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"].net

    query_results = [
        ("/frr-vrf:lib", "result-lib.json"),
        ("/frr-vrf:lib/vrf", "result-lib-vrf-nokey.json"),
        ('/frr-vrf:lib/vrf[name="default"]', "result-lib-vrf-default.json"),
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
    ]

    # To scrub new results from the system
    # for f in result-*; do
    #    sed -i -e 's,"uptime": ".*","uptime": "rubout",;s,"id": [0-9]*,"id": "rubout",' $f # noqa
    #    sed -i -e 's,"vrf": "[0-9]*","vrf": "rubout",' $f # noqa
    # done

    time.sleep(2)

    qcmd = (
        r"vtysh -c 'show mgmt get-data-tree {}' "
        r"""| sed -e 's/"uptime": ".*"/"uptime": "rubout"/'"""
        r"""| sed -e 's/"vrf": "[0-9]*"/"vrf": "rubout"/'"""
        r"""| sed -e 's/"id": [0-9]*/"id": "rubout"/'"""
    )
    doreset = True
    # dd_json_cmp = None
    for qr in query_results:
        step(f"Perform query '{qr[0]}'", reset=doreset)
        if doreset:
            doreset = False
        expected = open("oper-results/" + qr[1], encoding="ascii").read()
        output = r1.cmd_nostatus(qcmd.format(qr[0]))
        ojson = json.loads(output)
        ejson = json.loads(expected)
        if dd_json_cmp:
            cmpout = json_cmp(ojson, ejson, exact_match=True)
            if cmpout:
                logging.warning(
                    "-------DIFF---------\n%s\n---------DIFF----------",
                    pprint.pformat(cmpout),
                )
        else:
            cmpout = json_cmp(ojson, ejson, exact_match=True)
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


# To generate results

# vtysh -c 'show mgmt get-data-tree /frr-vrf:lib'  > ~chopps/w/frr/tests/topotests/mgmt_oper/oper-results/result-lib.json # noqa: 501
# vtysh -c 'show mgmt get-data-tree /frr-vrf:lib/vrf'  > ~chopps/w/frr/tests/topotests/mgmt_oper/oper-results/result-lib-vrf-nokey.json # noqa: 501
# vtysh -c 'show mgmt get-data-tree /frr-vrf:lib/vrf[name="default"]'  > ~chopps/w/frr/tests/topotests/mgmt_oper/oper-results/result-lib-vrf-default.json # noqa: 501
# vtysh -c 'show mgmt get-data-tree /frr-vrf:lib/vrf[name="red"]'  > ~chopps/w/frr/tests/topotests/mgmt_oper/oper-results/result-lib-vrf-red.json # noqa: 501
# vtysh -c 'show mgmt get-data-tree /frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra'  > ~chopps/w/frr/tests/topotests/mgmt_oper/oper-results/result-lib-vrf-zebra.json # noqa: 501
# vtysh -c 'show mgmt get-data-tree /frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs'  > ~chopps/w/frr/tests/topotests/mgmt_oper/oper-results/result-lib-vrf-zebra-ribs.json # noqa: 501
# vtysh -c 'show mgmt get-data-tree /frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/rib[afi-safi-name="frr-routing:ipv4-unicast"][table-id="254"]'  > ~chopps/w/frr/tests/topotests/mgmt_oper/oper-results/result-ribs-rib-ipv4-unicast.json # noqa: 501
# vtysh -c 'show mgmt get-data-tree /frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/rib'  > ~chopps/w/frr/tests/topotests/mgmt_oper/oper-results/result-ribs-rib-nokeys.json # noqa: 501
# # noqa: 501

# add rubout
# for f in result-*; do    sed -i -e 's,"uptime": ".*","uptime": "rubout",;s,"id": [0-9]*,"id": "rubout",' $f ; done # noqa: 501

# should not differ
# diff result-lib.json result-lib-vrf-nokey.json
# diff result-lib-vrf-zebra.json result-lib-vrf-zebra-ribs.json

# examine by eye to make sure is correct
