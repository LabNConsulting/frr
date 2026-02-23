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
import ipaddress
import math
import os
import re

import pytest
from lib.topolog import logger
from munet.testing.util import retry

pytestmark = [pytest.mark.staticd]


def get_ip_networks(super_prefix, count):
    count_log2 = math.log(count, 2)
    if count_log2 != int(count_log2):
        count_log2 = int(count_log2) + 1
    else:
        count_log2 = int(count_log2)
    network = ipaddress.ip_network(super_prefix)
    return tuple(network.subnets(count_log2))[0:count]


def get_src_networks(src_prefix, count, default=""):
    if src_prefix is not None:
        for net in get_ip_networks(src_prefix, count):
            yield " from {}".format(net)
    else:
        for i in range(0, count):
            yield default


@retry(retry_timeout=30, initial_wait=0.1)
def check_kernel(r1, super_prefix, src_prefix, count, add, is_blackhole, vrf, matchvia):
    network = ipaddress.ip_network(super_prefix)
    vrfstr = f" vrf {vrf}" if vrf else ""
    if network.version == 6:
        kernel = r1.cmd_nostatus(f"ip -6 route show{vrfstr}")
    else:
        kernel = r1.cmd_nostatus(f"ip -4 route show{vrfstr}")

    logger.debug("checking kernel routing table%s:\n%s", vrfstr, kernel)
    for net, srcnet in zip(
        get_ip_networks(super_prefix, count), get_src_networks(src_prefix, count)
    ):
        netfull = str(net) + srcnet
        if not add:
            assert netfull + " nhid" not in kernel
            assert netfull + " via" not in kernel
            continue

        if is_blackhole:
            route = f"blackhole {netfull}(?: dev lo)? proto (static|196) metric 20"
        else:
            route = (
                f"{netfull}(?: nhid [0-9]+)? {matchvia} proto (static|196) metric 20"
            )
        if not re.search(route, kernel):
            return f"Failed to find \n'{route}'\n in \n'{kernel}'"


def get_config(
    r1,
    count,
    add=True,
    do_ipv6=False,
    do_ipv6_nexthop=False,
    do_sadr=False,
    via=None,
    vrf=None,
    use_cli=False,
):
    optype = "adding" if add else "removing"
    iptype = "IPv6" if do_ipv6 else "IPv4"

    #
    # Set the route details
    #
    src_prefs = [None, None]
    if do_ipv6 and do_sadr:
        # intentionally using overlapping prefix
        super_prefs = ["2001::/48", "2002::/48"]
        src_prefs = ["2001:db8:1111::/48", "2001:db8:2222::/48"]
    elif do_ipv6:
        super_prefs = ["2001::/48", "2002::/48"]
    elif do_ipv6_nexthop:
        super_prefs = ["11.0.0.0/8", "21.0.0.0/8"]
    else:
        super_prefs = ["10.0.0.0/8", "20.0.0.0/8"]

    super_prefix = super_prefs[1 if vrf else 0]
    src_prefix = src_prefs[1 if vrf else 0]

    matchvia = ""
    if via == "blackhole":
        pass
    elif via:
        matchvia = f"dev {via}"
    else:
        if vrf:
            via = "2102::2" if do_ipv6 or do_ipv6_nexthop else "102.0.0.2"
            matchvia = (
                f"via inet6 {via} dev r1-eth1"
                if not do_ipv6 and do_ipv6_nexthop
                else f"via {via} dev r1-eth1"
            )
        else:
            via = "2101::2" if do_ipv6 or do_ipv6_nexthop else "101.0.0.2"
            matchvia = (
                f"via inet6 {via} dev r1-eth0"
                if not do_ipv6 and do_ipv6_nexthop
                else f"via {via} dev r1-eth0"
            )

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

        for net, srcnet in zip(
            get_ip_networks(super_prefix, count), get_src_networks(src_prefix, count)
        ):
            if add:
                f.write("ip route {}{} {}\n".format(net, srcnet, via))
            else:
                f.write("no ip route {}{} {}\n".format(net, srcnet, via))

    return config_file, super_prefix, src_prefix, matchvia


def do_config_inner(
    r1,
    count,
    add=True,
    do_ipv6=False,
    do_ipv6_nexthop=False,
    do_sadr=False,
    via=None,
    vrf=None,
    use_cli=False,
):
    iptype = "IPv6" if do_ipv6 else "IPv4"

    config_file, super_prefix, src_prefix, matchvia = get_config(
        r1, count, add, do_ipv6, do_ipv6_nexthop, do_sadr, via, vrf, use_cli
    )

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
    check_kernel(
        r1, super_prefix, src_prefix, count, add, via == "blackhole", vrf, matchvia
    )

    optyped = "added" if add else "removed"
    vrfdbg = " in vrf {}".format(vrf) if vrf else ""
    logger.debug(
        "{} {} {} static routes under {}{} in {}s".format(
            optyped, count, iptype.lower(), super_prefix, vrfdbg, delta
        )
    )
