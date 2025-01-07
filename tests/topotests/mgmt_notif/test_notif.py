# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# January 23 2024, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2024, LabN Consulting, L.L.C.
#

"""
Test YANG Notifications
"""
import json
import os
import re

import pytest
from lib.topogen import Topogen
from lib.topotest import json_cmp
from oper import check_kernel_32

pytestmark = [pytest.mark.ripd, pytest.mark.staticd, pytest.mark.mgmtd]

CWD = os.path.dirname(os.path.realpath(__file__))


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {
        "s1": ("r1", "r2"),
    }

    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for _, router in router_list.items():
        router.load_frr_config("frr.conf")

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


def get_op_and_json(output):
    op = ""
    path = ""
    data = ""
    for line in output.split("\n"):
        if not line:
            continue
        if not op:
            m = re.match("#OP=([A-Z]*): (.*)", line)
            if m:
                op = m.group(1)
                path = m.group(2)
                continue
        data += line + "\n"
    if not op:
        assert False, f"No notifcation op present in:\n{output}"
    return op, path, data


def test_frontend_datastore_notification(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"].net

    check_kernel_32(r1, "11.11.11.11", 1, "")

    fe_client_path = CWD + "/../lib/fe_client.py --verbose"
    rc, _, _ = r1.cmd_status(fe_client_path + " --help")

    if rc:
        pytest.skip("No protoc or present cannot run test")

    output = r1.cmd_raises(
        fe_client_path
        + " --datastore --listen /frr-ripd:ripd/instance/state/routes/route"
    )
    op, path, data = get_op_and_json(output)
    jsout = json.loads(data)

    # Change expire time to 0 to be deterministic
    jsout["frr-ripd:ripd"]["instance"][0]["state"]["routes"]["route"][0]["nexthops"][
        "nexthop"
    ][0]["expire-time"] = 0
    expected = json.loads(
        '{"frr-ripd:ripd":{"instance":[{"vrf":"default","state":{"routes":{"route":[{"prefix":"22.22.22.22/32","nexthops":{"nexthop":[{"expire-time":0}]}}]}}}]}}'
    )
    result = json_cmp(jsout, expected)
    assert result is None


def test_frontend_notification(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"].net

    check_kernel_32(r1, "11.11.11.11", 1, "")

    fe_client_path = CWD + "/../lib/fe_client.py --verbose"
    rc, _, _ = r1.cmd_status(fe_client_path + " --help")

    if rc:
        pytest.skip("No protoc or present cannot run test")

    # Update config to non-matching authentication.
    conf = """
    conf t
    interface r1-eth0
    ip rip authentication string bar
    """
    r1.cmd_raises("vtysh", stdin=conf)

    try:
        output = r1.cmd_raises(
            fe_client_path + " --listen /frr-ripd:authentication-failure"
        )
        jsout = json.loads(output)
        expected = {"frr-ripd:authentication-failure": {"interface-name": "r1-eth0"}}
        result = json_cmp(jsout, expected)
        assert result is None

        output = r1.cmd_raises(
            fe_client_path + " --use-protobuf --listen /frr-ripd:authentication-failure"
        )
        jsout = json.loads(output)
        expected = {"frr-ripd:authentication-failure": {"interface-name": "r1-eth0"}}
        result = json_cmp(jsout, expected)
        assert result is None
    finally:
        # Update config to matching authentication.
        conf = """
        conf t
        interface r1-eth0
        ip rip authentication string foo
        """
        r1.cmd_raises("vtysh", stdin=conf)


def test_frontend_all_notification(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"].net

    check_kernel_32(r1, "11.11.11.11", 1, "")

    fe_client_path = CWD + "/../lib/fe_client.py --verbose"
    rc, _, _ = r1.cmd_status(fe_client_path + " --help")

    if rc:
        pytest.skip("No protoc or present cannot run test")

    # Update config to non-matching authentication.
    conf = """
    conf t
    interface r1-eth0
    ip rip authentication string bar
    """
    r1.cmd_raises("vtysh", stdin=conf)

    try:
        # The first notifications is a frr-ripd:authentication-type-failure
        # All the rest are frr-ripd:authentication-failure so we check for both.
        output = r1.cmd_raises(fe_client_path + " --listen /")
        jsout = json.loads(output)
        expected = {
            "frr-ripd:authentication-type-failure": {"interface-name": "r1-eth0"}
        }
        result = json_cmp(jsout, expected)
        if result is not None:
            expected = {
                "frr-ripd:authentication-failure": {"interface-name": "r1-eth0"}
            }
            result = json_cmp(jsout, expected)
        assert result is None

        output = r1.cmd_raises(fe_client_path + " --use-protobuf --listen /")
        jsout = json.loads(output)
        expected = {"frr-ripd:authentication-failure": {"interface-name": "r1-eth0"}}
        result = json_cmp(jsout, expected)
        assert result is None
    finally:
        # Update config to matching authentication.
        conf = """
        conf t
        interface r1-eth0
        ip rip authentication string foo
        """
        r1.cmd_raises("vtysh", stdin=conf)


def test_backend_notification(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"].net

    check_kernel_32(r1, "11.11.11.11", 1, "")

    be_client_path = "/usr/lib/frr/mgmtd_testc"
    rc, _, _ = r1.cmd_status(be_client_path + " --help")

    if rc:
        pytest.skip("No mgmtd_testc")

    # Update config to non-matching authentication.
    conf = """
    conf t
    interface r1-eth0
    ip rip authentication string bar
    """
    r1.cmd_raises("vtysh", stdin=conf)

    try:
        output = r1.cmd_raises(
            be_client_path
            + " --timeout 20 --log file:mgmt_testc.log --listen /frr-ripd"
        )
        jsout = json.loads(output)
        expected = {"frr-ripd:authentication-failure": {"interface-name": "r1-eth0"}}
        result = json_cmp(jsout, expected)
        assert result is None
    finally:
        # Update config to matching authentication.
        conf = """
        conf t
        interface r1-eth0
        ip rip authentication string foo
        """
        r1.cmd_raises("vtysh", stdin=conf)
