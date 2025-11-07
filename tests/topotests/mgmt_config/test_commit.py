# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# October 29 2025, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2025, LabN Consulting, L.L.C.
#
"""
Test mgmtd commit

"""
import subprocess

import pytest
from lib.topogen import Topogen

pytestmark = [pytest.mark.staticd, pytest.mark.mgmtd]


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {"s1": ("r1",)}
    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    tgen.gears["r1"].load_frr_config("frr.conf")

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


def sendline(p, line):
    p.stdin.write(line + "\n")


def test_commit_client_quit(tgen, stepf):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1g = tgen.gears["r1"]
    r1 = r1g.net
    p = None

    try:
        stepf("Test kill client after lock")
        p = r1.popen("vtysh", stdin=subprocess.PIPE)
        sendline(p, "conf t file-lock")
        p.kill()
        p = None
        # Verify we can still change config
        r1.cmd_raises("vtysh -c 'conf t' -c 'hostname r1-1'")

        stepf("Test kill client after set-config")
        p = r1.popen("vtysh", stdin=subprocess.PIPE)
        sendline(p, "conf t file-lock")
        sendline(p, "mgmt set-config /frr-logging:logging/stdout/level info")
        p.kill()
        p = None
        # Verify we can still change config
        r1.cmd_raises("vtysh -c 'conf t' -c 'hostname r1-2'")

        stepf("Test kill client after commit check")
        p = r1.popen("vtysh", stdin=subprocess.PIPE)
        sendline(p, "conf t file-lock")
        sendline(p, "mgmt set-config /frr-logging:logging/stdout/level debug")
        sendline(p, "mgmt commit check")
        p.kill()
        p = None
        # Verify we can still change config
        r1.cmd_raises("vtysh -c 'conf t' -c 'hostname r1-3'")

        stepf("Test kill client after lock")
        p = r1.popen("vtysh", stdin=subprocess.PIPE)
        sendline(p, "conf t file-lock")
        sendline(p, "mgmt set-config /frr-logging:logging/stdout/level info")
        sendline(p, "mgmt commit check")
        sendline(p, "mgmt commit apply")
        p.kill()
        p = None
        # Verify we can still change config
        r1.cmd_raises("vtysh -c 'conf t' -c 'hostname r1-4'")

        stepf("Test kill client after end")
        p = r1.popen("vtysh", stdin=subprocess.PIPE)
        sendline(p, "conf t file-lock")
        sendline(p, "mgmt set-config /frr-logging:logging/stdout/level debug")
        sendline(p, "mgmt commit check")
        sendline(p, "mgmt commit apply")
        sendline(p, "end")
        p.kill()
        p = None
        # Verify we can still change config
        r1.cmd_raises("vtysh -c 'conf t' -c 'hostname r1-5'")
    finally:
        if p:
            p.kill()


def test_commit_check(tgen):
    r1 = tgen.gears["r1"]

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1.cmd_raises(
        "vtysh -c 'conf t file-lock' -c 'mgmt set-config /frr-logging:logging/stdout/level debug' -c 'mgmt commit check' -c 'mgmt commit apply'"
    )

    r1.vtysh_multicmd(
        """
        mgmt set-config /frr-logging:logging/stdout/level info
        mgmt commit check
        mgmt commit apply
    """,
        pretty_output=False,
    )

    output = r1.cmd_raises("vtysh -c 'show mgmt datastore'")
    print(output)

    r1.vtysh_multicmd(
        """
        mgmt set-config /frr-logging:logging/stdout/level debug
        mgmt commit apply
    """,
        pretty_output=False,
    )

    r1.cmd_raises("vtysh -c 'show mgmt datastore'")
    print(output)
