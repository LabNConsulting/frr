#!/usr/bin/env python
# SPDX-License-Identifier: ISC

import os
import re
import signal
import subprocess
import sys
import time

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(CWD)
sys.path.append(os.path.join(CWD, "../"))

import pytest

from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from util_pcap import PerInterfacePcapManager

pytestmark = [pytest.mark.ospfd]

PCAP_MANAGER = None

TOPOLOGY = """
         r1               r2               r3               r4
          |                |                |                |
          +----------------+----------------+----------------+
                         10.0.0.0/24 broadcast LAN

    Initial election:
      r4 = DR
      r3 = BDR
      r1/r2 = DROther
"""


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    r3 = tgen.add_router("r3")
    r4 = tgen.add_router("r4")

    lan = tgen.add_switch("s-lan")
    lan.add_link(r1, nodeif="eth1")
    lan.add_link(r2, nodeif="eth1")
    lan.add_link(r3, nodeif="eth1")
    lan.add_link(r4, nodeif="eth1")


def setup_module(mod):
    global PCAP_MANAGER

    logger.info("OSPF DR failure issue topology:\n%s", TOPOLOGY)

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, rname, "frr.conf"))

    tgen.start_router()

    PCAP_MANAGER = PerInterfacePcapManager(
        outdir=os.path.join(tgen.logdir, "pcaps"), tag="ospf-dr-failure"
    )
    PCAP_MANAGER.start_all(tgen)
    logger.info("pcap captures started in %s", PCAP_MANAGER.outdir)


def teardown_module():
    tgen = get_topogen()

    if PCAP_MANAGER is not None:
        PCAP_MANAGER.stop_all(tgen)
        logger.info("pcap captures stopped in %s", PCAP_MANAGER.outdir)

    tgen.stop_topology()


def _route_present(router, prefix, next_hop=None):
    data = router.vtysh_cmd(f"show ip route {prefix} json", isjson=True)
    routes = data.get(prefix, [])
    if not routes:
        return False

    for route in routes:
        if route.get("protocol") != "ospf":
            continue
        if next_hop is None:
            return True
        for nh in route.get("nexthops", []):
            if nh.get("ip") == next_hop and nh.get("active") is True:
                return True
    return False


def _wait_for_route(router, prefix, next_hop=None, present=True, count=30, wait=1):
    def _poll():
        seen = _route_present(router, prefix, next_hop)
        if seen == present:
            return None
        return f"route {prefix} present={seen}"

    _, result = topotest.run_and_expect(_poll, None, count=count, wait=wait)
    state = "present" if present else "absent"
    assert result is None, f"Route {prefix} not {state} on {router.name}"


def _start_continuous_ping(router, destination, source=None, interval=0.05):
    command = ["ping", "-n", "-D", "-i", str(interval)]
    if source:
        command.extend(["-I", source])
    command.append(destination)

    proc = router.popen(command)
    logger.info("started continuous ping on %s: %r", router.name, command)
    time.sleep(0.5)
    return proc, command


def _stop_process(proc):
    if proc.poll() is None:
        proc.send_signal(signal.SIGINT)

    try:
        stdout, stderr = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate(timeout=5)

    return stdout or "", stderr or ""


def _stop_continuous_ping(proc):
    return _stop_process(proc)


def _write_continuous_ping_log(tgen, output, stderr):
    path = os.path.join(tgen.logdir, "r1_to_r3_continuous_ping.log")
    with open(path, "w", encoding="utf-8") as logf:
        if output:
            logf.write(output)
        if stderr:
            logf.write("\n--- stderr ---\n")
            logf.write(stderr)
    logger.info("continuous ping output saved to %s", path)
    return path


def _start_route_monitor(router):
    command = ["ip", "-ts", "-4", "monitor", "route"]
    proc = router.popen(command)
    logger.info("started route monitor on %s: %r", router.name, command)
    time.sleep(0.2)
    return proc, command


def _write_route_monitor_log(tgen, output, stderr):
    path = os.path.join(tgen.logdir, "r1_ip_monitor_route.log")
    with open(path, "w", encoding="utf-8") as logf:
        if output:
            logf.write(output)
        if stderr:
            logf.write("\n--- stderr ---\n")
            logf.write(stderr)
    logger.info("route monitor output saved to %s", path)
    return path


def _assert_no_ping_loss(output, log_path):
    match = re.search(
        r"(\d+) packets transmitted,\s+(\d+) (?:packets )?received.*?"
        r"([0-9.]+)% packet loss",
        output,
        re.S,
    )
    assert match, f"Could not parse continuous ping summary; see {log_path}"

    tx, rx = int(match.group(1)), int(match.group(2))
    loss_pct = float(match.group(3))
    logger.info("continuous ping summary: tx=%s rx=%s loss=%s%%", tx, rx, loss_pct)

    assert tx > 0, f"Continuous ping sent no packets; see {log_path}"
    assert loss_pct == 0.0 and rx == tx, (
        f"Continuous ping lost packets: tx={tx} rx={rx} loss={loss_pct}%; "
        f"see {log_path}"
    )


def _assert_no_ping_seq_gaps(output, log_path):
    seqs = [int(seq) for seq in re.findall(r"icmp_seq=(\d+)", output)]
    assert seqs, f"Continuous ping produced no ICMP replies; see {log_path}"

    missing = sorted(set(range(seqs[0], seqs[-1] + 1)) - set(seqs))
    assert not missing, (
        f"Continuous ping has missing ICMP sequences: {missing[:20]}; "
        f"see {log_path}"
    )


def _neighbor_info(router, rid):
    data = router.vtysh_cmd("show ip ospf neighbor json", isjson=True)
    nbrs = data.get("neighbors", {})
    entries = nbrs.get(rid)
    if not entries:
        return None
    return entries[0]


def _wait_for_neighbor_role(router, rid, role, state_prefix=None, count=40, wait=1):
    def _poll():
        info = _neighbor_info(router, rid)
        if info is None:
            return "missing"
        if info.get("role") != role:
            return info.get("role", "unknown-role")
        if state_prefix and not info.get("nbrState", "").startswith(state_prefix):
            return info.get("nbrState", "unknown-state")
        return None

    _, result = topotest.run_and_expect(_poll, None, count=count, wait=wait)
    assert result is None, f"Neighbor {rid} did not reach {state_prefix}/{role}"


def test_dr_failure_preserves_routes_to_surviving_neighbors():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r4 = tgen.gears["r4"]

    # Initial broadcast roles should be deterministic.
    _wait_for_neighbor_role(r1, "4.4.4.4", "DR", state_prefix="Full")
    _wait_for_neighbor_role(r1, "3.3.3.3", "Backup", state_prefix="Full")
    _wait_for_neighbor_role(r1, "2.2.2.2", "DROther", state_prefix="2-Way")

    # Baseline reachability from the monitor router.
    _wait_for_route(r1, "2.2.2.2/32", "10.0.0.2")
    _wait_for_route(r1, "3.3.3.3/32", "10.0.0.3")
    _wait_for_route(r1, "4.4.4.4/32", "10.0.0.4")

    surviving = {
        "2.2.2.2/32": "10.0.0.2",
        "3.3.3.3/32": "10.0.0.3",
    }
    lost = set()
    ping_proc = None
    ping_output = ""
    ping_stderr = ""
    ping_log_path = None
    route_monitor_proc = None
    route_monitor_output = ""
    route_monitor_stderr = ""
    route_monitor_log_path = None

    try:
        route_monitor_proc, route_monitor_command = _start_route_monitor(r1)
        ping_proc, ping_command = _start_continuous_ping(
            r1, "3.3.3.3", source="1.1.1.1"
        )

        r4.link_enable("eth1", enabled=False)

        deadline = time.monotonic() + 15
        promoted = False
        while time.monotonic() < deadline:
            for prefix, nh in surviving.items():
                if not _route_present(r1, prefix, nh):
                    lost.add(prefix)

            r3_info = _neighbor_info(r1, "3.3.3.3")
            if (
                r3_info is not None
                and r3_info.get("role") == "DR"
                and r3_info.get("nbrState", "").startswith("Full")
            ):
                promoted = True

            if (
                promoted
                and all(
                    _route_present(r1, prefix, nh) for prefix, nh in surviving.items()
                )
                and not _route_present(r1, "4.4.4.4/32")
            ):
                break

            time.sleep(0.5)

        assert promoted, "r3 was not promoted from BDR to DR after r4 failed"

        _wait_for_neighbor_role(r1, "3.3.3.3", "DR", state_prefix="Full")
        _wait_for_route(r1, "4.4.4.4/32", present=False, count=20, wait=1)
        _wait_for_route(r1, "2.2.2.2/32", "10.0.0.2")
        _wait_for_route(r1, "3.3.3.3/32", "10.0.0.3")
    finally:
        if ping_proc is not None:
            ping_output, ping_stderr = _stop_continuous_ping(ping_proc)
            logger.info("continuous ping command: %r", ping_command)
            ping_log_path = _write_continuous_ping_log(
                tgen, ping_output, ping_stderr
            )
        if route_monitor_proc is not None:
            route_monitor_output, route_monitor_stderr = _stop_process(
                route_monitor_proc
            )
            logger.info("route monitor command: %r", route_monitor_command)
            route_monitor_log_path = _write_route_monitor_log(
                tgen, route_monitor_output, route_monitor_stderr
            )
        r4.link_enable("eth1", enabled=True)

    assert ping_log_path is not None, "Continuous ping did not run"
    assert route_monitor_log_path is not None, "Route monitor did not run"
    _assert_no_ping_loss(ping_output, ping_log_path)
    _assert_no_ping_seq_gaps(ping_output, ping_log_path)

    assert not lost, (
        "Routes to surviving routers were withdrawn during DR failover: "
        + ", ".join(sorted(lost))
    )


if __name__ == "__main__":
    sys.exit(pytest.main(["-s"] + sys.argv[1:]))
