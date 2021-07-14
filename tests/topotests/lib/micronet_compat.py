# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# July 11 2021, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2021, LabN Consulting, L.L.C
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; see the file COPYING; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
#
import logging
import os

from .micronet import LinuxNamespace, Micronet


def set_log_level(level):
    # logger.setLevel(level)
    del level


setLogLevel = set_log_level  # mininet compat


class Node(LinuxNamespace):
    """Node (mininet compat)."""

    def __init__(self, name, **kwargs):
        """
        Create a Node.
        """
        self.params = kwargs

        if "private_mounts" in kwargs:
            private_mounts = kwargs["private_mounts"]
        else:
            private_mounts = kwargs.get("privateDirs", [])

        super(Node, self).__init__(name, private_mounts=private_mounts)

    def config(self, lo="up", **params):
        """Called by Micronet when topology is built (but not started)."""
        # mininet brings up loopback here.
        del params
        del lo

    def intfNames(self):
        return []

    # Run a command in a new window (gnome-terminal, screen, tmux, xterm)
    def runInWindow(self, cmd, title=None):
        logging.warning("runInWindow(%s)", cmd)
        if "TMUX" not in os.environ and "STY" not in os.environ:
            return

        del title

        nscmd = self.pre_cmd_str + cmd
        if "TMUX" in os.environ:
            tmux_pane_arg = os.getenv("TMUX_PANE", "")
            tmux_pane_arg = " -t " + tmux_pane_arg if tmux_pane_arg else ""
            wcmd = "tmux split-window -h"
            if tmux_pane_arg:
                wcmd += tmux_pane_arg
            cmd = "{} {}".format(wcmd, nscmd)
        elif "STY" in os.environ:
            if os.path.exists(
                "/run/screen/S-{}/{}".format(os.environ["USER"], os.environ["STY"])
            ):
                wcmd = "screen"
            else:
                wcmd = "sudo -u {} screen".format(os.environ["SUDO_USER"])
            cmd = "{} {}".format(wcmd, nscmd)
        self.cmd(cmd)

        # Re-adjust the layout
        if "TMUX" in os.environ:
            self.cmd("tmux select-layout main-horizontal")


class Topo(object):  # pylint: disable=R0205
    """
    Topology object passed to Micronet to build actual topology.
    """

    def __init__(self, *args, **kwargs):
        self.params = kwargs
        self.name = kwargs["name"] if "name" in kwargs else "unnamed"
        self.tgen = kwargs["tgen"] if "tgen" in kwargs else None

        logging.debug("%s: Creating", self)

        self.nodes = {}
        self.hosts = {}
        self.switches = {}
        self.links = {}

        # if "no_init_build" in kwargs and kwargs["no_init_build"]:
        #     return

        # This needs to move outside of here. Current tests count on it being called on init;
        # however, b/c of this there is lots of twisty logic to support topogen based tests where
        # the build routine must get get_topogen() so topogen can then set it's topogen.topo to the
        # class it's in the process of instantiating (this one) b/c build will use topogen before
        # the instantiation completes.
        self.build(*args, **kwargs)

    def __str__(self):
        return "Topo({})".format(self.name)

    def build(self, *args, **kwargs):
        "Overriden by real class"
        del args
        del kwargs
        raise NotImplementedError("Needs to be overriden")

    def addHost(self, name, **kwargs):
        logging.debug("%s: addHost %s", self, name)
        self.nodes[name] = dict(**kwargs)
        self.hosts[name] = self.nodes[name]
        return name

    addNode = addHost

    def addSwitch(self, name, **kwargs):
        logging.debug("%s: addSwitch %s", self, name)
        self.nodes[name] = dict(**kwargs)
        if "cls" in self.nodes[name]:
            logging.warning("Overriding Bridge class with micronet.Bridge")
            del self.nodes[name]["cls"]
        self.switches[name] = self.nodes[name]
        return name

    def addLink(self, name1, name2, **kwargs):
        """Link up switch and a router.

        possible kwargs:
        - intfName1 :: switch-side interface name - sometimes missing
        - intfName2 :: router-side interface name
        - addr1 :: switch-side MAC used by test_ldp_topo1 only
        - addr2 :: router-side MAC used by test_ldp_topo1 only
        """
        if1 = (
            kwargs["intfName1"]
            if "intfName1" in kwargs
            else "{}-{}".format(name1, name2)
        )
        if2 = (
            kwargs["intfName2"]
            if "intfName2" in kwargs
            else "{}-{}".format(name2, name1)
        )

        logging.debug("%s: addLink %s %s if1: %s if2: %s", self, name1, name2, if1, if2)

        if name1 in self.switches:
            assert name2 in self.hosts
            swname, rname = name1, name2
        elif name2 in self.switches:
            assert name1 in self.hosts
            swname, rname = name2, name1
            if1, if2 = if2, if1
        else:
            # p2p link
            assert name1 in self.hosts
            assert name2 in self.hosts
            swname, rname = name1, name2

        if swname not in self.links:
            self.links[swname] = {}

        if rname not in self.links[swname]:
            self.links[swname][rname] = set()

        self.links[swname][rname].add((if1, if2))


class Mininet(Micronet):
    """
    Mininet using Micronet.
    """

    def __init__(self, controller=None, topo=None):
        """
        Create a Micronet.
        """
        assert topo
        assert not controller

        Mininet.g_inst = self

        self.host_params = {}
        self.prefix_len = 8
        self.topo = topo

        logging.debug("%s: Creating", self)

        super(Mininet, self).__init__()

        if topo.hosts:
            logging.debug("Adding hosts: %s", topo.hosts.keys())
            for name in topo.hosts:
                self.add_host(name, **topo.hosts[name])

        if topo.switches:
            logging.debug("Adding switches: %s", topo.switches.keys())
            for name in topo.switches:
                self.add_switch(name, **topo.switches[name])

        if topo.links:
            logging.debug("Adding links: ")
            for swname in sorted(topo.links):
                for rname in sorted(topo.links[swname]):
                    for link in topo.links[swname][rname]:
                        self.add_link(swname, rname, link[0], link[1])

        # Now that topology is built, configure hosts
        if self.hosts:
            logging.debug("Configuring hosts: %s", self.hosts.keys())
            for name, host in self.hosts.items():
                first_intf = self.host_intfs[name][0] if self.host_intfs[name] else None
                params = self.host_params[name]

                if "ip" in params and first_intf:
                    host.cmd(
                        "ip addr add {}/{} dev {}".format(
                            params["ip"], self.prefix_len, first_intf
                        )
                    )

                if "defaultRoute" in params:
                    host.cmd("ip route add default {}".format(params["defaultRoute"]))

                # host.cmd("ip link set lo up")

                host.config()

    def __str__(self):
        return "Mininet({})".format(self.topo)

    def cli(self):
        raise NotImplementedError("writeme")

    def add_host(self, name, cls=Node, **kwargs):
        """Add a host to micronet."""

        self.host_params[name] = kwargs
        super(Mininet, self).add_host(name, cls=cls, **kwargs)

    def start(self):
        """Start the micronet topology."""
        logging.debug("%s: Starting (no-op).", self)

    def stop(self):
        """Stop the mininet topology (deletes)."""
        logging.debug("%s: Stopping (deleting).", self)

        Mininet.g_inst = 1

        self.delete()
