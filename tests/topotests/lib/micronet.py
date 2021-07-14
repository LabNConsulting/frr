# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# July 9 2021, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2021, LabN Consulting, L.L.C.
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
import re
import shlex
import subprocess
import sys
import traceback


# import typing import Union
# logger = logging.Logger(__name__)


def shell_quote(command):
    """Return command wrapped in single quotes."""
    if sys.version_info[0] >= 3:
        return shlex.quote(command)
    return "'{}'".format(command.replace("'", "'\"'\"'"))  # type: ignore


def gethexpid():
    """Return process pid in HEX as a str."""
    return "{:X}".format(int(os.getpid()))


class Commander(object):  # pylint: disable=R0205
    """
    Commander.

    An object that can execute commands.
    """

    def __init__(self, name):
        """Create a Commander."""
        self.name = name
        self.pre_cmd = []
        self.pre_cmd_str = ""
        self.cwd = self.cmd("pwd").strip()

    def set_pre_cmd(self, pre_cmd=None):
        if not pre_cmd:
            self.pre_cmd = []
            self.pre_cmd_str = ""
        else:
            self.pre_cmd = pre_cmd
            self.pre_cmd_str = " ".join(self.pre_cmd) + " "

    @staticmethod
    def is_string(value):
        """Return True if value is a string."""
        try:
            return isinstance(value, basestring)  # type: ignore
        except NameError:
            return isinstance(value, str)

    def __str__(self):
        return "Commander({})".format(self.name)

    def _get_cmd_str(self, cmd):
        if LinuxNamespace.is_string(cmd):
            return self.pre_cmd_str + cmd
        cmd = self.pre_cmd + cmd
        return " ".join(cmd)

    def _get_sub_args(self, cmd, defaults, **kwargs):
        if LinuxNamespace.is_string(cmd):
            defaults["shell"] = True
            pre_cmd = self.pre_cmd_str
            # XXX this is what topotests expects, it's a sub-optimal default
            defaults["stderr"] = subprocess.STDOUT
        else:
            defaults["shell"] = False
            pre_cmd = self.pre_cmd
        defaults.update(kwargs)
        return pre_cmd, cmd, defaults

    def _popen(self, method, cmd, **kwargs):
        if sys.version_info[0] >= 3:
            defaults = {
                "encoding": "utf-8",
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
            }
        else:
            defaults = {
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
            }
        pre_cmd, cmd, defaults = self._get_sub_args(cmd, defaults, **kwargs)

        logging.debug('%s: %s("%s", kwargs: %s)', self, method, cmd, defaults)
        return subprocess.Popen(pre_cmd + cmd, **defaults)

    def set_cwd(self, cwd):
        logging.debug("%s: new CWD %s", self, cwd)
        self.cwd = cwd

    def popen(self, cmd, **kwargs):
        """Create a Popen object."""
        return self._popen("popen", cmd, **kwargs)

    def cmd_status(self, cmd, **kwargs):
        """Execute a command."""

        # We not a shell like mininet, so we need to intercept this
        # XXX we can drop this when the code stops assuming it works
        chdir = False
        m = re.match(r"cd(\s*|\s+(\S+))$", cmd)
        if m and m.group(2):
            assert LinuxNamespace.is_string(cmd)
            chdir = True
            cmd += " && pwd"
        cmd = "bash -c {}".format(shell_quote(cmd))

        p = self._popen("cmd", cmd, **kwargs)
        stdout, stderr = p.communicate()
        rc = p.wait()
        if rc:
            cmd_str = self._get_cmd_str(cmd)
            logging.warning(
                '%s: cmd("%s"): Failed: %d%s%s:\n%s',
                self,
                cmd_str,
                rc,
                '\n:stdout: "{}"'.format(stdout) if stdout else "",
                '\n:stderr: "{}"'.format(stderr) if stderr else "",
                "".join(traceback.format_stack(limit=12)),
            )
        elif chdir:
            self.set_cwd(stdout.strip())

        return rc, stdout, stderr

    def cmd(self, cmd, **kwargs):
        """Execute a command."""

        _, stdout, _ = self.cmd_status(cmd, **kwargs)
        return stdout


class LinuxNamespace(Commander):
    """
    A linux Namespace.

    An object that creates and executes commands in a linux namespace
    """

    def __init__(
        self,
        name,
        net=True,
        mount=True,
        uts=True,
        cgroup=False,
        ipc=False,
        pid=False,
        time=False,
        user=False,
        set_hostname=True,
        private_mounts=None,
    ):
        """
        Create a new linux namespace.

        Paramaters
        ----------
        * `name` :: internal name for the namespace
        * `net` :: create network namespace
        * `mount` :: create network namespace
        * `uts` :: create UTS (hostname) namespace
        * `cgroup` :: create cgroup namespace
        * `ipc` :: create IPC namespace
        * `pid` :: create PID namespace, also mounts new /proc
        * `time` :: create time namespace
        * `user` :: create user namespace, also keeps capabilities
        * `private_mounts` :: list of strings of the form "[/external/path:]/internal/path. If no
                              external path is specified a tmpfs is mounted on the internal path.
                              Any paths specified are first passed to `mkdir -p`.
        """
        super(LinuxNamespace, self).__init__(name)

        logging.debug("%s: Creating", self)

        cmd = ["/usr/bin/unshare"]
        flags = "-"

        if cgroup:
            flags += "C"
        if ipc:
            flags += "i"
        if mount:
            flags += "m"
        if net:
            flags += "n"
        if pid:
            flags += "p"
            cmd.append("--mount-proc")
        if time:
            flags += "T"
        if user:
            flags += "U"
            cmd.append("--keep-caps")
        if uts:
            flags += "u"

        cmd.append(flags)

        # Using cat and a stdin PIPE is nice as it will exit when we do.
        logging.debug("Creating namespace process: %s", cmd)
        self.p = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=open("/dev/null", "w"),
            stderr=open("/dev/null", "w"),
            shell=False,
        )
        self.pid = self.p.pid

        # Set pre-command based on our namespace proc
        self.set_pre_cmd(
            ["/usr/bin/nsenter", "-a", "-t", str(self.pid), "--wd=" + self.cwd]
        )

        # Set the hostname to the namespace name
        if set_hostname:
            self.cmd("hostname " + self.name)

        # Remount /sys to pickup any changes
        self.cmd("mount -t sysfs none /sys")

        if private_mounts:
            if LinuxNamespace.is_string(private_mounts):
                private_mounts = [private_mounts]
            for m in private_mounts:
                s = m.split(":", 1)
                e, i = s if len(s) != 1 else (None, s[0])
                self.cmd("mkdir -p " + i)
                if not e:
                    self.cmd("mount -n -t tmpfs tmpfs " + i)
                else:
                    self.cmd("mkdir -p " + e)
                    self.cmd("mount --bind {} {} ".format(e, i))

        # Doing this here messes up all_protocols ipv6 check
        self.cmd("ip link set lo up")

    def __str__(self):
        return "LinuxNamespace({})".format(self.name)

    def set_cwd(self, cwd):
        # Set pre-command based on our namespace proc
        logging.debug("%s: new CWD %s", self, cwd)
        self.set_pre_cmd(["/usr/bin/nsenter", "-a", "-t", str(self.pid), "--wd=" + cwd])


class Bridge(Commander):
    """
    A linux bridge.
    """

    base_brid_str = "un{}".format(gethexpid())
    next_brid_ord = 0

    @classmethod
    def _get_next_brid(cls):
        brid_ord = cls.next_brid_ord
        cls.next_brid_ord += 1
        return cls.base_brid_str, "{:x}".format(brid_ord)

    def __init__(self, name=None):
        """Create a linux Bridge."""
        logging.debug("Bridge: Creating")

        self.next_if_ord = 0

        suffix, self.brid_ord = self._get_next_brid()
        if name:
            self.brid = name + suffix
        else:
            self.brid = "b{:x}".format(self.brid_ord) + suffix
            name = self.brid

        Commander.__init__(self, name)

        assert len(self.brid) <= 16  # Make sure fits in IFNAMSIZE
        self.cmd("ip link delete {} || true".format(self.brid))
        self.cmd("ip link add {} type bridge".format(self.brid))
        self.cmd("ip link set {} up".format(self.brid))

        logging.debug("%s: Created, Running", self)

    def __str__(self):
        return "Bridge({})".format(self.brid)

    def delete(self):
        """Stop the bridge (i.e., delete the linux resources)."""

        self.cmd("ip link delete {}".format(self.brid))
        logging.debug("%s: Deleted.", self)

    def get_next_ifname(self):
        iord = self.next_if_ord
        self.next_if_ord += 1
        return "i{:x}b{}{}".format(iord, self.brid_ord, self.base_brid_str)


class Micronet(Commander):  # pylint: disable=R0205
    """
    Micronet.
    """

    def __init__(self):
        """
        Create a Micronet.
        """
        logging.debug("%s: Creating", self)

        self.hosts = {}
        self.host_intfs = {}
        self.switches = {}
        self.links = {}

        super(Micronet, self).__init__("micronet")

        self.cleanup_old()

    def __str__(self):
        return "Micronet()"

    def __getitem__(self, key):
        if key in self.switches:
            return self.switches[key]
        return self.hosts[key]

    def add_host(self, name, cls=LinuxNamespace, **kwargs):
        """Add a host to micronet."""

        logging.debug("%s: add_host %s", self, name)

        self.host_intfs[name] = []
        self.hosts[name] = cls(name, **kwargs)

    def add_link(self, name1, name2, if1, if2):
        """Add a link between switch and host to micronet."""
        isp2p = False
        if name1 in self.switches:
            assert name2 in self.hosts
        elif name2 in self.switches:
            assert name1 in self.hosts
            name1, name2 = name2, name1
            if1, if2 = if2, if1
        else:
            # p2p link
            assert name1 in self.hosts
            assert name2 in self.hosts
            isp2p = True

        lname = "{}:{}-{}:{}".format(name1, if1, name2, if2)
        logging.debug("%s: add_link %s%s", self, lname, " p2p" if isp2p else "")
        self.links[lname] = (name1, if1, name2, if2)

        # And create the veth now.
        hexpid = gethexpid()
        if isp2p:
            lhost, rhost = self.hosts[name1], self.hosts[name2]
            lhifpid = "Run{}".format(hexpid)
            rhifpid = "run{}".format(hexpid)
            self.cmd("ip link add {} type veth peer name {}".format(lhifpid, rhifpid))

            self.cmd("ip link set {} netns {}".format(lhifpid, lhost.pid))
            lhost.cmd("ip link set {} name {}".format(lhifpid, if1))
            lhost.cmd("ip link set {} up".format(if1))
            if if1 not in self.host_intfs[name1]:
                self.host_intfs[name1].append(if1)

            self.cmd("ip link set {} netns {}".format(rhifpid, rhost.pid))
            rhost.cmd("ip link set {} name {}".format(rhifpid, if2))
            rhost.cmd("ip link set {} up".format(if2))
            if if2 not in self.host_intfs[name2]:
                self.host_intfs[name2].append(if2)
        else:
            switch = self.switches[name1]
            swifpid = switch.get_next_ifname()
            host = self.hosts[name2]
            hifpid = "Run{}".format(hexpid)

            # Make sure fits in IFNAMSIZE
            assert len(hifpid) <= 16
            assert len(swifpid) <= 16

            logging.debug("%s: Creating veth pair for link %s", self, lname)
            self.cmd(
                "ip link add {} type veth peer name {} netns {}".format(
                    swifpid, if2, host.pid
                )
            )
            if if2 not in self.host_intfs[name2]:
                self.host_intfs[name2].append(if2)
            self.cmd("ip link set {} master {}".format(swifpid, switch.brid))
            self.cmd("ip link set {} up".format(swifpid))
            host.cmd("ip link set {} up".format(if2))

    def add_switch(self, name):
        """Add a switch to micronet."""

        logging.debug("%s: add_switch %s", self, name)
        self.switches[name] = Bridge(name)

    def cleanup_old(self):
        """Cleanup any interfaces left around from previous runs."""
        logging.debug("%s: Cleaning out any old micronet intefaces", self)

        ifs = {}
        output = self.cmd("ip -o link show | awk -F': ' '{print $2}'")

        for m in re.finditer(r"([^@/\s]+un([0-9A-F]+))(@.*)?", output):
            pid = int(m.group(2), 16)
            if pid not in ifs:
                ifs[pid] = set()
            ifs[pid].add(m.group(1))

        for pid, names in ifs.items():
            if os.path.exists("/proc/" + str(pid)):
                continue
            for name in names:
                logging.debug("Reaping old interface %s", name)
                self.cmd("ip link delete {} || true".format(name))

    def delete(self):
        """Delete the micronet topology."""

        logging.debug("%s: Deleting.", self)

        for lname, (_, _, rname, rif) in self.links.items():
            host = self.hosts[rname]

            logging.debug("%s: Deleting veth pair for link %s", self, lname)
            host.cmd("ip link delete {}".format(rif))

        for switch in self.switches.values():
            switch.delete()

        logging.debug("%s: Deleted.", self)
