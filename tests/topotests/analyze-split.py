#!/usr/bin/env python3
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

import argparse
import glob
import json
import logging
import os
import pdb
import re
import sys
from collections import OrderedDict

import xmltodict


def get_summary(results):
    ntest = int(results["@tests"])
    nfail = int(results["@failures"])
    nerror = int(results["@errors"])
    nskip = int(results["@skipped"])
    npass = ntest - nfail - nskip - nerror
    return ntest, npass, nfail, nerror, nskip


def print_summary(results, args):
    ntest, npass, nfail, nerror, nskip = (0, 0, 0, 0, 0)
    for group in results:
        _ntest, _npass, _nfail, _nerror, _nskip = get_summary(results[group])
        if args.verbose:
            print(f"Group: {group} Total: {_ntest} PASSED: {_npass}"
                  " FAIL: {_nfail} ERROR: {_nerror} SKIP: {_nskip}")
        ntest += _ntest
        npass += _npass
        nfail += _nfail
        nerror += _nerror
        nskip += _nskip
    print(f"Total: {ntest} PASSED: {npass} FAIL: {nfail} ERROR: {nerror} SKIP: {nskip}")


def get_global_testcase(results):
    for group in results:
        for testcase in results[group]["testcase"]:
            if "@file" not in testcase:
                return testcase
    return None


def get_filtered(tfilters, results, args):
    if isinstance(tfilters, str) or tfilters is None:
        tfilters = [tfilters]
    found_files = OrderedDict()
    for group in results:
        if isinstance(results[group]["testcase"], list):
            tlist = results[group]["testcase"]
        else:
            tlist = [results[group]["testcase"]]
        for testcase in tlist:
            for tfilter in tfilters:
                if tfilter is None:
                    if (
                        "failure" not in testcase
                        and "error" not in testcase
                        and "skipped" not in testcase
                    ):
                        break
                elif tfilter in testcase:
                    break
            else:
                continue
            #cname = testcase["@classname"]
            fname = testcase.get("@file", "")
            cname = testcase.get("@classname", "")
            if not fname and not cname:
                continue
            if not fname:
                fname = cname.replace(".", "/") + ".py"
            if args.files or "@name" not in testcase:
                tcname = fname
            else:
                tcname = fname + "::" + testcase["@name"]
            found_files[tcname] = testcase
    return found_files



def dump_testcase(testcase):
    expand_keys = ("failure", "error", "skipped")

    s = ""
    for key, val in testcase.items():
        if isinstance(val, str) or isinstance(val, float) or isinstance(val, int):
            s += "{}: {}\n".format(key, val)
        else:
            for k2, v2 in val.items():
                s += "{}: {}\n".format(k2, v2)
    return s


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rundir", help="split-test.sh topotest results base directory")
    parser.add_argument("-F", "--files", action="store_true", help="print test file names rather than individual full testcase names")
    parser.add_argument("-r", "--runfile", help="tpotests.xml results file")
    parser.add_argument(
        "-E",
        "--enumerate",
        action="store_true",
        help="enumerate each item (results scoped)",
    )
    parser.add_argument(
        "-f", "--failed", action="store_true", help="print failed tests"
    )
    parser.add_argument(
        "-e", "--errored", action="store_true", help="print errored tests"
    )
    parser.add_argument(
        "-p", "--passed", action="store_true", help="print passed tests"
    )
    parser.add_argument(
        "-s", "--skipped", action="store_true", help="print skipped tests"
    )
    parser.add_argument(
        "-T", "--test", help="print testcase at enumeration"
    )
    parser.add_argument(
        "--test-errmsg", action="store_true", help="print testcase error message"
    )
    parser.add_argument(
        "--test-errtext", action="store_true", help="print testcase error text"
    )

    parser.add_argument("-S", "--summary", action="store_true", help="print summary")
    parser.add_argument("-v", "--verbose", action="store_true", help="be verbose")
    args = parser.parse_args()

    assert args.test is None or not args.files, "Can't have both --files and --test"

    results = {}
    ttfiles = []
    if args.rundir:
        basedir = os.path.realpath(args.rundir)
        os.chdir(basedir)

        newfiles = glob.glob("tt-group-*/topotests.xml")
        if newfiles:
            ttfiles.extend(newfiles)
        if os.path.exists("topotests.xml"):
            ttfiles.append("topotests.xml")
    else:
        if args.runfile:
            if os.path.exists(os.path.join(args.runfile, "topotests.xml")):
                args.runfile = os.path.join(args.runfile, "topotests.xml")
            ttfiles = [args.runfile]

        if not ttfiles and os.path.exists("/tmp/topotests.xml"):
            ttfiles.append("/tmp/topotests.xml")

    for f in ttfiles:
        m = re.match(r"tt-group-(\d+)/topotests.xml", f)
        group = int(m.group(1)) if m else 0
        with open(f) as xml_file:
            results[group] = xmltodict.parse(xml_file.read())["testsuites"]["testsuite"]

    filters = []
    if args.errored:
        filters.append("error")
    if args.failed:
        filters.append("failure")
    if args.skipped:
        filters.append("skipped")
    if args.passed:
        filters.append(None)

    found_files = get_filtered(filters, results, args)
    if found_files:
        if args.test is not None:
            if args.test == "all":
                keys = found_files.keys()
            else:
                keys = [list(found_files.keys())[int(args.test)]]
            for key in keys:
                testcase = found_files[key]
                if args.test_errtext:
                    if "error" in testcase:
                        errmsg = testcase["error"]["#text"]
                    elif "failure" in testcase:
                        errmsg = testcase["failure"]["#text"]
                    else:
                        errmsg = "none found"
                    s = "{}: {}".format(key, errmsg)
                elif args.test_errmsg:
                    if "error" in testcase:
                        errmsg = testcase["error"]["@message"]
                    elif "failure" in testcase:
                        errmsg = testcase["failure"]["@message"]
                    else:
                        errmsg = "none found"
                    s = "{}: {}".format(key, errmsg)
                else:
                    s = dump_testcase(testcase)
                print(s)
        elif filters:
            if args.enumerate:
                print(
                    "\n".join(["{} {}".format(i, x) for i, x in enumerate(found_files)])
                )
            else:
                print("\n".join(found_files))

    if args.summary:
        print_summary(results, args)


if __name__ == "__main__":
    main()
