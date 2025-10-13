# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# October 4 2025, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2025, LabN Consulting, L.L.C.
#
"""Generate CLI code from YANG models.

YANG extensions in module frr-extensions

    frr-ext:show-cli-cmd - SNode level statement.
    frr-ext:cli-cmd-help - Sub-statement of frr-ext:*-cli-cmd (currently allowed as SNode-level due to libyang bug)
    frr-ext:cli-cmd-finish - SNode-level or sub-statement of frr-ext:*-cli-cmd
    frr-ext:cli-arg-map - SNode-level or sub-statement of frr-ext:*-cli-cmd
"""

import argparse
import logging
import os
import subprocess
import sys
from copy import copy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

import libyang
from libyang import ExtensionCompiled, LibyangError, Module, SContainer, SList, SNode


@dataclass
class Cmd:
    snode_or_mod: SNode | Module
    c_ident: str
    cmd_tpl: str
    help: str
    arg_maps: dict[str, str] = field(default_factory=dict)
    finish_func: str = ""
    format_arg: str = ""


UNIQ_CMDS: dict[str, int] = {}
FINISH_FUNCS: set[str] = set()
SNODE_CMDS: dict[str, list[Cmd]] = {}
SNODE_ARG_MAPS: dict[str, dict[str, str]] = {}
SNODE_FINISH: dict[str, str] = {}
FILE = sys.stdout

_dbg = logging.debug
_info = logging.info


def iter_subtree(snode: SNode) -> Iterator[SNode]:
    """Iterate depth first for the subtree rooted at snode."""
    yield snode
    if isinstance(snode, (SContainer, SList)):
        for child in snode:
            yield from iter_subtree(child)
        # this is broken in libyang
        # for child in iter_snode_actions(snode):
        #     yield from iter_subtree(child, no_np, no_keys, no_inout)


def iter_schema(context: libyang.Context) -> Iterator[SNode]:
    """Iterate over all schema in all implemented modules."""
    for module in context:
        if not module.implemented():
            continue
        for snode in module:
            yield from iter_subtree(snode)


def fprint(*args, **kwargs):
    """Print to the output file."""
    print(*args, file=FILE, **kwargs)


def tabify(s: str, tabsize: int = 8) -> str:
    """Convert leading spaces to tabs using tabsize (8)."""
    lines = []
    for line in s.expandtabs().split("\n"):
        prefix_len = len(line) - len(line.lstrip(" "))
        tabs, spaces = divmod(prefix_len, tabsize)
        lines.append("\t" * tabs + " " * spaces + line[prefix_len:])
    return "\n".join(lines)


def __print_cli_header(c_ident: str, cmd_tpl: str, help: str):
    helpl = [x.strip() for x in help.split("\n")]
    helpl = [x + "\n" for x in helpl if x]
    help = "      ".join(helpl).rstrip()
    fprint(f"DEFPY_YANG({c_ident}, {c_ident}_cmd,")
    fprint(f'      "{cmd_tpl}",')
    fprint(f"      {help})")


def __print_cli_cmd(
    cmd: Cmd,
):
    __print_cli_header(cmd.c_ident, cmd.cmd_tpl, cmd.help)

    if isinstance(cmd.snode_or_mod, SNode):
        snode = cmd.snode_or_mod
    else:
        # This isn't really supported yet by mgmtd.
        snode = None
        assert False, "Module-root not supported yet by mgmtd"

    # Get the path from root to this node
    branch = []
    parent = snode
    while parent is not None:
        if parent.keyword() in ("container", "list"):
            branch.append(parent)
        parent = parent.parent()
    branch.reverse()

    # Get path segments with correct module prefixes.
    # Each segment is the path of the nodes up to the next user specified key value.
    # Each segment ends with 1 or more key predicates as found in the `arg_maps`.
    # For each key given at this list node in the path, the key is appneded to `keys`
    # and the c variable holding the value is appended to the corresponding `subvars`
    # list. The number of `keys, values` present for this list node is saved in
    # `predcounts`.
    path = ""
    prev_mod = ""
    segments = []
    keys = []
    subvars = []
    predcounts = []
    lasti = len(branch) - 1
    for i, node in enumerate(branch):
        mod_name = node.module().name()
        if mod_name != prev_mod:
            path += f"/{mod_name}:{node.name()}"
        else:
            path += f"/{node.name()}"
        prev_mod = mod_name

        relpath = "../" * (lasti - i)
        if not hasattr(node, "keys"):
            continue
        for keyleaf in node.keys():
            key = keyleaf.name()
            keyref = relpath + key
            if keyref in cmd.arg_maps:
                # key="name", keyref="../../name", value(varname)="var2"
                if path:
                    segments.append(path)
                    predcounts.append(0)
                    path = ""
                keys.append(key)
                subvars.append(cmd.arg_maps[keyref])
                predcounts[-1] += 1

    c_segs = ", ".join(f'"{k}"' for k in segments)
    c_predcounts = ", ".join(f"{x}" for x in predcounts)
    c_preds = ", ".join(f'"[{k}="' for k in keys)
    c_vars = ", ".join(f"{v}" for v in subvars)

    code = f"""{{
        LYD_FORMAT _fmt = LYD_JSON;
        uint8_t datastore = MGMT_MSG_DATASTORE_OPERATIONAL;
        uint8_t flags = GET_DATA_FLAG_STATE;
        uint8_t defaults = GET_DATA_DEFAULTS_EXPLICIT;
        const char *segs[] = {{ {c_segs} }};
        const uint predcounts[] = {{ {c_predcounts} }};
        const char *preds[] = {{ {c_preds} }};
        const char *vars[] = {{ {c_vars} }};
        const char *last_path = "{path}";
        char *path = NULL;
        char *arg = NULL;"""

    code += r"""
        for (uint i = 0; i < array_size(segs); i++) {
                darr_in_strcat(path, segs[i]);
                for (uint j = 0; j < predcounts[i]; j++) {
                        if (vars[i] == NULL)
                                continue;
                        darr_in_strcat(path, preds[i]);
                        if (strchr(vars[i], '"'))
                                darr_in_sprintf(arg, "'%s']", vars[i]);
                        else
                                darr_in_sprintf(arg, "\"%s\"]", vars[i]);
                        darr_in_strcat(path, arg);
                }
        }
        darr_in_strcat(path, last_path);"""

    if cmd.format_arg:
        code += f"""
        if ({cmd.format_arg} && strcmp({cmd.format_arg}, "xml") == 0)
                _fmt = LYD_XML;"""

    if not cmd.finish_func:
        code += """
        vty_mgmt_send_get_data_req(vty, datastore, _fmt, flags, defaults, path);"""
    else:
        code += f"""
        if (!vty_mgmt_send_get_data_req(vty, datastore, _fmt, flags, defaults, path)) {{
            extern int {cmd.finish_func}(struct vty *, LYD_FORMAT, const char *, int);
            vty->mgmt_req_pending_cb = {cmd.finish_func};
        }}
    """

    code += """
        darr_free(path);
        darr_free(arg);
        return CMD_SUCCESS;
}"""
    fprint(tabify(code))


def print_file_header(rel_path: str):
    """Print CLI header code."""
    path_stem = os.path.splitext(rel_path)[0]
    code = '''
/* Auto-generated by python/gen_yang_cli.py from YANG models. */
#include <zebra.h>
#include "command.h"
#include "darr.h"
#include "vrf.h"
#include "vty.h"'''
    if FINISH_FUNCS:
        code += f'''
#include "{path_stem}_custom.h"'''

    code += f"""
#include "{path_stem}_clippy.c"
"""
    fprint(tabify(code))


def print_cli_footer(rel_path: str):
    """Print CLI footer code."""
    stem = Path(rel_path).stem

    code = f"""
extern void {stem}_init(void);
void {stem}_init(void)
{{\n"""

    lines = []
    for spath in SNODE_CMDS:
        for cmd in SNODE_CMDS[spath]:
            lines.append(f"\tinstall_element(ENABLE_NODE, &{cmd.c_ident}_cmd);")

    code += "\n".join(lines)
    code += """
}"""
    fprint(tabify(code))


def print_cli_commands(basename: str):
    """Print CLI commands found."""
    for spath in sorted(SNODE_CMDS):
        _dbg("CLI commands for %s", spath)

        node_arg_maps = SNODE_ARG_MAPS.get(spath, {})
        if node_arg_maps:
            _dbg("  Node arg map: %s", node_arg_maps)
        node_finish_func = SNODE_FINISH.get(spath, "")

        for _cmd in SNODE_CMDS[spath]:
            cmd = copy(_cmd)
            if not cmd.finish_func:
                cmd.finish_func = node_finish_func
            cmd.arg_maps.update(node_arg_maps)
            if cmd.arg_maps:
                _dbg("  Cmd arg map: %s", cmd.arg_maps)
            __print_cli_cmd(cmd)

    print_cli_footer(basename)


def __cident(snode_or_mod: SNode | Module, cmd_tpl: str) -> str:
    """Convert a CLI command to a C identifier."""
    if isinstance(snode_or_mod, Module):
        mod_name = snode_or_mod.name()
    else:
        mod_name = snode_or_mod.module().name()

    cmdl = [mod_name]
    for e in cmd_tpl.strip().split():
        if not (e.isidentifier() or e == "-"):
            break
        cmdl.append(e)
    return "_".join(cmdl).replace("-", "_")


def process_extension(
    snode_or_mod: SNode | Module,
    ext: ExtensionCompiled,
    help_ext: ExtensionCompiled | None = None,
):
    """Print an extension and its sub-extensions."""

    name = ext.name()
    if (_ext_arg := ext.argument()) is None:
        ext_arg = ""
    else:
        ext_arg = _ext_arg
    try:
        ext_mod_name = ext.module().name()
    except LibyangError:
        ext_mod_name = ""
    if isinstance(snode_or_mod, SNode):
        spath = snode_or_mod.schema_path()
    else:
        spath = "/" + snode_or_mod.name()
    fullname = ext_mod_name + ":" + name
    finish_seen = False

    _dbg(f"  Extension {fullname}: {ext_arg}")

    # Unfortunately libyang python bindings don't provide compiled module level
    # extensions so we use the parsed versions which lack a module link.
    if ext_mod_name and ext_mod_name != "frr-extensions":
        return

    if name == "show-cli-cmd":
        assert ext_arg, "show-cli-cmd requires an argument"
        cmd_tpl = ext_arg

        c_ident = __cident(snode_or_mod, cmd_tpl)
        count = 1
        while c_ident in UNIQ_CMDS:
            count += 1
            c_ident = f"{c_ident}_n{count}"
            UNIQ_CMDS[c_ident] = 1

        # Process sub-statement extensions
        arg_maps = {}
        finish_func = ""
        format_arg = ""
        help_text = help_ext.argument() if help_ext else ""
        for sub in ext.extensions():
            sub_name = sub.name()
            sub_arg = sub.argument() if sub.argument() else ""
            if sub_name == "cli-cmd-help":
                assert sub_arg, "cli-cmd-help requires a help string"
                help_text = sub_arg
            elif sub_name == "cli-cmd-finish":
                assert not finish_func, "Only one `cli-cmd-finish` allowed"
                assert sub_arg, "cli-cmd-finish requires a function name"
                finish_func = sub_arg
                FINISH_FUNCS.add(sub_arg)
            elif sub_name == "cli-cmd-format-arg":
                assert not format_arg, "Only one `cli-cmd-format-arg` allowed"
                assert sub_arg, "cli-cmd-format-arg requires an argument"
                format_arg = sub_arg
            elif sub_name == "cli-arg-map":
                assert sub_arg and "=" in sub_arg, "cli-arg-map requires key=value str"
                tup = [x.strip() for x in sub_arg.split("=", 1)]
                arg_maps[tup[0]] = tup[1]

        assert bool(help_text), "`cli-cmd-help` is required for `show-cli-cmd`"

        cmd = Cmd(
            snode_or_mod, c_ident, cmd_tpl, help_text, arg_maps, finish_func, format_arg
        )

        if spath not in SNODE_CMDS:
            SNODE_CMDS[spath] = []
        SNODE_CMDS[spath].append(cmd)
    elif name == "cli-cmd-finish":
        assert spath not in SNODE_FINISH, "One `cli-cmd-finish` per node"
        SNODE_FINISH[spath] = ext_arg
        FINISH_FUNCS.add(ext_arg)
    elif name == "cli-arg-map":
        if spath not in SNODE_ARG_MAPS:
            SNODE_ARG_MAPS[spath] = {}
        tup = tuple(x.strip() for x in ext_arg.split("=", 1))
        SNODE_ARG_MAPS[spath][tup[0]] = tup[1]

    return finish_seen


def process_extensions(ctx: libyang.Context):
    """Iterate over actions children of a schema node."""
    for snode in iter_schema(ctx):
        if any(snode.extensions()):
            _dbg(f"Schema Node: {snode.schema_path()}")
            # Due to a bug in libyang's handling of extensiosn inside grouping/refines
            # we have to allow for cli-cmd-help outside of the show-cli-cmd extension.
            help_ext = None
            for ext in snode.extensions():
                if ext.name() == "cli-cmd-help":
                    assert help_ext is None, "can't have multiple cli-cmd-help"
                    help_ext = ext
            for ext in snode.extensions():
                process_extension(snode, ext, help_ext)


def arg_parser():
    """Parse command-line arguments for the mgmtd client."""
    p = argparse.ArgumentParser()
    _ = p.add_argument("-o", "--output", help="file to write generated CLI commands to")
    _ = p.add_argument("--verbose", action="store_true")
    _ = p.add_argument("--yang-path", help="path to YANG modules")
    _ = p.add_argument(
        "--rel-path", required=True, help="relative path for generated file"
    )
    _ = p.add_argument("modules", nargs="*", help="modules to process, blank for all")
    return p


def __path_and_modules(yang_path, modfiles: list[str]):
    paths = set([path for p in modfiles if (path := os.path.dirname(p))])
    if yang_path:
        paths.update(yang_path.split(":"))
    path = ":".join(paths)
    return path, [Path(p).stem for p in modfiles]


def main(*args):
    """Convert JSON to table."""
    args = arg_parser().parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO  # pyright:ignore[reportAny]
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s: %(message)s")

    if args.output:
        global FILE
        FILE = open(args.output, "w")

    if not args.modules and args.yang_path:
        args.modules = subprocess.run(
            f"grep -l frr-ext: {args.yang_path}/frr-*.yang",
            shell=True,
            capture_output=True,
            text=True,
        ).stdout.split("\n")

    yang_path, modules = __path_and_modules(args.yang_path, args.modules)
    ctx = libyang.Context(search_path=yang_path)

    for mod_name in modules:
        _info("Loading module %s", mod_name)
        mod = ctx.load_module(mod_name)
        assert mod is not None, f"Failed to load module {mod_name}"
        for f in mod.features():
            feat_name = f.name()
            if f.obsolete():
                _dbg("Skipping obsolete feature: %s:%s", mod_name, feat_name)
                continue
            if f.deprecated():
                _dbg("Skipping deprecated feature: %s:%s", mod_name, feat_name)
                continue
            _dbg("  Enabling feature: %s:%s", mod_name, feat_name)
            mod.feature_enable(feat_name)
        for rev in mod.revisions():
            _dbg("  Revision %s", rev.date())
            for ext in rev.extensions():
                _dbg("revision extension", rev.extensions())
        if hasattr(mod, "parsed_extensions"):
            for ext in mod.parsed_extensions():
                process_extension(mod, ext)
        for i in mod.parsed_identities():
            _dbg("  Identity: %s:%s", mod_name, i.name())

    process_extensions(ctx)

    print_file_header(args.rel_path)
    print_cli_commands(args.rel_path)


if __name__ == "__main__":
    main()
