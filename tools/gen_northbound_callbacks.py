#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate skeleton northbound callbacks.

This is a Python rewrite of ``gen_northbound_callbacks.c``.  The
script loads a set of YANG modules, walks over their schema nodes and
emits C skeletons for the northbound callbacks used by FRR.

The implementation relies on the ``libyang`` Python bindings.  These
bindings are required at runtime and must provide an API compatible
with ``libyang2``.  Behaviour is kept close to the C version but some
corner cases may behave slightly differently due to the higher level
API.
"""

import argparse
import os
import sys

try:
    import libyang
except Exception as exc:  # pragma: no cover - optional dependency
    sys.stderr.write("error: libyang python bindings are required: %s\n" % exc)
    sys.exit(1)


# ---------------------------------------------------------------------
# Callback information table
# ---------------------------------------------------------------------

class CallbackInfo:
    def __init__(self, operation, return_type, return_value, arguments,
                 optional=False, need_config_write=False):
        self.operation = operation
        self.return_type = return_type
        self.return_value = return_value
        self.arguments = arguments
        self.optional = optional
        self.need_config_write = need_config_write


# Operation identifiers (must match lib/northbound.h)
NB_CB_CREATE = 0
NB_CB_MODIFY = 1
NB_CB_DESTROY = 2
NB_CB_MOVE = 3
NB_CB_PRE_VALIDATE = 4
NB_CB_APPLY_FINISH = 5
NB_CB_GET_ELEM = 6
NB_CB_GET_NEXT = 7
NB_CB_GET_KEYS = 8
NB_CB_LIST_ENTRY_DONE = 9
NB_CB_LOOKUP_ENTRY = 10
NB_CB_RPC = 11
NB_CB_NOTIFY = 12


NB_CALLBACKS = [
    CallbackInfo(NB_CB_CREATE, "int ", "NB_OK",
                 "struct nb_cb_create_args *args", need_config_write=True),
    CallbackInfo(NB_CB_MODIFY, "int ", "NB_OK",
                 "struct nb_cb_modify_args *args", need_config_write=True),
    CallbackInfo(NB_CB_DESTROY, "int ", "NB_OK",
                 "struct nb_cb_destroy_args *args"),
    CallbackInfo(NB_CB_MOVE, "int ", "NB_OK",
                 "struct nb_cb_move_args *args"),
    CallbackInfo(NB_CB_APPLY_FINISH, "void ", "",
                 "struct nb_cb_apply_finish_args *args", optional=True),
    CallbackInfo(NB_CB_GET_ELEM, "struct yang_data *", "NULL",
                 "struct nb_cb_get_elem_args *args"),
    CallbackInfo(NB_CB_GET_NEXT, "const void *", "NULL",
                 "struct nb_cb_get_next_args *args"),
    CallbackInfo(NB_CB_GET_KEYS, "int ", "NB_OK",
                 "struct nb_cb_get_keys_args *args"),
    CallbackInfo(NB_CB_LOOKUP_ENTRY, "const void *", "NULL",
                 "struct nb_cb_lookup_entry_args *args"),
    CallbackInfo(NB_CB_RPC, "int ", "NB_OK",
                 "struct nb_cb_rpc_args *args"),
]


# Info blocks for auxiliary callbacks
NB_CONFIG_WRITE = CallbackInfo(
    None,
    "void ",
    "",
    "struct vty *vty, const struct lyd_node *dnode, bool show_defaults",
)

NB_OPER_GET = CallbackInfo(
    NB_CB_GET_ELEM,
    "enum nb_error ",
    "NB_OK",
    "const struct nb_node *nb_node, const void *parent_list_entry, struct lyd_node *parent",
)


# ---------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------

def replace_hyphens(text: str) -> str:
    """Convert '-' into '_' for symbol names."""
    return text.replace('-', '_')


def operation_name(op: int, new: bool) -> str:
    if new and op == NB_CB_GET_ELEM:
        return "get"
    names = {
        NB_CB_CREATE: "create",
        NB_CB_MODIFY: "modify",
        NB_CB_DESTROY: "destroy",
        NB_CB_MOVE: "move",
        NB_CB_PRE_VALIDATE: "pre_validate",
        NB_CB_APPLY_FINISH: "apply_finish",
        NB_CB_GET_ELEM: "get_elem",
        NB_CB_GET_NEXT: "get_next",
        NB_CB_GET_KEYS: "get_keys",
        NB_CB_LIST_ENTRY_DONE: "list_entry_done",
        NB_CB_LOOKUP_ENTRY: "lookup_entry",
        NB_CB_RPC: "rpc",
        NB_CB_NOTIFY: "notify",
    }
    return names.get(op, "unknown")


def generate_callback_name(snode: libyang.SNode, op: int, new: bool) -> str:
    parts = []
    cur = snode
    while cur is not None:
        if cur.nodetype in (libyang.LYS_USES, libyang.LYS_CHOICE,
                            libyang.LYS_CASE, libyang.LYS_INPUT,
                            libyang.LYS_OUTPUT):
            cur = cur.parent
            continue
        parts.insert(0, cur.name)
        cur = cur.parent

    parts.append(operation_name(op, new))
    return replace_hyphens('_'.join(parts))


def generate_config_write_cb_name(snode: libyang.SNode) -> str:
    parts = []
    cur = snode
    while cur is not None:
        if cur.nodetype in (libyang.LYS_USES, libyang.LYS_CHOICE,
                            libyang.LYS_CASE, libyang.LYS_INPUT,
                            libyang.LYS_OUTPUT):
            cur = cur.parent
            continue
        parts.insert(0, cur.name)
        cur = cur.parent

    parts.append('cli_write')
    return replace_hyphens('_'.join(parts))


# ---------------------------------------------------------------------
# Code generation helpers
# ---------------------------------------------------------------------

def emit_prototype(info: CallbackInfo, name: str, static: bool) -> None:
    prefix = "static " if static else ""
    print(f"{prefix}{info.return_type}{name}({info.arguments});")


def emit_callback(info: CallbackInfo, name: str, static: bool) -> None:
    prefix = "static " if static else ""
    print(f"{prefix}{info.return_type}{name}({info.arguments})\n{{")

    if info.operation in (NB_CB_CREATE, NB_CB_MODIFY, NB_CB_DESTROY, NB_CB_MOVE):
        print("\tswitch (args->event) {")
        for ev in ["NB_EV_VALIDATE", "NB_EV_PREPARE", "NB_EV_ABORT", "NB_EV_APPLY"]:
            print(f"\tcase {ev}:")
            print("\t\t/* TODO: implement me. */")
            print("\t\tbreak;")
        print("\t}\n")
    else:
        print("\t/* TODO: implement me. */")

    ret = info.return_value
    if ret:
        print(f"\treturn {ret};")
    print("}\n")


def emit_config_write_callback(info: CallbackInfo, name: str, static: bool) -> None:
    prefix = "static " if static else ""
    print(f"{prefix}{info.return_type}{name}({info.arguments})\n{{")
    print("\t/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */")
    print("}\n")


# ---------------------------------------------------------------------
# Traversal helpers
# ---------------------------------------------------------------------

def iter_schema_nodes(module: libyang.Module):
    def walk(node):
        yield node
        child = node.child
        while child is not None:
            yield from walk(child)
            child = child.next

    for child in module.data:
        yield from walk(child)


# ---------------------------------------------------------------------
# Main code
# ---------------------------------------------------------------------

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-h', action='help')
    parser.add_argument('-n', dest='new_cbs', action='store_true')
    parser.add_argument('-s', dest='static_cbs', action='store_true')
    parser.add_argument('-p', dest='paths', action='append', default=[])
    parser.add_argument('modules', nargs='+')
    args = parser.parse_args(argv)

    if len(args.modules) < 1:
        parser.print_usage(sys.stderr)
        return 1

    ctx = libyang.Context()
    for p in args.paths:
        ctx.search_path_add(p)

    # Load all FRR native modules first so that augmentations work
    yang_dir = os.path.join(os.path.dirname(__file__), '..', 'yang')
    if os.path.isdir(yang_dir):
        for fname in os.listdir(yang_dir):
            if fname.endswith('.yang'):
                ctx.load_module(fname[:-5])

    module = None
    for name in args.modules:
        module = ctx.load_module(name)

    if module is None:
        sys.stderr.write('error: module not found\n')
        return 1

    print("// SPDX-License-Identifier: GPL-2.0-or-later\n")

    if not args.static_cbs:
        print("/* prototypes */")
        for snode in iter_schema_nodes(module):
            if snode.nodetype not in (libyang.LYS_CONTAINER, libyang.LYS_LEAF,
                                      libyang.LYS_LEAFLIST, libyang.LYS_LIST,
                                      libyang.LYS_NOTIF, libyang.LYS_RPC):
                continue
            for cb in NB_CALLBACKS:
                name = generate_callback_name(snode, cb.operation, args.new_cbs)
                emit_prototype(cb if not (args.new_cbs and cb.operation == NB_CB_GET_ELEM) else NB_OPER_GET,
                               name, args.static_cbs)
                if cb.need_config_write:
                    cw_name = generate_config_write_cb_name(snode)
                    emit_prototype(NB_CONFIG_WRITE, cw_name, args.static_cbs)
        print()

    for snode in iter_schema_nodes(module):
        if snode.nodetype not in (libyang.LYS_CONTAINER, libyang.LYS_LEAF,
                                  libyang.LYS_LEAFLIST, libyang.LYS_LIST,
                                  libyang.LYS_NOTIF, libyang.LYS_RPC):
            continue
        first = True
        need_config_write = True
        for cb in NB_CALLBACKS:
            name = generate_callback_name(snode, cb.operation, args.new_cbs)
            info = cb
            if args.new_cbs and cb.operation == NB_CB_GET_ELEM:
                info = NB_OPER_GET
            emit_callback(info, name, args.static_cbs)
            if cb.need_config_write and need_config_write:
                cw_name = generate_config_write_cb_name(snode)
                emit_config_write_callback(NB_CONFIG_WRITE, cw_name, args.static_cbs)
                need_config_write = False

    module_name = replace_hyphens(module.name)

    # Emit empty module info structures. The full logic is complex in C and
    # depends on nb_nodes from FRR.  Here we provide a stub implementation
    # that mirrors the original output format but without nb_node data.
    print("/* clang-format off */")
    print(f"const struct frr_yang_module_info {module_name}_nb_info = {{")
    print(f"\t.name = \"{module.name}\",")
    print("\t.nodes = {")
    print("\t\t{ .xpath = NULL },")
    print("\t}\n};")

    print("\n/* clang-format off */")
    print(f"const struct frr_yang_module_info {module_name}_cli_info = {{")
    print(f"\t.name = \"{module.name}\",")
    print("\t.nodes = {")
    print("\t\t{ .xpath = NULL },")
    print("\t}\n};")

    return 0


if __name__ == '__main__':
    sys.exit(main())

