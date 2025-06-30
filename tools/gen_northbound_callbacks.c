// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
 */

#define REALLY_NEED_PLAIN_GETOPT 1

#include <zebra.h>
#include <sys/stat.h>

#include <unistd.h>

#include "darr.h"
#include "yang.h"
#include "northbound.h"

static bool f_static_cbs;
static bool f_new_cbs;

static void __attribute__((noreturn)) usage(int status)
{
	extern const char *__progname;
	fprintf(stderr, "usage: %s [-h] [-n] [-s] [-p path]* [LOAD-MODULE ...] MODULE\n",
		__progname);
	exit(status);
}

static struct nb_callback_info {
	int operation;
	bool optional;
	bool need_config_write;
	char return_type[32];
	char return_value[32];
	char arguments[128];
} nb_callbacks[] = {
	{
		.operation = NB_CB_CREATE,
		.need_config_write = true,
		.return_type = "int ",
		.return_value = "NB_OK",
		.arguments = "struct nb_cb_create_args *args",
	},
	{
		.operation = NB_CB_MODIFY,
		.need_config_write = true,
		.return_type = "int ",
		.return_value = "NB_OK",
		.arguments = "struct nb_cb_modify_args *args",
	},
	{
		.operation = NB_CB_DESTROY,
		.return_type = "int ",
		.return_value = "NB_OK",
		.arguments = "struct nb_cb_destroy_args *args",
	},
	{
		.operation = NB_CB_MOVE,
		.return_type = "int ",
		.return_value = "NB_OK",
		.arguments = "struct nb_cb_move_args *args",
	},
	{
		.operation = NB_CB_APPLY_FINISH,
		.optional = true,
		.return_type = "void ",
		.return_value = "",
		.arguments = "struct nb_cb_apply_finish_args *args",
	},
	{
		.operation = NB_CB_GET_ELEM,
		.return_type = "struct yang_data *",
		.return_value = "NULL",
		.arguments = "struct nb_cb_get_elem_args *args",
	},
	{
		.operation = NB_CB_GET_NEXT,
		.return_type = "const void *",
		.return_value = "NULL",
		.arguments = "struct nb_cb_get_next_args *args",
	},
	{
		.operation = NB_CB_GET_KEYS,
		.return_type = "int ",
		.return_value = "NB_OK",
		.arguments = "struct nb_cb_get_keys_args *args",
	},
	{
		.operation = NB_CB_LOOKUP_ENTRY,
		.return_type = "const void *",
		.return_value = "NULL",
		.arguments = "struct nb_cb_lookup_entry_args *args",
	},
	{
		.operation = NB_CB_RPC,
		.return_type = "int ",
		.return_value = "NB_OK",
		.arguments = "struct nb_cb_rpc_args *args",
	},
	{
		/* sentinel */
		.operation = -1,
	},
};

/*
 * Special-purpose info block for the cli-config-write callback. This
 * is different enough from the config-oriented callbacks that it doesn't
 * really fit in the array above.
 */
static struct nb_callback_info nb_config_write = {
	.return_type = "void ",
	.arguments = "struct vty *vty, const struct lyd_node *dnode, bool show_defaults",
};

static struct nb_callback_info nb_oper_get = {
	.operation = NB_CB_GET_ELEM,
	.return_type = "enum nb_error ",
	.return_value = "NB_OK",
	.arguments =
		"const struct nb_node *nb_node, const void *parent_list_entry, struct lyd_node *parent",
};

static void replace_hyphens_by_underscores(char *str)
{
	char *p;

	p = str;
	while ((p = strchr(p, '-')) != NULL)
		*p++ = '_';
}

static const char *__operation_name(enum nb_cb_operation operation)
{
	if (f_new_cbs && operation == NB_CB_GET_ELEM)
		return "get";
	else
		return nb_cb_operation_name(operation);
}

static void generate_callback_name(const struct lysc_node *snode,
				   enum nb_cb_operation operation, char *buffer,
				   size_t size)
{
	struct list *snodes;
	struct listnode *ln;

	snodes = list_new();
	for (; snode; snode = snode->parent) {
		/* Skip schema-only snodes. */
		if (CHECK_FLAG(snode->nodetype, LYS_USES | LYS_CHOICE | LYS_CASE
							| LYS_INPUT
							| LYS_OUTPUT))
			continue;

		listnode_add_head(snodes, (void *)snode);
	}

	memset(buffer, 0, size);
	for (ALL_LIST_ELEMENTS_RO(snodes, ln, snode)) {
		strlcat(buffer, snode->name, size);
		strlcat(buffer, "_", size);
	}
	strlcat(buffer, __operation_name(operation), size);
	list_delete(&snodes);

	replace_hyphens_by_underscores(buffer);
}

static void generate_config_write_cb_name(const struct lysc_node *snode,
					  char *buffer, size_t size)
{
	struct list *snodes;
	struct listnode *ln;

	buffer[0] = '\0';

	snodes = list_new();
	for (; snode; snode = snode->parent) {
		/* Skip schema-only snodes. */
		if (CHECK_FLAG(snode->nodetype, LYS_USES | LYS_CHOICE | LYS_CASE
							| LYS_INPUT
							| LYS_OUTPUT))
			continue;

		listnode_add_head(snodes, (void *)snode);
	}

	for (ALL_LIST_ELEMENTS_RO(snodes, ln, snode)) {
		strlcat(buffer, snode->name, size);
		strlcat(buffer, "_", size);
	}

	strlcat(buffer, "cli_write", size);

	list_delete(&snodes);

	replace_hyphens_by_underscores(buffer);
}

static void generate_prototype(const struct nb_callback_info *ncinfo,
                              const char *cb_name)
{
       /* prototypes are unnecessary in Python */
}

static void generate_config_write_prototype(const struct nb_callback_info *ncinfo,
                                            const char *cb_name)
{
       /* prototypes are unnecessary in Python */
}

static int generate_prototypes(const struct lysc_node *snode, void *arg)
{
	bool need_config_write = true;

	switch (snode->nodetype) {
	case LYS_CONTAINER:
	case LYS_LEAF:
	case LYS_LEAFLIST:
	case LYS_LIST:
	case LYS_NOTIF:
	case LYS_RPC:
		break;
	default:
		return YANG_ITER_CONTINUE;
	}

	for (struct nb_callback_info *cb = &nb_callbacks[0]; cb->operation != -1; cb++) {
		char cb_name[BUFSIZ];

		if (cb->optional
		    || !nb_cb_operation_is_valid(cb->operation, snode))
			continue;

		if (f_new_cbs && cb->operation == NB_CB_GET_NEXT && snode->nodetype == LYS_LEAFLIST)
			continue;

		generate_callback_name(snode, cb->operation, cb_name,
				       sizeof(cb_name));

		if (cb->operation == NB_CB_GET_ELEM && f_new_cbs)
			generate_prototype(&nb_oper_get, cb_name);
		else
			generate_prototype(cb, cb_name);

		if (cb->need_config_write && need_config_write) {
			generate_config_write_cb_name(snode, cb_name,
						      sizeof(cb_name));
			generate_config_write_prototype(&nb_config_write,
							cb_name);

			need_config_write = false;
		}
	}

	return YANG_ITER_CONTINUE;
}

static const char *python_return_value(const char *ret)
{
       if (strcmp(ret, "NULL") == 0)
               return "None";
       return ret;
}

static void generate_callback(const struct nb_callback_info *ncinfo,
                              const char *cb_name)
{
       printf("def %s(args):\n", cb_name);
       printf("\t\"\"\"TODO: implement me.\"\"\"\n");

       switch (ncinfo->operation) {
       case NB_CB_CREATE:
       case NB_CB_MODIFY:
       case NB_CB_DESTROY:
       case NB_CB_MOVE:
               printf("\t# handle args.event here\n");
               break;
       default:
               break;
       }

       if (ncinfo->return_value[0])
               printf("\treturn %s\n\n", python_return_value(ncinfo->return_value));
       else
               printf("\n");
}

static void generate_config_write_callback(const struct nb_callback_info *ncinfo,
                                           const char *cb_name)
{
       printf("def %s(vty, dnode, show_defaults):\n", cb_name);
       printf("\t# TODO: this cli callback is optional; the cli output may not need to be done at each node.\n\n");
}

static int generate_callbacks(const struct lysc_node *snode, void *arg)
{
	bool first = true;
	bool need_config_write = true;

	switch (snode->nodetype) {
	case LYS_CONTAINER:
	case LYS_LEAF:
	case LYS_LEAFLIST:
	case LYS_LIST:
	case LYS_NOTIF:
	case LYS_RPC:
		break;
	default:
		return YANG_ITER_CONTINUE;
	}

	for (struct nb_callback_info *cb = &nb_callbacks[0];
	     cb->operation != -1; cb++) {
		char cb_name[BUFSIZ];

		if (cb->optional
		    || !nb_cb_operation_is_valid(cb->operation, snode))
			continue;

		if (first) {
			char xpath[XPATH_MAXLEN];

			yang_snode_get_path(snode, YANG_PATH_DATA, xpath,
					    sizeof(xpath));

                       printf("# XPath: %s\n", xpath);
                       first = false;
               }

		if (f_new_cbs && cb->operation == NB_CB_GET_NEXT && snode->nodetype == LYS_LEAFLIST)
			continue;

		generate_callback_name(snode, cb->operation, cb_name,
				       sizeof(cb_name));

		if (cb->operation == NB_CB_GET_ELEM && f_new_cbs)
			generate_callback(&nb_oper_get, cb_name);
		else
			generate_callback(cb, cb_name);

		if (cb->need_config_write && need_config_write) {
			generate_config_write_cb_name(snode, cb_name,
						      sizeof(cb_name));
			generate_config_write_callback(&nb_config_write,
						       cb_name);

			need_config_write = false;
		}
	}

	return YANG_ITER_CONTINUE;
}

static int generate_nb_nodes(const struct lysc_node *snode, void *arg)
{
       bool first = true;
       char cb_name[BUFSIZ];
       char xpath[XPATH_MAXLEN];
       bool config_pass = *(bool *)arg;
       bool need_config_write = true;

	switch (snode->nodetype) {
	case LYS_CONTAINER:
	case LYS_LEAF:
	case LYS_LEAFLIST:
	case LYS_LIST:
	case LYS_NOTIF:
	case LYS_RPC:
		break;
	default:
		return YANG_ITER_CONTINUE;
	}

	/* We generate two types of structs currently; behavior is a little
	 * different between the types.
	 */
	for (struct nb_callback_info *cb = &nb_callbacks[0];
	     cb->operation != -1; cb++) {

		if (cb->optional
		    || !nb_cb_operation_is_valid(cb->operation, snode))
			continue;

               if (config_pass) {
                       if (first) {
                               yang_snode_get_path(snode, YANG_PATH_DATA, xpath,
                                                   sizeof(xpath));

                               printf("        {\n            \"xpath\": \"%s\",\n            \"cbs\": {\n",
                                      xpath);
                               first = false;
                       }
                       if (f_new_cbs && cb->operation == NB_CB_GET_NEXT &&
                           snode->nodetype == LYS_LEAFLIST)
                               continue;

                       generate_callback_name(snode, cb->operation, cb_name,
                                              sizeof(cb_name));
                       printf("                \"%s\": %s,\n", __operation_name(cb->operation), cb_name);
               } else if (cb->need_config_write && need_config_write) {
                       if (first) {
                               yang_snode_get_path(snode,
                                                   YANG_PATH_DATA,
                                                   xpath,
                                                   sizeof(xpath));

                               printf("        {\n            \"xpath\": \"%s\",\n            \"cbs\": {\n",
                                      xpath);
                               first = false;
                       }

                       generate_config_write_cb_name(snode, cb_name,
                                                     sizeof(cb_name));
                       printf("                \"cli_show\": %s,\n", cb_name);

                       need_config_write = false;
               }
       }

       if (!first) {
               printf("            }\n        },\n");
       }

	return YANG_ITER_CONTINUE;
}

int main(int argc, char *argv[])
{
	char **search_paths = NULL;
	char **iter = NULL;
	struct yang_module *module;
	char module_name_underscores[64];
	struct stat st;
	int opt;
	bool config_pass;

	while ((opt = getopt(argc, argv, "hnp:s")) != -1) {
		switch (opt) {
		case 'h':
			usage(EXIT_SUCCESS);
			/* NOTREACHED */
		case 'n':
			f_new_cbs = true;
			break;
		case 'p':
			if (stat(optarg, &st) == -1) {
				fprintf(stderr,
				    "error: invalid search path '%s': %s\n",
				    optarg, strerror(errno));
				exit(EXIT_FAILURE);
			}
			if (S_ISDIR(st.st_mode) == 0) {
				fprintf(stderr,
				    "error: search path is not directory");
				exit(EXIT_FAILURE);
			}

			*darr_append(search_paths) = darr_strdup(optarg);
			break;
		case 's':
			f_static_cbs = true;
			break;
		default:
			usage(EXIT_FAILURE);
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;
	if (argc < 1)
		usage(EXIT_FAILURE);

	yang_init(false, true, false);

	darr_foreach_p (search_paths, iter) {
		ly_ctx_set_searchdir(ly_native_ctx, *iter);
		darr_free(*iter);
	}
	darr_free(search_paths);

	/* Load all FRR native models to ensure all augmentations are loaded. */
	yang_module_load_all();

	while (argc) {
		module = yang_module_find(argv[0]);
		if (!module)
			/* Non-native FRR module (e.g. modules from unit tests). */
			module = yang_module_load(argv[0], NULL);
		argc--;
		argv++;
	}

	yang_init_loading_complete();

	/* Create a nb_node for all YANG schema nodes. */
	nb_nodes_create();

	/* Emit bare-bones license line (and fool the checkpatch regex
	 * that triggers a warning).
	 */
	printf("// SPDX-" "License-Identifier: GPL-2.0-or-later\n\n");

       /* Prototypes are not required for Python output. */

	/* Generate callback functions. */
	yang_snodes_iterate(module->info, generate_callbacks, 0, NULL);

	strlcpy(module_name_underscores, module->name,
		sizeof(module_name_underscores));
	replace_hyphens_by_underscores(module_name_underscores);

	/*
	 * We're going to generate two structs here, two arrays of callbacks:
	 * first one with config-handling callbacks, then a second struct with
	 * config-output-oriented callbacks.
	 */

       /* Generate Python structures with callbacks */
       config_pass = true;
       printf("%s_nb_info = {\n    \"name\": \"%s\",\n    \"nodes\": [\n",
              module_name_underscores, module->name);
       yang_snodes_iterate(module->info, generate_nb_nodes, 0, &config_pass);
       printf("    ]\n}\n");

       /* Generate second array, with output-oriented callbacks. */
       config_pass = false;
       printf("\n%s_cli_info = {\n    \"name\": \"%s\",\n    \"nodes\": [\n",
              module_name_underscores, module->name);
       yang_snodes_iterate(module->info, generate_nb_nodes, 0, &config_pass);
       printf("    ]\n}\n");

	/* Cleanup and exit. */
	nb_nodes_delete();
	yang_terminate();

	return 0;
}
