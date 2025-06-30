// SPDX-License-Identifier: GPL-2.0-or-later

/* prototypes */
int truststore_certificate_bags_certificate_bag_create(struct nb_cb_create_args *args);
void truststore_certificate_bags_certificate_bag_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
int truststore_certificate_bags_certificate_bag_destroy(struct nb_cb_destroy_args *args);
int truststore_certificate_bags_certificate_bag_description_modify(struct nb_cb_modify_args *args);
void truststore_certificate_bags_certificate_bag_description_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
int truststore_certificate_bags_certificate_bag_description_destroy(struct nb_cb_destroy_args *args);
int truststore_certificate_bags_certificate_bag_certificate_create(struct nb_cb_create_args *args);
void truststore_certificate_bags_certificate_bag_certificate_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
int truststore_certificate_bags_certificate_bag_certificate_destroy(struct nb_cb_destroy_args *args);
int truststore_certificate_bags_certificate_bag_certificate_cert_data_modify(struct nb_cb_modify_args *args);
void truststore_certificate_bags_certificate_bag_certificate_cert_data_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);

/*
 * XPath: /ietf-truststore:truststore/certificate-bags/certificate-bag
 */
int truststore_certificate_bags_certificate_bag_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

void truststore_certificate_bags_certificate_bag_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}

int truststore_certificate_bags_certificate_bag_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /ietf-truststore:truststore/certificate-bags/certificate-bag/description
 */
int truststore_certificate_bags_certificate_bag_description_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

void truststore_certificate_bags_certificate_bag_description_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}

int truststore_certificate_bags_certificate_bag_description_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /ietf-truststore:truststore/certificate-bags/certificate-bag/certificate
 */
int truststore_certificate_bags_certificate_bag_certificate_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

void truststore_certificate_bags_certificate_bag_certificate_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}

int truststore_certificate_bags_certificate_bag_certificate_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /ietf-truststore:truststore/certificate-bags/certificate-bag/certificate/cert-data
 */
int truststore_certificate_bags_certificate_bag_certificate_cert_data_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

void truststore_certificate_bags_certificate_bag_certificate_cert_data_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}

static const char * const truststore_features[] = {
	"cleartext-private-key",
	"central-truststore-supported",
	"certificates",
	NULL,
};

/* clang-format off */
const struct frr_yang_module_info ietf_truststore_info = {
	.name = "ietf-truststore",
	.features = (const char **)truststore_features,
	.nodes = {
		{
			.xpath = "/ietf-truststore:truststore/certificate-bags/certificate-bag",
			.cbs = {
				.create = truststore_certificate_bags_certificate_bag_create,
				.destroy = truststore_certificate_bags_certificate_bag_destroy,
			}
		},
		{
			.xpath = "/ietf-truststore:truststore/certificate-bags/certificate-bag/description",
			.cbs = {
				.modify = truststore_certificate_bags_certificate_bag_description_modify,
				.destroy = truststore_certificate_bags_certificate_bag_description_destroy,
			}
		},
		{
			.xpath = "/ietf-truststore:truststore/certificate-bags/certificate-bag/certificate",
			.cbs = {
				.create = truststore_certificate_bags_certificate_bag_certificate_create,
				.destroy = truststore_certificate_bags_certificate_bag_certificate_destroy,
			}
		},
		{
			.xpath = "/ietf-truststore:truststore/certificate-bags/certificate-bag/certificate/cert-data",
			.cbs = {
				.modify = truststore_certificate_bags_certificate_bag_certificate_cert_data_modify,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
