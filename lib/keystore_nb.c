// SPDX-License-Identifier: GPL-2.0-or-later

/* prototypes */
int keystore_asymmetric_keys_asymmetric_key_create(struct nb_cb_create_args *args);
void keystore_asymmetric_keys_asymmetric_key_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
int keystore_asymmetric_keys_asymmetric_key_destroy(struct nb_cb_destroy_args *args);
int keystore_asymmetric_keys_asymmetric_key_public_key_format_modify(struct nb_cb_modify_args *args);
void keystore_asymmetric_keys_asymmetric_key_public_key_format_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
int keystore_asymmetric_keys_asymmetric_key_public_key_format_destroy(struct nb_cb_destroy_args *args);
int keystore_asymmetric_keys_asymmetric_key_public_key_modify(struct nb_cb_modify_args *args);
void keystore_asymmetric_keys_asymmetric_key_public_key_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
int keystore_asymmetric_keys_asymmetric_key_public_key_destroy(struct nb_cb_destroy_args *args);
int keystore_asymmetric_keys_asymmetric_key_private_key_format_modify(struct nb_cb_modify_args *args);
void keystore_asymmetric_keys_asymmetric_key_private_key_format_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
int keystore_asymmetric_keys_asymmetric_key_private_key_format_destroy(struct nb_cb_destroy_args *args);
int keystore_asymmetric_keys_asymmetric_key_cleartext_private_key_modify(struct nb_cb_modify_args *args);
void keystore_asymmetric_keys_asymmetric_key_cleartext_private_key_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
int keystore_asymmetric_keys_asymmetric_key_cleartext_private_key_destroy(struct nb_cb_destroy_args *args);
int keystore_asymmetric_keys_asymmetric_key_certificates_certificate_create(struct nb_cb_create_args *args);
void keystore_asymmetric_keys_asymmetric_key_certificates_certificate_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
int keystore_asymmetric_keys_asymmetric_key_certificates_certificate_destroy(struct nb_cb_destroy_args *args);
int keystore_asymmetric_keys_asymmetric_key_certificates_certificate_cert_data_modify(struct nb_cb_modify_args *args);
void keystore_asymmetric_keys_asymmetric_key_certificates_certificate_cert_data_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);

/*
 * XPath: /ietf-keystore:keystore/asymmetric-keys/asymmetric-key
 */
int keystore_asymmetric_keys_asymmetric_key_create(struct nb_cb_create_args *args)
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

void keystore_asymmetric_keys_asymmetric_key_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}

int keystore_asymmetric_keys_asymmetric_key_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /ietf-keystore:keystore/asymmetric-keys/asymmetric-key/public-key-format
 */
int keystore_asymmetric_keys_asymmetric_key_public_key_format_modify(struct nb_cb_modify_args *args)
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

void keystore_asymmetric_keys_asymmetric_key_public_key_format_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}

int keystore_asymmetric_keys_asymmetric_key_public_key_format_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /ietf-keystore:keystore/asymmetric-keys/asymmetric-key/public-key
 */
int keystore_asymmetric_keys_asymmetric_key_public_key_modify(struct nb_cb_modify_args *args)
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

void keystore_asymmetric_keys_asymmetric_key_public_key_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}

int keystore_asymmetric_keys_asymmetric_key_public_key_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /ietf-keystore:keystore/asymmetric-keys/asymmetric-key/private-key-format
 */
int keystore_asymmetric_keys_asymmetric_key_private_key_format_modify(struct nb_cb_modify_args *args)
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

void keystore_asymmetric_keys_asymmetric_key_private_key_format_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}

int keystore_asymmetric_keys_asymmetric_key_private_key_format_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /ietf-keystore:keystore/asymmetric-keys/asymmetric-key/cleartext-private-key
 */
int keystore_asymmetric_keys_asymmetric_key_cleartext_private_key_modify(struct nb_cb_modify_args *args)
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

void keystore_asymmetric_keys_asymmetric_key_cleartext_private_key_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}

int keystore_asymmetric_keys_asymmetric_key_cleartext_private_key_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /ietf-keystore:keystore/asymmetric-keys/asymmetric-key/certificates/certificate
 */
int keystore_asymmetric_keys_asymmetric_key_certificates_certificate_create(struct nb_cb_create_args *args)
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

void keystore_asymmetric_keys_asymmetric_key_certificates_certificate_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}

int keystore_asymmetric_keys_asymmetric_key_certificates_certificate_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /ietf-keystore:keystore/asymmetric-keys/asymmetric-key/certificates/certificate/cert-data
 */
int keystore_asymmetric_keys_asymmetric_key_certificates_certificate_cert_data_modify(struct nb_cb_modify_args *args)
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

void keystore_asymmetric_keys_asymmetric_key_certificates_certificate_cert_data_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}

static const char * const keystore_features[] = {
	"cleartext-private-key",
	"central-keystore-supported",
	"asymmetric-keys",
	NULL,
};

/* clang-format off */
const struct frr_yang_module_info ietf_keystore_info = {
	.name = "ietf-keystore",
	.features = (const char **)keystore_features,
	.nodes = {
		{
			.xpath = "/ietf-keystore:keystore/asymmetric-keys/asymmetric-key",
			.cbs = {
				.create = keystore_asymmetric_keys_asymmetric_key_create,
				.destroy = keystore_asymmetric_keys_asymmetric_key_destroy,
			}
		},
		{
			.xpath = "/ietf-keystore:keystore/asymmetric-keys/asymmetric-key/public-key-format",
			.cbs = {
				.modify = keystore_asymmetric_keys_asymmetric_key_public_key_format_modify,
				.destroy = keystore_asymmetric_keys_asymmetric_key_public_key_format_destroy,
			}
		},
		{
			.xpath = "/ietf-keystore:keystore/asymmetric-keys/asymmetric-key/public-key",
			.cbs = {
				.modify = keystore_asymmetric_keys_asymmetric_key_public_key_modify,
				.destroy = keystore_asymmetric_keys_asymmetric_key_public_key_destroy,
			}
		},
		{
			.xpath = "/ietf-keystore:keystore/asymmetric-keys/asymmetric-key/private-key-format",
			.cbs = {
				.modify = keystore_asymmetric_keys_asymmetric_key_private_key_format_modify,
				.destroy = keystore_asymmetric_keys_asymmetric_key_private_key_format_destroy,
			}
		},
		{
			.xpath = "/ietf-keystore:keystore/asymmetric-keys/asymmetric-key/cleartext-private-key",
			.cbs = {
				.modify = keystore_asymmetric_keys_asymmetric_key_cleartext_private_key_modify,
				.destroy = keystore_asymmetric_keys_asymmetric_key_cleartext_private_key_destroy,
			}
		},
		{
			.xpath = "/ietf-keystore:keystore/asymmetric-keys/asymmetric-key/certificates/certificate",
			.cbs = {
				.create = keystore_asymmetric_keys_asymmetric_key_certificates_certificate_create,
				.destroy = keystore_asymmetric_keys_asymmetric_key_certificates_certificate_destroy,
			}
		},
		{
			.xpath = "/ietf-keystore:keystore/asymmetric-keys/asymmetric-key/certificates/certificate/cert-data",
			.cbs = {
				.modify = keystore_asymmetric_keys_asymmetric_key_certificates_certificate_cert_data_modify,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
