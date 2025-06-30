static const char * const keystore_features[] = {
	"cleartext-private-key",
	"central-keystore-supported",
	"asymmetric-keys",
	NULL,
};

/* clang-format off */
const struct frr_yang_module_info ietf_keystore_cli_info = {
	.name = "ietf-keystore",
	.features = (const char **)keystore_features,
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = "/ietf-keystore:keystore/asymmetric-keys/asymmetric-key",
			.cbs = {
				.cli_show = keystore_asymmetric_keys_asymmetric_key_cli_write,
			}
		},
		{
			.xpath = "/ietf-keystore:keystore/asymmetric-keys/asymmetric-key/public-key-format",
			.cbs = {
				.cli_show = keystore_asymmetric_keys_asymmetric_key_public_key_format_cli_write,
			}
		},
		{
			.xpath = "/ietf-keystore:keystore/asymmetric-keys/asymmetric-key/public-key",
			.cbs = {
				.cli_show = keystore_asymmetric_keys_asymmetric_key_public_key_cli_write,
			}
		},
		{
			.xpath = "/ietf-keystore:keystore/asymmetric-keys/asymmetric-key/private-key-format",
			.cbs = {
				.cli_show = keystore_asymmetric_keys_asymmetric_key_private_key_format_cli_write,
			}
		},
		{
			.xpath = "/ietf-keystore:keystore/asymmetric-keys/asymmetric-key/cleartext-private-key",
			.cbs = {
				.cli_show = keystore_asymmetric_keys_asymmetric_key_cleartext_private_key_cli_write,
			}
		},
		{
			.xpath = "/ietf-keystore:keystore/asymmetric-keys/asymmetric-key/certificates/certificate",
			.cbs = {
				.cli_show = keystore_asymmetric_keys_asymmetric_key_certificates_certificate_cli_write,
			}
		},
		{
			.xpath = "/ietf-keystore:keystore/asymmetric-keys/asymmetric-key/certificates/certificate/cert-data",
			.cbs = {
				.cli_show = keystore_asymmetric_keys_asymmetric_key_certificates_certificate_cert_data_cli_write,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
