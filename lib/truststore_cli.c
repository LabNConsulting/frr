static const char * const truststore_features[] = {
	"cleartext-private-key",
	"central-truststore-supported",
	"certificates",
	NULL,
};

/* clang-format off */
const struct frr_yang_module_info ietf_truststore_cli_info = {
	.name = "ietf-truststore",
	.features = (const char **)truststore_features,
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = "/ietf-truststore:truststore/certificate-bags/certificate-bag",
			.cbs = {
				.cli_show = truststore_certificate_bags_certificate_bag_cli_write,
			}
		},
		{
			.xpath = "/ietf-truststore:truststore/certificate-bags/certificate-bag/description",
			.cbs = {
				.cli_show = truststore_certificate_bags_certificate_bag_description_cli_write,
			}
		},
		{
			.xpath = "/ietf-truststore:truststore/certificate-bags/certificate-bag/certificate",
			.cbs = {
				.cli_show = truststore_certificate_bags_certificate_bag_certificate_cli_write,
			}
		},
		{
			.xpath = "/ietf-truststore:truststore/certificate-bags/certificate-bag/certificate/cert-data",
			.cbs = {
				.cli_show = truststore_certificate_bags_certificate_bag_certificate_cert_data_cli_write,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
