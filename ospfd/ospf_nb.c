#include <zebra.h>

#include "northbound.h"
#include "libfrr.h"

#include "ospfd/ospf_nb.h"

/* clang-format off */
const struct frr_yang_module_info frr_ospfd_info = {
	.name = "frr-ospfd",
	.nodes = {
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf",
			.cbs = {
				.create = lib_interface_ospf_create,
				.destroy = lib_interface_ospf_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/ospf-id",
			.cbs = {
				.modify = lib_interface_ospf_ospf_id_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/area",
			.cbs = {
				.modify = lib_interface_ospf_area_modify,
				.destroy = lib_interface_ospf_area_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/cost",
			.cbs = {
				.modify = lib_interface_ospf_cost_modify,
				.destroy = lib_interface_ospf_cost_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/passive",
			.cbs = {
				.modify = lib_interface_ospf_passive_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/priority",
			.cbs = {
				.modify = lib_interface_ospf_priority_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-type",
			.cbs = {
				.modify = lib_interface_ospf_interface_type_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/dmvpn",
			.cbs = {
				.modify = lib_interface_ospf_dmvpn_modify,
				.destroy = lib_interface_ospf_dmvpn_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/mtu-ignore",
			.cbs = {
				.modify = lib_interface_ospf_mtu_ignore_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/dead-interval/interval",
			.cbs = {
				.modify = lib_interface_ospf_dead_interval_interval_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/dead-interval/minimal/hello-multiplier",
			.cbs = {
				.modify = lib_interface_ospf_dead_interval_minimal_hello_multiplier_modify,
				.destroy = lib_interface_ospf_dead_interval_minimal_hello_multiplier_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/hello-interval",
			.cbs = {
				.modify = lib_interface_ospf_hello_interval_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/retransmit-interval",
			.cbs = {
				.modify = lib_interface_ospf_retransmit_interval_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/transmit-delay",
			.cbs = {
				.modify = lib_interface_ospf_transmit_delay_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/authentication/type",
			.cbs = {
				.modify = lib_interface_ospf_authentication_type_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/authentication/simple-key",
			.cbs = {
				.modify = lib_interface_ospf_authentication_simple_key_modify,
				.destroy = lib_interface_ospf_authentication_simple_key_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/authentication/mds-keys/mds-key",
			.cbs = {
				.create = lib_interface_ospf_authentication_mds_keys_mds_key_create,
				.destroy = lib_interface_ospf_authentication_mds_keys_mds_key_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/mpls/ldp-sync/enable",
			.cbs = {
				.modify = lib_interface_ospf_mpls_ldp_sync_enable_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/mpls/ldp-sync/holddown",
			.cbs = {
				.modify = lib_interface_ospf_mpls_ldp_sync_holddown_modify,
				.destroy = lib_interface_ospf_mpls_ldp_sync_holddown_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/bfd/enable",
			.cbs = {
				.modify = lib_interface_ospf_bfd_enable_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/bfd/local-multiplier",
			.cbs = {
				.modify = lib_interface_ospf_bfd_local_multiplier_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/bfd/profile",
			.cbs = {
				.modify = lib_interface_ospf_bfd_profile_modify,
				.destroy = lib_interface_ospf_bfd_profile_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/bfd/tx-rx-intervals/desired-min-tx-interval",
			.cbs = {
				.modify = lib_interface_ospf_bfd_tx_rx_intervals_desired_min_tx_interval_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/bfd/tx-rx-intervals/required-min-rx-interval",
			.cbs = {
				.modify = lib_interface_ospf_bfd_tx_rx_intervals_required_min_rx_interval_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address",
			.cbs = {
				.create = lib_interface_ospf_interface_address_create,
				.destroy = lib_interface_ospf_interface_address_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/area",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_area_modify,
				.destroy = lib_interface_ospf_interface_address_area_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/cost",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_cost_modify,
				.destroy = lib_interface_ospf_interface_address_cost_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/passive",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_passive_modify,
				.destroy = lib_interface_ospf_interface_address_passive_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/priority",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_priority_modify,
				.destroy = lib_interface_ospf_interface_address_priority_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/interface-type",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_interface_type_modify,
				.destroy = lib_interface_ospf_interface_address_interface_type_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/dmvpn",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_dmvpn_modify,
				.destroy = lib_interface_ospf_interface_address_dmvpn_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/mtu-ignore",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_mtu_ignore_modify,
				.destroy = lib_interface_ospf_interface_address_mtu_ignore_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/dead-interval/interval",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_dead_interval_interval_modify,
				.destroy = lib_interface_ospf_interface_address_dead_interval_interval_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/dead-interval/minimal/hello-multiplier",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_dead_interval_minimal_hello_multiplier_modify,
				.destroy = lib_interface_ospf_interface_address_dead_interval_minimal_hello_multiplier_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/hello-interval",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_hello_interval_modify,
				.destroy = lib_interface_ospf_interface_address_hello_interval_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/retransmit-interval",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_retransmit_interval_modify,
				.destroy = lib_interface_ospf_interface_address_retransmit_interval_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/transmit-delay",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_transmit_delay_modify,
				.destroy = lib_interface_ospf_interface_address_transmit_delay_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/authentication/type",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_authentication_type_modify,
				.destroy = lib_interface_ospf_interface_address_authentication_type_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/authentication/simple-key",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_authentication_simple_key_modify,
				.destroy = lib_interface_ospf_interface_address_authentication_simple_key_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/authentication/mds-keys/mds-key",
			.cbs = {
				.create = lib_interface_ospf_interface_address_authentication_mds_keys_mds_key_create,
				.destroy = lib_interface_ospf_interface_address_authentication_mds_keys_mds_key_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/mpls/ldp-sync/enable",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_mpls_ldp_sync_enable_modify,
				.destroy = lib_interface_ospf_interface_address_mpls_ldp_sync_enable_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/mpls/ldp-sync/holddown",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_mpls_ldp_sync_holddown_modify,
				.destroy = lib_interface_ospf_interface_address_mpls_ldp_sync_holddown_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/bfd/enable",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_bfd_enable_modify,
				.destroy = lib_interface_ospf_interface_address_bfd_enable_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/bfd/local-multiplier",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_bfd_local_multiplier_modify,
				.destroy = lib_interface_ospf_interface_address_bfd_local_multiplier_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/bfd/profile",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_bfd_profile_modify,
				.destroy = lib_interface_ospf_interface_address_bfd_profile_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/bfd/tx-rx-intervals/desired-min-tx-interval",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_bfd_tx_rx_intervals_desired_min_tx_interval_modify,
				.destroy = lib_interface_ospf_interface_address_bfd_tx_rx_intervals_desired_min_tx_interval_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/bfd/tx-rx-intervals/required-min-rx-interval",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_bfd_tx_rx_intervals_required_min_rx_interval_modify,
				.destroy = lib_interface_ospf_interface_address_bfd_tx_rx_intervals_required_min_rx_interval_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/state",
			.cbs = {
				.get_elem = lib_interface_ospf_state_state_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/hello-timer",
			.cbs = {
				.get_elem = lib_interface_ospf_state_hello_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/wait-timer",
			.cbs = {
				.get_elem = lib_interface_ospf_state_wait_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/dr-router-id",
			.cbs = {
				.get_elem = lib_interface_ospf_state_dr_router_id_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/dr-ip-addr",
			.cbs = {
				.get_elem = lib_interface_ospf_state_dr_ip_addr_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/bdr-router-id",
			.cbs = {
				.get_elem = lib_interface_ospf_state_bdr_router_id_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/bdr-ip-addr",
			.cbs = {
				.get_elem = lib_interface_ospf_state_bdr_ip_addr_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/network-lsa-seqno",
			.cbs = {
				.get_elem = lib_interface_ospf_state_network_lsa_seqno_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/multicast-groups/ospf-all-routers",
			.cbs = {
				.get_elem = lib_interface_ospf_state_multicast_groups_ospf_all_routers_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/multicast-groups/ospf-designated-routers",
			.cbs = {
				.get_elem = lib_interface_ospf_state_multicast_groups_ospf_designated_routers_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/threads/ls-ack",
			.cbs = {
				.get_elem = lib_interface_ospf_state_threads_ls_ack_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/threads/ls-ack/timer",
			.cbs = {
				.get_elem = lib_interface_ospf_state_threads_ls_ack_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/threads/ls-ack-direct",
			.cbs = {
				.get_elem = lib_interface_ospf_state_threads_ls_ack_direct_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/threads/ls-upd-event",
			.cbs = {
				.get_elem = lib_interface_ospf_state_threads_ls_upd_event_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/threads/opaque-lsa-self",
			.cbs = {
				.get_elem = lib_interface_ospf_state_threads_opaque_lsa_self_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/threads/opaque-lsa-self/timer",
			.cbs = {
				.get_elem = lib_interface_ospf_state_threads_opaque_lsa_self_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/statistics/if-event-count",
			.cbs = {
				.get_elem = lib_interface_ospf_state_statistics_if_event_count_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/statistics/hello-in",
			.cbs = {
				.get_elem = lib_interface_ospf_state_statistics_hello_in_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/statistics/hello-out",
			.cbs = {
				.get_elem = lib_interface_ospf_state_statistics_hello_out_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/statistics/db-desc-in",
			.cbs = {
				.get_elem = lib_interface_ospf_state_statistics_db_desc_in_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/statistics/db-desc-out",
			.cbs = {
				.get_elem = lib_interface_ospf_state_statistics_db_desc_out_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/statistics/ls-req-in",
			.cbs = {
				.get_elem = lib_interface_ospf_state_statistics_ls_req_in_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/statistics/ls-req-out",
			.cbs = {
				.get_elem = lib_interface_ospf_state_statistics_ls_req_out_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/statistics/ls-upd-in",
			.cbs = {
				.get_elem = lib_interface_ospf_state_statistics_ls_upd_in_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/statistics/ls-upd-out",
			.cbs = {
				.get_elem = lib_interface_ospf_state_statistics_ls_upd_out_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/statistics/ls-ack-in",
			.cbs = {
				.get_elem = lib_interface_ospf_state_statistics_ls_ack_in_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/statistics/ls-ack-out",
			.cbs = {
				.get_elem = lib_interface_ospf_state_statistics_ls_ack_out_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/statistics/discarded",
			.cbs = {
				.get_elem = lib_interface_ospf_state_statistics_discarded_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/statistics/nbrs",
			.cbs = {
				.get_elem = lib_interface_ospf_state_statistics_nbrs_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/statistics/full-nbrs",
			.cbs = {
				.get_elem = lib_interface_ospf_state_statistics_full_nbrs_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/neighbors/neighbor",
			.cbs = {
				.get_next = lib_interface_ospf_state_neighbors_neighbor_get_next,
				.get_keys = lib_interface_ospf_state_neighbors_neighbor_get_keys,
				.lookup_entry = lib_interface_ospf_state_neighbors_neighbor_lookup_entry,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/neighbors/neighbor/neighbor-router-id",
			.cbs = {
				.get_elem = lib_interface_ospf_state_neighbors_neighbor_neighbor_router_id_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/neighbors/neighbor/address",
			.cbs = {
				.get_elem = lib_interface_ospf_state_neighbors_neighbor_address_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/neighbors/neighbor/dr-router-id",
			.cbs = {
				.get_elem = lib_interface_ospf_state_neighbors_neighbor_dr_router_id_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/neighbors/neighbor/dr-ip-addr",
			.cbs = {
				.get_elem = lib_interface_ospf_state_neighbors_neighbor_dr_ip_addr_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/neighbors/neighbor/bdr-router-id",
			.cbs = {
				.get_elem = lib_interface_ospf_state_neighbors_neighbor_bdr_router_id_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/neighbors/neighbor/bdr-ip-addr",
			.cbs = {
				.get_elem = lib_interface_ospf_state_neighbors_neighbor_bdr_ip_addr_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/neighbors/neighbor/state",
			.cbs = {
				.get_elem = lib_interface_ospf_state_neighbors_neighbor_state_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/neighbors/neighbor/dead-timer",
			.cbs = {
				.get_elem = lib_interface_ospf_state_neighbors_neighbor_dead_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/neighbors/neighbor/statistics/nbr-retrans-qlen",
			.cbs = {
				.get_elem = lib_interface_ospf_state_neighbors_neighbor_statistics_nbr_retrans_qlen_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/neighbors/neighbor/statistics/nbr-request-qlen",
			.cbs = {
				.get_elem = lib_interface_ospf_state_neighbors_neighbor_statistics_nbr_request_qlen_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/neighbors/neighbor/statistics/nbr-summary-len",
			.cbs = {
				.get_elem = lib_interface_ospf_state_neighbors_neighbor_statistics_nbr_summary_len_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/neighbors/neighbor/statistics/nbr-uptime",
			.cbs = {
				.get_elem = lib_interface_ospf_state_neighbors_neighbor_statistics_nbr_uptime_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/neighbors/neighbor/statistics/nbr-downtime",
			.cbs = {
				.get_elem = lib_interface_ospf_state_neighbors_neighbor_statistics_nbr_downtime_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/neighbors/neighbor/statistics/nsm/state-changes",
			.cbs = {
				.get_elem = lib_interface_ospf_state_neighbors_neighbor_statistics_nsm_state_changes_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/neighbors/neighbor/statistics/nsm/last-progressive",
			.cbs = {
				.get_elem = lib_interface_ospf_state_neighbors_neighbor_statistics_nsm_last_progressive_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/neighbors/neighbor/statistics/nsm/last-regressive",
			.cbs = {
				.get_elem = lib_interface_ospf_state_neighbors_neighbor_statistics_nsm_last_regressive_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/neighbors/neighbor/threads/db-desc-retransmission",
			.cbs = {
				.get_elem = lib_interface_ospf_state_neighbors_neighbor_threads_db_desc_retransmission_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/neighbors/neighbor/threads/db-desc-retransmission/timer",
			.cbs = {
				.get_elem = lib_interface_ospf_state_neighbors_neighbor_threads_db_desc_retransmission_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/neighbors/neighbor/threads/ls-request-retransmission",
			.cbs = {
				.get_elem = lib_interface_ospf_state_neighbors_neighbor_threads_ls_request_retransmission_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/neighbors/neighbor/threads/ls-request-retransmission/timer",
			.cbs = {
				.get_elem = lib_interface_ospf_state_neighbors_neighbor_threads_ls_request_retransmission_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/neighbors/neighbor/threads/ls-update-retransmission",
			.cbs = {
				.get_elem = lib_interface_ospf_state_neighbors_neighbor_threads_ls_update_retransmission_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/neighbors/neighbor/threads/ls-update-retransmission/timer",
			.cbs = {
				.get_elem = lib_interface_ospf_state_neighbors_neighbor_threads_ls_update_retransmission_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/neighbors/neighbor/threads/hello-reply",
			.cbs = {
				.get_elem = lib_interface_ospf_state_neighbors_neighbor_threads_hello_reply_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/neighbors/neighbor/threads/hello-reply/timer",
			.cbs = {
				.get_elem = lib_interface_ospf_state_neighbors_neighbor_threads_hello_reply_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/neighbors/neighbor/graceful-restart-helper/grace-period",
			.cbs = {
				.get_elem = lib_interface_ospf_state_neighbors_neighbor_graceful_restart_helper_grace_period_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/neighbors/neighbor/graceful-restart-helper/restart-reason",
			.cbs = {
				.get_elem = lib_interface_ospf_state_neighbors_neighbor_graceful_restart_helper_restart_reason_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/neighbors/neighbor/graceful-restart-helper/helper-status",
			.cbs = {
				.get_elem = lib_interface_ospf_state_neighbors_neighbor_graceful_restart_helper_helper_status_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/neighbors/neighbor/graceful-restart-helper/helper-exit-reason",
			.cbs = {
				.get_elem = lib_interface_ospf_state_neighbors_neighbor_graceful_restart_helper_helper_exit_reason_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/neighbors/neighbor/graceful-restart-helper/helper-rejected-reason",
			.cbs = {
				.get_elem = lib_interface_ospf_state_neighbors_neighbor_graceful_restart_helper_helper_rejected_reason_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type",
			.cbs = {
				.get_next = lib_interface_ospf_state_database_link_scope_lsa_type_get_next,
				.get_keys = lib_interface_ospf_state_database_link_scope_lsa_type_get_keys,
				.lookup_entry = lib_interface_ospf_state_database_link_scope_lsa_type_lookup_entry,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/lsa-type",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_lsa_type_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa",
			.cbs = {
				.get_next = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_get_next,
				.get_keys = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_get_keys,
				.lookup_entry = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_lookup_entry,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/lsa-id",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_lsa_id_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/adv-router",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_adv_router_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/decode-completed",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_decode_completed_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/raw-data",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_raw_data_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/header/lsa-options/lsa-option",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_header_lsa_options_lsa_option_get_elem,
				.get_next = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_header_lsa_options_lsa_option_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/header/lsa-id",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_header_lsa_id_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/header/opaque-type",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_header_opaque_type_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/header/opaque-id",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_header_opaque_id_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/header/age",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_header_age_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/header/type",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_header_type_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/header/adv-router",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_header_adv_router_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/header/seq-num",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_header_seq_num_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/header/checksum",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_header_checksum_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/header/length",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_header_length_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/router/router-bits/rtr-lsa-bits",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_router_router_bits_rtr_lsa_bits_get_elem,
				.get_next = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_router_router_bits_rtr_lsa_bits_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/router/num-of-links",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_router_num_of_links_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/router/links/link",
			.cbs = {
				.get_next = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_router_links_link_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/router/links/link/link-id",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_router_links_link_link_id_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/router/links/link/link-data",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_router_links_link_link_data_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/router/links/link/type",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_router_links_link_type_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/router/links/link/topologies/topology",
			.cbs = {
				.get_next = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_router_links_link_topologies_topology_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/router/links/link/topologies/topology/mt-id",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_router_links_link_topologies_topology_mt_id_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/router/links/link/topologies/topology/metric",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_router_links_link_topologies_topology_metric_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/network/network-mask",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_network_network_mask_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/network/attached-routers/attached-router",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_network_attached_routers_attached_router_get_elem,
				.get_next = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_network_attached_routers_attached_router_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/summary/network-mask",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_summary_network_mask_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/summary/topologies/topology",
			.cbs = {
				.get_next = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_summary_topologies_topology_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/summary/topologies/topology/mt-id",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_summary_topologies_topology_mt_id_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/summary/topologies/topology/metric",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_summary_topologies_topology_metric_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/external/network-mask",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_external_network_mask_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/external/topologies/topology",
			.cbs = {
				.get_next = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_external_topologies_topology_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/external/topologies/topology/mt-id",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_external_topologies_topology_mt_id_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/external/topologies/topology/flags",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_external_topologies_topology_flags_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/external/topologies/topology/metric",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_external_topologies_topology_metric_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/external/topologies/topology/forwarding-address",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_external_topologies_topology_forwarding_address_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/external/topologies/topology/external-route-tag",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_external_topologies_topology_external_route_tag_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/router-capabilities-tlv/router-informational-capabilities/informational-capabilities",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_router_capabilities_tlv_router_informational_capabilities_informational_capabilities_get_elem,
				.get_next = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_router_capabilities_tlv_router_informational_capabilities_informational_capabilities_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/pce-address",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_pce_address_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/path-scope/scope-flags",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_path_scope_scope_flags_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/path-scope/pref-l",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_path_scope_pref_l_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/path-scope/pref-r",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_path_scope_pref_r_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/path-scope/pref-s",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_path_scope_pref_s_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/path-scope/pref-y",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_path_scope_pref_y_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/domain/type",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_domain_type_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/domain/id",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_domain_id_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/neighbors/neighbor",
			.cbs = {
				.get_next = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_neighbors_neighbor_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/neighbors/neighbor/type",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_neighbors_neighbor_type_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/neighbors/neighbor/id",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_neighbors_neighbor_id_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/capabilities",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_capabilities_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/sr-algorithm-tlv/sr-algorithm",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_sr_algorithm_tlv_sr_algorithm_get_elem,
				.get_next = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_sr_algorithm_tlv_sr_algorithm_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/sid-range-tlvs/sid-range-tlv",
			.cbs = {
				.get_next = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_sid_range_tlvs_sid_range_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/sid-range-tlvs/sid-range-tlv/range-size",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_sid_range_tlvs_sid_range_tlv_range_size_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/sid-range-tlvs/sid-range-tlv/sid-sub-tlv/sid",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_sid_range_tlvs_sid_range_tlv_sid_sub_tlv_sid_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/local-block-tlvs/local-block-tlv",
			.cbs = {
				.get_next = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_local_block_tlvs_local_block_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/local-block-tlvs/local-block-tlv/range-size",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_local_block_tlvs_local_block_tlv_range_size_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/local-block-tlvs/local-block-tlv/sid-sub-tlv/sid",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_local_block_tlvs_local_block_tlv_sid_sub_tlv_sid_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/node-msd-tlvs/node-msd-tlv",
			.cbs = {
				.get_next = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_node_msd_tlvs_node_msd_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/node-msd-tlvs/node-msd-tlv/type",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_node_msd_tlvs_node_msd_tlv_type_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/node-msd-tlvs/node-msd-tlv/value",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_node_msd_tlvs_node_msd_tlv_value_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/unknown-tlvs/unknown-tlv",
			.cbs = {
				.get_next = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_unknown_tlvs_unknown_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/unknown-tlvs/unknown-tlv/type",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_unknown_tlvs_unknown_tlv_type_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/unknown-tlvs/unknown-tlv/length",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_unknown_tlvs_unknown_tlv_length_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/unknown-tlvs/unknown-tlv/value",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_unknown_tlvs_unknown_tlv_value_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/router-address-tlv/router-address",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_router_address_tlv_router_address_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/link-type",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_link_type_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/link-id",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_link_id_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/local-if-ipv4-addrs/local-if-ipv4-addr",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_local_if_ipv4_addrs_local_if_ipv4_addr_get_elem,
				.get_next = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_local_if_ipv4_addrs_local_if_ipv4_addr_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/remote-if-ipv4-addrs/remote-if-ipv4-addr",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_remote_if_ipv4_addrs_remote_if_ipv4_addr_get_elem,
				.get_next = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_remote_if_ipv4_addrs_remote_if_ipv4_addr_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/te-metric",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_te_metric_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/max-bandwidth",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_max_bandwidth_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/max-reservable-bandwidth",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_max_reservable_bandwidth_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unreserved-bandwidths/unreserved-bandwidth",
			.cbs = {
				.get_next = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unreserved_bandwidths_unreserved_bandwidth_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unreserved-bandwidths/unreserved-bandwidth/priority",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unreserved_bandwidths_unreserved_bandwidth_priority_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unreserved-bandwidths/unreserved-bandwidth/unreserved-bandwidth",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unreserved_bandwidths_unreserved_bandwidth_unreserved_bandwidth_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/admin-group",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_admin_group_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/local-and-remote-te-router-id/local-router-id",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_local_and_remote_te_router_id_local_router_id_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/local-and-remote-te-router-id/remote-router-id",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_local_and_remote_te_router_id_remote_router_id_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/link-local-remote-id/link-local-id",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_link_local_remote_id_link_local_id_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/link-local-remote-id/link-remote-id",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_link_local_remote_id_link_remote_id_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/remote-as-number",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_remote_as_number_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/ipv4-remote-asbr-id",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_ipv4_remote_asbr_id_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unidirectional-link-delay",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unidirectional_link_delay_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/min-max-unidirectional-link-delay/min-delay",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_min_max_unidirectional_link_delay_min_delay_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/min-max-unidirectional-link-delay/max-delay",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_min_max_unidirectional_link_delay_max_delay_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unidirectional-delay-variation",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unidirectional_delay_variation_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unidirectional-link-loss",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unidirectional_link_loss_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unidirectional-residual-bandwidth",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unidirectional_residual_bandwidth_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unidirectional-available-bandwidth",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unidirectional_available_bandwidth_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unidirectional-utilized-bandwidth",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unidirectional_utilized_bandwidth_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unknown-tlvs/unknown-tlv",
			.cbs = {
				.get_next = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unknown_tlvs_unknown_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unknown-tlvs/unknown-tlv/type",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unknown_tlvs_unknown_tlv_type_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unknown-tlvs/unknown-tlv/length",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unknown_tlvs_unknown_tlv_length_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unknown-tlvs/unknown-tlv/value",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unknown_tlvs_unknown_tlv_value_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/grace-lsa-opaque/grace-period-tlv/grace-period",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_grace_lsa_opaque_grace_period_tlv_grace_period_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/grace-lsa-opaque/restart-reason-tlv/restart-reason",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_grace_lsa_opaque_restart_reason_tlv_restart_reason_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/grace-lsa-opaque/if-address-tlv/if-address",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_grace_lsa_opaque_if_address_tlv_if_address_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv",
			.cbs = {
				.get_next = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/route-type",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_route_type_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/flags/extended-prefix-flags",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_flags_extended_prefix_flags_get_elem,
				.get_next = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_flags_extended_prefix_flags_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/prefix",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_prefix_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/prefix-sid-sub-tlvs/prefix-sid-sub-tlv",
			.cbs = {
				.get_next = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_prefix_sid_sub_tlvs_prefix_sid_sub_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/prefix-sid-sub-tlvs/prefix-sid-sub-tlv/prefix-sid-flags/bits",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_prefix_sid_sub_tlvs_prefix_sid_sub_tlv_prefix_sid_flags_bits_get_elem,
				.get_next = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_prefix_sid_sub_tlvs_prefix_sid_sub_tlv_prefix_sid_flags_bits_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/prefix-sid-sub-tlvs/prefix-sid-sub-tlv/mt-id",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_prefix_sid_sub_tlvs_prefix_sid_sub_tlv_mt_id_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/prefix-sid-sub-tlvs/prefix-sid-sub-tlv/algorithm",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_prefix_sid_sub_tlvs_prefix_sid_sub_tlv_algorithm_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/prefix-sid-sub-tlvs/prefix-sid-sub-tlv/sid",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_prefix_sid_sub_tlvs_prefix_sid_sub_tlv_sid_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/unknown-tlvs/unknown-tlv",
			.cbs = {
				.get_next = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_unknown_tlvs_unknown_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/unknown-tlvs/unknown-tlv/type",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_unknown_tlvs_unknown_tlv_type_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/unknown-tlvs/unknown-tlv/length",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_unknown_tlvs_unknown_tlv_length_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/unknown-tlvs/unknown-tlv/value",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_unknown_tlvs_unknown_tlv_value_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv",
			.cbs = {
				.get_next = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/prefix-length",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_prefix_length_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/af",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_af_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/range-size",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_range_size_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/extended-prefix-range-flags/bits",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_extended_prefix_range_flags_bits_get_elem,
				.get_next = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_extended_prefix_range_flags_bits_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/prefix",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_prefix_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/unknown-tlvs/unknown-tlv",
			.cbs = {
				.get_next = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_unknown_tlvs_unknown_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/unknown-tlvs/unknown-tlv/type",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_unknown_tlvs_unknown_tlv_type_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/unknown-tlvs/unknown-tlv/length",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_unknown_tlvs_unknown_tlv_length_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/unknown-tlvs/unknown-tlv/value",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_unknown_tlvs_unknown_tlv_value_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/link-id",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_link_id_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/link-data",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_link_data_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/type",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_type_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/maximum-sid-depth-tlv/msd-type",
			.cbs = {
				.get_next = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_maximum_sid_depth_tlv_msd_type_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/maximum-sid-depth-tlv/msd-type/msd-type",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_maximum_sid_depth_tlv_msd_type_msd_type_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/maximum-sid-depth-tlv/msd-type/msd-value",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_maximum_sid_depth_tlv_msd_type_msd_value_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/adj-sid-sub-tlvs/adj-sid-sub-tlv",
			.cbs = {
				.get_next = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_adj_sid_sub_tlvs_adj_sid_sub_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/adj-sid-sub-tlvs/adj-sid-sub-tlv/adj-sid-flags/bits",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_adj_sid_sub_tlvs_adj_sid_sub_tlv_adj_sid_flags_bits_get_elem,
				.get_next = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_adj_sid_sub_tlvs_adj_sid_sub_tlv_adj_sid_flags_bits_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/adj-sid-sub-tlvs/adj-sid-sub-tlv/mt-id",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_adj_sid_sub_tlvs_adj_sid_sub_tlv_mt_id_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/adj-sid-sub-tlvs/adj-sid-sub-tlv/weight",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_adj_sid_sub_tlvs_adj_sid_sub_tlv_weight_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/adj-sid-sub-tlvs/adj-sid-sub-tlv/sid",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_adj_sid_sub_tlvs_adj_sid_sub_tlv_sid_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/lan-adj-sid-sub-tlvs/lan-adj-sid-sub-tlv",
			.cbs = {
				.get_next = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_lan_adj_sid_sub_tlvs_lan_adj_sid_sub_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/lan-adj-sid-sub-tlvs/lan-adj-sid-sub-tlv/lan-adj-sid-flags/bits",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_lan_adj_sid_sub_tlvs_lan_adj_sid_sub_tlv_lan_adj_sid_flags_bits_get_elem,
				.get_next = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_lan_adj_sid_sub_tlvs_lan_adj_sid_sub_tlv_lan_adj_sid_flags_bits_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/lan-adj-sid-sub-tlvs/lan-adj-sid-sub-tlv/mt-id",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_lan_adj_sid_sub_tlvs_lan_adj_sid_sub_tlv_mt_id_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/lan-adj-sid-sub-tlvs/lan-adj-sid-sub-tlv/weight",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_lan_adj_sid_sub_tlvs_lan_adj_sid_sub_tlv_weight_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/lan-adj-sid-sub-tlvs/lan-adj-sid-sub-tlv/neighbor-router-id",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_lan_adj_sid_sub_tlvs_lan_adj_sid_sub_tlv_neighbor_router_id_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/lan-adj-sid-sub-tlvs/lan-adj-sid-sub-tlv/sid",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_lan_adj_sid_sub_tlvs_lan_adj_sid_sub_tlv_sid_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/remote-if-address",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_remote_if_address_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/unknown-tlvs/unknown-tlv",
			.cbs = {
				.get_next = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_unknown_tlvs_unknown_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/unknown-tlvs/unknown-tlv/type",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_unknown_tlvs_unknown_tlv_type_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/unknown-tlvs/unknown-tlv/length",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_unknown_tlvs_unknown_tlv_length_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/unknown-tlvs/unknown-tlv/value",
			.cbs = {
				.get_elem = lib_interface_ospf_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_unknown_tlvs_unknown_tlv_value_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/use-arp",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_use_arp_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/explicit-router-id",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_explicit_router_id_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_explicit_router_id_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/capability-opaque",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_capability_opaque_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/compatible-rfc1583",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_compatible_rfc1583_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/log-adjacency-changes",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_log_adjacency_changes_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_log_adjacency_changes_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/log-adjacency-changes/detail",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_log_adjacency_changes_detail_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/send-extra-data-zebra",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_send_extra_data_zebra_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/default-metric",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_default_metric_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_default_metric_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/write-multiplier",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_write_multiplier_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/passive-interface-default",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_passive_interface_default_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/abr-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_abr_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info/as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info/area",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_area_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_area_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info/pce/address",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_address_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_address_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info/pce/scope/scope-flags",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_scope_scope_flags_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_scope_scope_flags_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info/pce/scope/pref-l",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_scope_pref_l_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_scope_pref_l_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info/pce/scope/pref-r",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_scope_pref_r_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_scope_pref_r_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info/pce/scope/pref-s",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_scope_pref_s_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_scope_pref_s_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info/pce/scope/pref-y",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_scope_pref_y_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_scope_pref_y_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info/pce/as/domain",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_as_domain_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_as_domain_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info/pce/as/neighbor",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_as_neighbor_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_as_neighbor_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info/pce/capabilities",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_capabilities_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_capabilities_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/graceful-restart/enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_graceful_restart_enable_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/graceful-restart/helper-enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_graceful_restart_helper_enable_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/graceful-restart/restart-interval",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_graceful_restart_restart_interval_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/graceful-restart/helper-strict-lsa-checking",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_graceful_restart_helper_strict_lsa_checking_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/graceful-restart/helper-only-planned-restart",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_graceful_restart_helper_only_planned_restart_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/graceful-restart/supported-grace-time",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_graceful_restart_supported_grace_time_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/auto-cost/reference-bandwidth",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_auto_cost_reference_bandwidth_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/default-information/originate",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_default_information_originate_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/default-information/metric",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_default_information_metric_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_default_information_metric_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/default-information/metric-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_default_information_metric_type_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_default_information_metric_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/default-information/route-map",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_default_information_route_map_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_default_information_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/redistribute/routes",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_routes_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_routes_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/redistribute/routes/metric",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_routes_metric_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_routes_metric_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/redistribute/routes/metric-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_routes_metric_type_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_routes_metric_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/redistribute/routes/route-map",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_routes_route_map_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_routes_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/route-aggregation/summary-routes/summary",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_route_aggregation_summary_routes_summary_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_route_aggregation_summary_routes_summary_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/route-aggregation/summary-routes/summary/tag",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_route_aggregation_summary_routes_summary_tag_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_route_aggregation_summary_routes_summary_tag_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/route-aggregation/summary-routes/summary/no-advertise",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_route_aggregation_summary_routes_summary_no_advertise_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/route-aggregation/timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_route_aggregation_timer_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/preference/all",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_preference_all_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_preference_all_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/preference/external",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_preference_external_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_preference_external_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/preference/inter-area",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_preference_inter_area_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_preference_inter_area_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/preference/intra-area",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_preference_intra_area_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_preference_intra_area_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/distribute-from-zebra/distribute",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_distribute_from_zebra_distribute_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_distribute_from_zebra_distribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/max-metric/router-lsa/always",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_max_metric_router_lsa_always_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/max-metric/router-lsa/on-shutdown",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_max_metric_router_lsa_on_shutdown_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_max_metric_router_lsa_on_shutdown_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/max-metric/router-lsa/on-startup",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_max_metric_router_lsa_on_startup_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_max_metric_router_lsa_on_startup_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/mpls/te/on",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_mpls_te_on_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/mpls/te/rid",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_mpls_te_rid_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_mpls_te_rid_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/mpls/te/inter-as/as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_mpls_te_inter_as_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_mpls_te_inter_as_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/mpls/te/inter-as/area",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_mpls_te_inter_as_area_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_mpls_te_inter_as_area_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/mpls/ldp/igp-sync",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_mpls_ldp_igp_sync_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/mpls/ldp/holddown",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_mpls_ldp_holddown_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/fast-reroute/ti-lfa/protection",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_fast_reroute_ti_lfa_protection_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/spf-control/paths",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_spf_control_paths_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/spf-control/ietf-spf-delay/delay",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_spf_control_ietf_spf_delay_delay_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/spf-control/ietf-spf-delay/initial-holdtime",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_spf_control_ietf_spf_delay_initial_holdtime_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/spf-control/ietf-spf-delay/max-holdtime",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_spf_control_ietf_spf_delay_max_holdtime_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/spf-control/ietf-spf-delay/hold-multiplier",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_spf_control_ietf_spf_delay_hold_multiplier_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/timers/refresh-interval",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_timers_refresh_interval_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/timers/lsa-min-arrival",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_timers_lsa_min_arrival_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/timers/lsa-min-interval",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_timers_lsa_min_interval_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/sr-mpls/srgb/lower-bound",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_sr_mpls_srgb_lower_bound_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/sr-mpls/srgb/upper-bound",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_sr_mpls_srgb_upper_bound_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/sr-mpls/srlb/lower-bound",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_sr_mpls_srlb_lower_bound_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/sr-mpls/srlb/upper-bound",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_sr_mpls_srlb_upper_bound_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/sr-mpls/node-msd",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_sr_mpls_node_msd_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_sr_mpls_node_msd_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/sr-mpls/on",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_sr_mpls_on_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/sr-mpls/bindings/connected-prefix-sid-map/connected-prefix-sid",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_sr_mpls_bindings_connected_prefix_sid_map_connected_prefix_sid_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_sr_mpls_bindings_connected_prefix_sid_map_connected_prefix_sid_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/sr-mpls/bindings/connected-prefix-sid-map/connected-prefix-sid/value-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_sr_mpls_bindings_connected_prefix_sid_map_connected_prefix_sid_value_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/sr-mpls/bindings/connected-prefix-sid-map/connected-prefix-sid/sid-value",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_sr_mpls_bindings_connected_prefix_sid_map_connected_prefix_sid_sid_value_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/sr-mpls/bindings/connected-prefix-sid-map/connected-prefix-sid/last-hop-behavior",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_sr_mpls_bindings_connected_prefix_sid_map_connected_prefix_sid_last_hop_behavior_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/nbma-neighbors/neighbor",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_nbma_neighbors_neighbor_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_nbma_neighbors_neighbor_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/nbma-neighbors/neighbor/priority",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_nbma_neighbors_neighbor_priority_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/nbma-neighbors/neighbor/poll-interval",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_nbma_neighbors_neighbor_poll_interval_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/ip-networks/network",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_ip_networks_network_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_ip_networks_network_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/ip-networks/network/area",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_ip_networks_network_area_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/router-flags/router-flag",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_router_flags_router_flag_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_router_flags_router_flag_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/threads/abr-task",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_threads_abr_task_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/threads/abr-task/timer",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_threads_abr_task_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/threads/asbr-check",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_threads_asbr_check_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/threads/asbr-check/timer",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_threads_asbr_check_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/threads/asbr-nssa-redist-update",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_threads_asbr_nssa_redist_update_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/threads/asbr-nssa-redist-update/timer",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_threads_asbr_nssa_redist_update_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/threads/distribute-update",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_threads_distribute_update_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/threads/distribute-update/timer",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_threads_distribute_update_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/threads/spf-calc",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_threads_spf_calc_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/threads/spf-calc/timer",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_threads_spf_calc_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/threads/ase-calc",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_threads_ase_calc_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/threads/ase-calc/timer",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_threads_ase_calc_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/threads/opaque-lsa-self",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_threads_opaque_lsa_self_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/threads/opaque-lsa-self/timer",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_threads_opaque_lsa_self_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/threads/sr-update",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_threads_sr_update_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/threads/sr-update/timer",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_threads_sr_update_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/threads/max-age",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_threads_max_age_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/threads/max-age/timer",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_threads_max_age_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/threads/max-age-walker",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_threads_max_age_walker_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/threads/max-age-walker/timer",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_threads_max_age_walker_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/threads/deferred-shutdown",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_threads_deferred_shutdown_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/threads/deferred-shutdown/timer",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_threads_deferred_shutdown_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/threads/default-routemap-timer",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_threads_default_routemap_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/threads/lsa-refresher",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_threads_lsa_refresher_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/threads/lsa-refresher/timer",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_threads_lsa_refresher_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/threads/lsa-refresher/started",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_threads_lsa_refresher_started_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/threads/external-aggr",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_threads_external_aggr_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/threads/external-aggr/timer",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_threads_external_aggr_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/graceful-restart/active-restarter-count",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_graceful_restart_active_restarter_count_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/graceful-restart/last-exit-reason",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_graceful_restart_last_exit_reason_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/network",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_network_get_next,
				.get_keys = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_network_get_keys,
				.lookup_entry = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_network_lookup_entry,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/network/prefix",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_network_prefix_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/network/next-hops/next-hop",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_network_next_hops_next_hop_get_next,
				.get_keys = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_network_next_hops_next_hop_get_keys,
				.lookup_entry = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_network_next_hops_next_hop_lookup_entry,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/network/next-hops/next-hop/next-hop",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_network_next_hops_next_hop_next_hop_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/network/next-hops/next-hop/outgoing-interface",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_network_next_hops_next_hop_outgoing_interface_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/network/metric",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_network_metric_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/network/route-type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_network_route_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/network/destination-type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_network_destination_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/network/changed",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_network_changed_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/network/area-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_network_area_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/network/area-type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_network_area_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/network/options/lsa-options",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_network_options_lsa_options_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_network_options_lsa_options_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/network/flags/router-flags",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_network_flags_router_flags_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_network_flags_router_flags_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/router",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_router_get_next,
				.get_keys = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_router_get_keys,
				.lookup_entry = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_router_lookup_entry,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/router/prefix",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_router_prefix_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/router/next-hops/next-hop",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_router_next_hops_next_hop_get_next,
				.get_keys = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_router_next_hops_next_hop_get_keys,
				.lookup_entry = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_router_next_hops_next_hop_lookup_entry,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/router/next-hops/next-hop/next-hop",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_router_next_hops_next_hop_next_hop_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/router/next-hops/next-hop/outgoing-interface",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_router_next_hops_next_hop_outgoing_interface_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/router/metric",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_router_metric_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/router/route-type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_router_route_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/router/destination-type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_router_destination_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/router/changed",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_router_changed_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/router/area-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_router_area_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/router/area-type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_router_area_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/router/options/lsa-options",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_router_options_lsa_options_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_router_options_lsa_options_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/router/flags/router-flags",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_router_flags_router_flags_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_router_flags_router_flags_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/border",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_border_get_next,
				.get_keys = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_border_get_keys,
				.lookup_entry = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_border_lookup_entry,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/border/prefix",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_border_prefix_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/border/next-hops/next-hop",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_border_next_hops_next_hop_get_next,
				.get_keys = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_border_next_hops_next_hop_get_keys,
				.lookup_entry = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_border_next_hops_next_hop_lookup_entry,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/border/next-hops/next-hop/next-hop",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_border_next_hops_next_hop_next_hop_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/border/next-hops/next-hop/outgoing-interface",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_border_next_hops_next_hop_outgoing_interface_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/border/metric",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_border_metric_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/border/route-type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_border_route_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/border/destination-type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_border_destination_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/border/changed",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_border_changed_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/border/area-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_border_area_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/border/area-type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_border_area_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/border/options/lsa-options",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_border_options_lsa_options_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_border_options_lsa_options_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/border/flags/router-flags",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_border_flags_router_flags_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_border_flags_router_flags_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/external",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_external_get_next,
				.get_keys = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_external_get_keys,
				.lookup_entry = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_external_lookup_entry,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/external/prefix",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_external_prefix_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/external/next-hops/next-hop",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_external_next_hops_next_hop_get_next,
				.get_keys = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_external_next_hops_next_hop_get_keys,
				.lookup_entry = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_external_next_hops_next_hop_lookup_entry,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/external/next-hops/next-hop/next-hop",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_external_next_hops_next_hop_next_hop_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/external/next-hops/next-hop/outgoing-interface",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_external_next_hops_next_hop_outgoing_interface_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/external/metric",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_external_metric_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/external/route-type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_external_route_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/external/destination-type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_external_destination_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/external/changed",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_external_changed_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/external/ls-cost",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_external_ls_cost_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/external/route-tag",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_external_route_tag_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/external/asbr/prefix",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_external_asbr_prefix_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/external/asbr/next-hops/next-hop",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_external_asbr_next_hops_next_hop_get_next,
				.get_keys = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_external_asbr_next_hops_next_hop_get_keys,
				.lookup_entry = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_external_asbr_next_hops_next_hop_lookup_entry,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/external/asbr/next-hops/next-hop/next-hop",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_external_asbr_next_hops_next_hop_next_hop_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/external/asbr/next-hops/next-hop/outgoing-interface",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_external_asbr_next_hops_next_hop_outgoing_interface_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/external/asbr/metric",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_external_asbr_metric_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/external/asbr/route-type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_external_asbr_route_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/external/asbr/destination-type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_external_asbr_destination_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/external/asbr/changed",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_external_asbr_changed_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/external/asbr/area-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_external_asbr_area_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/external/asbr/area-type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_external_asbr_area_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/external/asbr/options/lsa-options",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_external_asbr_options_lsa_options_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_external_asbr_options_lsa_options_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/local-rib/external/asbr/flags/router-flags",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_external_asbr_flags_router_flags_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_local_rib_external_asbr_flags_router_flags_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/statistics/originate-new-lsa-count",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_statistics_originate_new_lsa_count_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/statistics/rx-new-lsas-count",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_statistics_rx_new_lsas_count_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/statistics/spf/timestamp",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_statistics_spf_timestamp_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/statistics/spf/duration",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_statistics_spf_duration_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_get_next,
				.get_keys = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_get_keys,
				.lookup_entry = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_lookup_entry,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/lsa-type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_lsa_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_get_next,
				.get_keys = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_get_keys,
				.lookup_entry = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_lookup_entry,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/lsa-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_lsa_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/adv-router",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_adv_router_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/decode-completed",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_decode_completed_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/raw-data",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_raw_data_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/header/lsa-options/lsa-option",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_header_lsa_options_lsa_option_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_header_lsa_options_lsa_option_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/header/lsa-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_header_lsa_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/header/opaque-type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_header_opaque_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/header/opaque-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_header_opaque_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/header/age",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_header_age_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/header/type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_header_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/header/adv-router",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_header_adv_router_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/header/seq-num",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_header_seq_num_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/header/checksum",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_header_checksum_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/header/length",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_header_length_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/router/router-bits/rtr-lsa-bits",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_router_router_bits_rtr_lsa_bits_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_router_router_bits_rtr_lsa_bits_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/router/num-of-links",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_router_num_of_links_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/router/links/link",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_router_links_link_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/router/links/link/link-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_router_links_link_link_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/router/links/link/link-data",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_router_links_link_link_data_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/router/links/link/type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_router_links_link_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/router/links/link/topologies/topology",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_router_links_link_topologies_topology_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/router/links/link/topologies/topology/mt-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_router_links_link_topologies_topology_mt_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/router/links/link/topologies/topology/metric",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_router_links_link_topologies_topology_metric_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/network/network-mask",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_network_network_mask_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/network/attached-routers/attached-router",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_network_attached_routers_attached_router_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_network_attached_routers_attached_router_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/summary/network-mask",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_summary_network_mask_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/summary/topologies/topology",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_summary_topologies_topology_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/summary/topologies/topology/mt-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_summary_topologies_topology_mt_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/summary/topologies/topology/metric",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_summary_topologies_topology_metric_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/external/network-mask",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_external_network_mask_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/external/topologies/topology",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_external_topologies_topology_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/external/topologies/topology/mt-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_external_topologies_topology_mt_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/external/topologies/topology/flags",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_external_topologies_topology_flags_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/external/topologies/topology/metric",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_external_topologies_topology_metric_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/external/topologies/topology/forwarding-address",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_external_topologies_topology_forwarding_address_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/external/topologies/topology/external-route-tag",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_external_topologies_topology_external_route_tag_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/ri-opaque/router-capabilities-tlv/router-informational-capabilities/informational-capabilities",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_ri_opaque_router_capabilities_tlv_router_informational_capabilities_informational_capabilities_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_ri_opaque_router_capabilities_tlv_router_informational_capabilities_informational_capabilities_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/pce-address",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_pce_address_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/path-scope/scope-flags",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_path_scope_scope_flags_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/path-scope/pref-l",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_path_scope_pref_l_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/path-scope/pref-r",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_path_scope_pref_r_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/path-scope/pref-s",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_path_scope_pref_s_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/path-scope/pref-y",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_path_scope_pref_y_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/domain/type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_domain_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/domain/id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_domain_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/neighbors/neighbor",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_neighbors_neighbor_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/neighbors/neighbor/type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_neighbors_neighbor_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/neighbors/neighbor/id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_neighbors_neighbor_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/capabilities",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_capabilities_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/ri-opaque/sr-algorithm-tlv/sr-algorithm",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_ri_opaque_sr_algorithm_tlv_sr_algorithm_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_ri_opaque_sr_algorithm_tlv_sr_algorithm_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/ri-opaque/sid-range-tlvs/sid-range-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_ri_opaque_sid_range_tlvs_sid_range_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/ri-opaque/sid-range-tlvs/sid-range-tlv/range-size",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_ri_opaque_sid_range_tlvs_sid_range_tlv_range_size_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/ri-opaque/sid-range-tlvs/sid-range-tlv/sid-sub-tlv/sid",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_ri_opaque_sid_range_tlvs_sid_range_tlv_sid_sub_tlv_sid_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/ri-opaque/local-block-tlvs/local-block-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_ri_opaque_local_block_tlvs_local_block_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/ri-opaque/local-block-tlvs/local-block-tlv/range-size",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_ri_opaque_local_block_tlvs_local_block_tlv_range_size_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/ri-opaque/local-block-tlvs/local-block-tlv/sid-sub-tlv/sid",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_ri_opaque_local_block_tlvs_local_block_tlv_sid_sub_tlv_sid_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/ri-opaque/node-msd-tlvs/node-msd-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_ri_opaque_node_msd_tlvs_node_msd_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/ri-opaque/node-msd-tlvs/node-msd-tlv/type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_ri_opaque_node_msd_tlvs_node_msd_tlv_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/ri-opaque/node-msd-tlvs/node-msd-tlv/value",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_ri_opaque_node_msd_tlvs_node_msd_tlv_value_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/ri-opaque/unknown-tlvs/unknown-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_ri_opaque_unknown_tlvs_unknown_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/ri-opaque/unknown-tlvs/unknown-tlv/type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_ri_opaque_unknown_tlvs_unknown_tlv_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/ri-opaque/unknown-tlvs/unknown-tlv/length",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_ri_opaque_unknown_tlvs_unknown_tlv_length_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/ri-opaque/unknown-tlvs/unknown-tlv/value",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_ri_opaque_unknown_tlvs_unknown_tlv_value_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/te-opaque/router-address-tlv/router-address",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_te_opaque_router_address_tlv_router_address_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/link-type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_link_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/link-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_link_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/local-if-ipv4-addrs/local-if-ipv4-addr",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_local_if_ipv4_addrs_local_if_ipv4_addr_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_local_if_ipv4_addrs_local_if_ipv4_addr_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/remote-if-ipv4-addrs/remote-if-ipv4-addr",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_remote_if_ipv4_addrs_remote_if_ipv4_addr_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_remote_if_ipv4_addrs_remote_if_ipv4_addr_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/te-metric",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_te_metric_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/max-bandwidth",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_max_bandwidth_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/max-reservable-bandwidth",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_max_reservable_bandwidth_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unreserved-bandwidths/unreserved-bandwidth",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unreserved_bandwidths_unreserved_bandwidth_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unreserved-bandwidths/unreserved-bandwidth/priority",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unreserved_bandwidths_unreserved_bandwidth_priority_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unreserved-bandwidths/unreserved-bandwidth/unreserved-bandwidth",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unreserved_bandwidths_unreserved_bandwidth_unreserved_bandwidth_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/admin-group",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_admin_group_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/local-and-remote-te-router-id/local-router-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_local_and_remote_te_router_id_local_router_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/local-and-remote-te-router-id/remote-router-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_local_and_remote_te_router_id_remote_router_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/link-local-remote-id/link-local-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_link_local_remote_id_link_local_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/link-local-remote-id/link-remote-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_link_local_remote_id_link_remote_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/remote-as-number",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_remote_as_number_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/ipv4-remote-asbr-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_ipv4_remote_asbr_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unidirectional-link-delay",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unidirectional_link_delay_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/min-max-unidirectional-link-delay/min-delay",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_min_max_unidirectional_link_delay_min_delay_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/min-max-unidirectional-link-delay/max-delay",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_min_max_unidirectional_link_delay_max_delay_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unidirectional-delay-variation",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unidirectional_delay_variation_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unidirectional-link-loss",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unidirectional_link_loss_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unidirectional-residual-bandwidth",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unidirectional_residual_bandwidth_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unidirectional-available-bandwidth",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unidirectional_available_bandwidth_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unidirectional-utilized-bandwidth",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unidirectional_utilized_bandwidth_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unknown-tlvs/unknown-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unknown_tlvs_unknown_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unknown-tlvs/unknown-tlv/type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unknown_tlvs_unknown_tlv_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unknown-tlvs/unknown-tlv/length",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unknown_tlvs_unknown_tlv_length_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unknown-tlvs/unknown-tlv/value",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unknown_tlvs_unknown_tlv_value_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/grace-lsa-opaque/grace-period-tlv/grace-period",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_grace_lsa_opaque_grace_period_tlv_grace_period_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/grace-lsa-opaque/restart-reason-tlv/restart-reason",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_grace_lsa_opaque_restart_reason_tlv_restart_reason_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/grace-lsa-opaque/if-address-tlv/if-address",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_grace_lsa_opaque_if_address_tlv_if_address_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/route-type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_route_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/flags/extended-prefix-flags",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_flags_extended_prefix_flags_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_flags_extended_prefix_flags_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/prefix",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_prefix_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/prefix-sid-sub-tlvs/prefix-sid-sub-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_prefix_sid_sub_tlvs_prefix_sid_sub_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/prefix-sid-sub-tlvs/prefix-sid-sub-tlv/prefix-sid-flags/bits",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_prefix_sid_sub_tlvs_prefix_sid_sub_tlv_prefix_sid_flags_bits_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_prefix_sid_sub_tlvs_prefix_sid_sub_tlv_prefix_sid_flags_bits_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/prefix-sid-sub-tlvs/prefix-sid-sub-tlv/mt-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_prefix_sid_sub_tlvs_prefix_sid_sub_tlv_mt_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/prefix-sid-sub-tlvs/prefix-sid-sub-tlv/algorithm",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_prefix_sid_sub_tlvs_prefix_sid_sub_tlv_algorithm_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/prefix-sid-sub-tlvs/prefix-sid-sub-tlv/sid",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_prefix_sid_sub_tlvs_prefix_sid_sub_tlv_sid_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/unknown-tlvs/unknown-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_unknown_tlvs_unknown_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/unknown-tlvs/unknown-tlv/type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_unknown_tlvs_unknown_tlv_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/unknown-tlvs/unknown-tlv/length",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_unknown_tlvs_unknown_tlv_length_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/unknown-tlvs/unknown-tlv/value",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_unknown_tlvs_unknown_tlv_value_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/prefix-length",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_prefix_length_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/af",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_af_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/range-size",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_range_size_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/extended-prefix-range-flags/bits",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_extended_prefix_range_flags_bits_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_extended_prefix_range_flags_bits_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/prefix",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_prefix_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/unknown-tlvs/unknown-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_unknown_tlvs_unknown_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/unknown-tlvs/unknown-tlv/type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_unknown_tlvs_unknown_tlv_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/unknown-tlvs/unknown-tlv/length",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_unknown_tlvs_unknown_tlv_length_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/unknown-tlvs/unknown-tlv/value",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_unknown_tlvs_unknown_tlv_value_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/link-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_link_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/link-data",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_link_data_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/maximum-sid-depth-tlv/msd-type",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_maximum_sid_depth_tlv_msd_type_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/maximum-sid-depth-tlv/msd-type/msd-type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_maximum_sid_depth_tlv_msd_type_msd_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/maximum-sid-depth-tlv/msd-type/msd-value",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_maximum_sid_depth_tlv_msd_type_msd_value_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/adj-sid-sub-tlvs/adj-sid-sub-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_adj_sid_sub_tlvs_adj_sid_sub_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/adj-sid-sub-tlvs/adj-sid-sub-tlv/adj-sid-flags/bits",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_adj_sid_sub_tlvs_adj_sid_sub_tlv_adj_sid_flags_bits_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_adj_sid_sub_tlvs_adj_sid_sub_tlv_adj_sid_flags_bits_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/adj-sid-sub-tlvs/adj-sid-sub-tlv/mt-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_adj_sid_sub_tlvs_adj_sid_sub_tlv_mt_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/adj-sid-sub-tlvs/adj-sid-sub-tlv/weight",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_adj_sid_sub_tlvs_adj_sid_sub_tlv_weight_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/adj-sid-sub-tlvs/adj-sid-sub-tlv/sid",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_adj_sid_sub_tlvs_adj_sid_sub_tlv_sid_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/lan-adj-sid-sub-tlvs/lan-adj-sid-sub-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_lan_adj_sid_sub_tlvs_lan_adj_sid_sub_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/lan-adj-sid-sub-tlvs/lan-adj-sid-sub-tlv/lan-adj-sid-flags/bits",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_lan_adj_sid_sub_tlvs_lan_adj_sid_sub_tlv_lan_adj_sid_flags_bits_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_lan_adj_sid_sub_tlvs_lan_adj_sid_sub_tlv_lan_adj_sid_flags_bits_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/lan-adj-sid-sub-tlvs/lan-adj-sid-sub-tlv/mt-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_lan_adj_sid_sub_tlvs_lan_adj_sid_sub_tlv_mt_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/lan-adj-sid-sub-tlvs/lan-adj-sid-sub-tlv/weight",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_lan_adj_sid_sub_tlvs_lan_adj_sid_sub_tlv_weight_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/lan-adj-sid-sub-tlvs/lan-adj-sid-sub-tlv/neighbor-router-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_lan_adj_sid_sub_tlvs_lan_adj_sid_sub_tlv_neighbor_router_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/lan-adj-sid-sub-tlvs/lan-adj-sid-sub-tlv/sid",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_lan_adj_sid_sub_tlvs_lan_adj_sid_sub_tlv_sid_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/remote-if-address",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_remote_if_address_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/unknown-tlvs/unknown-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_unknown_tlvs_unknown_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/unknown-tlvs/unknown-tlv/type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_unknown_tlvs_unknown_tlv_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/unknown-tlvs/unknown-tlv/length",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_unknown_tlvs_unknown_tlv_length_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/state/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/unknown-tlvs/unknown-tlv/value",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_state_database_as_scope_lsa_type_as_scope_lsas_as_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_unknown_tlvs_unknown_tlv_value_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_destroy,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_get_next,
				.get_keys = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_get_keys,
				.lookup_entry = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_lookup_entry,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/area-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_area_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/authentication",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_authentication_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_authentication_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/authentication/type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_authentication_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/summary",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_summary_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_summary_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/default-cost",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_default_cost_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_default_cost_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/nssa/translate",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_translate_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/nssa/suppress-fa",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_suppress_fa_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/export-list",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_export_list_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_export_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/import-list",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_import_list_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_import_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/filter-list/in/prefix",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_filter_list_in_prefix_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_filter_list_in_prefix_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/filter-list/out/prefix",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_filter_list_out_prefix_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_filter_list_out_prefix_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/ranges/range",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_ranges_range_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_ranges_range_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/ranges/range/advertise",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_ranges_range_advertise_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/ranges/range/cost",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_ranges_range_cost_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_ranges_range_cost_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/ranges/range/substitute",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_ranges_range_substitute_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_ranges_range_substitute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/shortcut/configuration",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_shortcut_configuration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/threads/stub-router",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_threads_stub_router_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/threads/stub-router/timer",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_threads_stub_router_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/threads/opaque-lsa-self",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_threads_opaque_lsa_self_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/threads/opaque-lsa-self/timer",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_threads_opaque_lsa_self_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/statistics/spf-runs-count",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_statistics_spf_runs_count_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/statistics/abr-count",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_statistics_abr_count_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/statistics/asbr-count",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_statistics_asbr_count_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/statistics/spf-timestamp",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_statistics_spf_timestamp_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/statistics/active-interfaces",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_statistics_active_interfaces_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/statistics/full-nbrs",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_statistics_full_nbrs_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/statistics/full-virtual",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_statistics_full_virtual_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_get_next,
				.get_keys = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_get_keys,
				.lookup_entry = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_lookup_entry,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/lsa-type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_lsa_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_get_next,
				.get_keys = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_get_keys,
				.lookup_entry = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_lookup_entry,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/lsa-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_lsa_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/adv-router",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_adv_router_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/decode-completed",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_decode_completed_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/raw-data",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_raw_data_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/header/lsa-options/lsa-option",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_header_lsa_options_lsa_option_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_header_lsa_options_lsa_option_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/header/lsa-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_header_lsa_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/header/opaque-type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_header_opaque_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/header/opaque-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_header_opaque_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/header/age",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_header_age_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/header/type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_header_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/header/adv-router",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_header_adv_router_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/header/seq-num",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_header_seq_num_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/header/checksum",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_header_checksum_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/header/length",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_header_length_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/router/router-bits/rtr-lsa-bits",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_router_router_bits_rtr_lsa_bits_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_router_router_bits_rtr_lsa_bits_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/router/num-of-links",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_router_num_of_links_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/router/links/link",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_router_links_link_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/router/links/link/link-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_router_links_link_link_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/router/links/link/link-data",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_router_links_link_link_data_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/router/links/link/type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_router_links_link_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/router/links/link/topologies/topology",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_router_links_link_topologies_topology_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/router/links/link/topologies/topology/mt-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_router_links_link_topologies_topology_mt_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/router/links/link/topologies/topology/metric",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_router_links_link_topologies_topology_metric_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/network/network-mask",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_network_network_mask_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/network/attached-routers/attached-router",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_network_attached_routers_attached_router_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_network_attached_routers_attached_router_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/summary/network-mask",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_summary_network_mask_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/summary/topologies/topology",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_summary_topologies_topology_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/summary/topologies/topology/mt-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_summary_topologies_topology_mt_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/summary/topologies/topology/metric",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_summary_topologies_topology_metric_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/external/network-mask",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_external_network_mask_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/external/topologies/topology",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_external_topologies_topology_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/external/topologies/topology/mt-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_external_topologies_topology_mt_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/external/topologies/topology/flags",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_external_topologies_topology_flags_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/external/topologies/topology/metric",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_external_topologies_topology_metric_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/external/topologies/topology/forwarding-address",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_external_topologies_topology_forwarding_address_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/external/topologies/topology/external-route-tag",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_external_topologies_topology_external_route_tag_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/ri-opaque/router-capabilities-tlv/router-informational-capabilities/informational-capabilities",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_ri_opaque_router_capabilities_tlv_router_informational_capabilities_informational_capabilities_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_ri_opaque_router_capabilities_tlv_router_informational_capabilities_informational_capabilities_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/pce-address",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_pce_address_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/path-scope/scope-flags",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_path_scope_scope_flags_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/path-scope/pref-l",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_path_scope_pref_l_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/path-scope/pref-r",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_path_scope_pref_r_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/path-scope/pref-s",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_path_scope_pref_s_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/path-scope/pref-y",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_path_scope_pref_y_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/domain/type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_domain_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/domain/id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_domain_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/neighbors/neighbor",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_neighbors_neighbor_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/neighbors/neighbor/type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_neighbors_neighbor_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/neighbors/neighbor/id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_neighbors_neighbor_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/capabilities",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_capabilities_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/ri-opaque/sr-algorithm-tlv/sr-algorithm",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_ri_opaque_sr_algorithm_tlv_sr_algorithm_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_ri_opaque_sr_algorithm_tlv_sr_algorithm_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/ri-opaque/sid-range-tlvs/sid-range-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_ri_opaque_sid_range_tlvs_sid_range_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/ri-opaque/sid-range-tlvs/sid-range-tlv/range-size",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_ri_opaque_sid_range_tlvs_sid_range_tlv_range_size_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/ri-opaque/sid-range-tlvs/sid-range-tlv/sid-sub-tlv/sid",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_ri_opaque_sid_range_tlvs_sid_range_tlv_sid_sub_tlv_sid_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/ri-opaque/local-block-tlvs/local-block-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_ri_opaque_local_block_tlvs_local_block_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/ri-opaque/local-block-tlvs/local-block-tlv/range-size",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_ri_opaque_local_block_tlvs_local_block_tlv_range_size_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/ri-opaque/local-block-tlvs/local-block-tlv/sid-sub-tlv/sid",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_ri_opaque_local_block_tlvs_local_block_tlv_sid_sub_tlv_sid_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/ri-opaque/node-msd-tlvs/node-msd-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_ri_opaque_node_msd_tlvs_node_msd_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/ri-opaque/node-msd-tlvs/node-msd-tlv/type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_ri_opaque_node_msd_tlvs_node_msd_tlv_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/ri-opaque/node-msd-tlvs/node-msd-tlv/value",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_ri_opaque_node_msd_tlvs_node_msd_tlv_value_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/ri-opaque/unknown-tlvs/unknown-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_ri_opaque_unknown_tlvs_unknown_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/ri-opaque/unknown-tlvs/unknown-tlv/type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_ri_opaque_unknown_tlvs_unknown_tlv_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/ri-opaque/unknown-tlvs/unknown-tlv/length",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_ri_opaque_unknown_tlvs_unknown_tlv_length_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/ri-opaque/unknown-tlvs/unknown-tlv/value",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_ri_opaque_unknown_tlvs_unknown_tlv_value_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/te-opaque/router-address-tlv/router-address",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_te_opaque_router_address_tlv_router_address_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/link-type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_link_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/link-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_link_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/local-if-ipv4-addrs/local-if-ipv4-addr",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_local_if_ipv4_addrs_local_if_ipv4_addr_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_local_if_ipv4_addrs_local_if_ipv4_addr_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/remote-if-ipv4-addrs/remote-if-ipv4-addr",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_remote_if_ipv4_addrs_remote_if_ipv4_addr_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_remote_if_ipv4_addrs_remote_if_ipv4_addr_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/te-metric",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_te_metric_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/max-bandwidth",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_max_bandwidth_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/max-reservable-bandwidth",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_max_reservable_bandwidth_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unreserved-bandwidths/unreserved-bandwidth",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unreserved_bandwidths_unreserved_bandwidth_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unreserved-bandwidths/unreserved-bandwidth/priority",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unreserved_bandwidths_unreserved_bandwidth_priority_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unreserved-bandwidths/unreserved-bandwidth/unreserved-bandwidth",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unreserved_bandwidths_unreserved_bandwidth_unreserved_bandwidth_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/admin-group",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_admin_group_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/local-and-remote-te-router-id/local-router-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_local_and_remote_te_router_id_local_router_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/local-and-remote-te-router-id/remote-router-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_local_and_remote_te_router_id_remote_router_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/link-local-remote-id/link-local-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_link_local_remote_id_link_local_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/link-local-remote-id/link-remote-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_link_local_remote_id_link_remote_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/remote-as-number",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_remote_as_number_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/ipv4-remote-asbr-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_ipv4_remote_asbr_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unidirectional-link-delay",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unidirectional_link_delay_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/min-max-unidirectional-link-delay/min-delay",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_min_max_unidirectional_link_delay_min_delay_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/min-max-unidirectional-link-delay/max-delay",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_min_max_unidirectional_link_delay_max_delay_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unidirectional-delay-variation",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unidirectional_delay_variation_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unidirectional-link-loss",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unidirectional_link_loss_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unidirectional-residual-bandwidth",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unidirectional_residual_bandwidth_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unidirectional-available-bandwidth",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unidirectional_available_bandwidth_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unidirectional-utilized-bandwidth",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unidirectional_utilized_bandwidth_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unknown-tlvs/unknown-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unknown_tlvs_unknown_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unknown-tlvs/unknown-tlv/type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unknown_tlvs_unknown_tlv_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unknown-tlvs/unknown-tlv/length",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unknown_tlvs_unknown_tlv_length_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unknown-tlvs/unknown-tlv/value",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unknown_tlvs_unknown_tlv_value_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/grace-lsa-opaque/grace-period-tlv/grace-period",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_grace_lsa_opaque_grace_period_tlv_grace_period_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/grace-lsa-opaque/restart-reason-tlv/restart-reason",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_grace_lsa_opaque_restart_reason_tlv_restart_reason_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/grace-lsa-opaque/if-address-tlv/if-address",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_grace_lsa_opaque_if_address_tlv_if_address_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/route-type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_route_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/flags/extended-prefix-flags",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_flags_extended_prefix_flags_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_flags_extended_prefix_flags_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/prefix",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_prefix_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/prefix-sid-sub-tlvs/prefix-sid-sub-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_prefix_sid_sub_tlvs_prefix_sid_sub_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/prefix-sid-sub-tlvs/prefix-sid-sub-tlv/prefix-sid-flags/bits",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_prefix_sid_sub_tlvs_prefix_sid_sub_tlv_prefix_sid_flags_bits_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_prefix_sid_sub_tlvs_prefix_sid_sub_tlv_prefix_sid_flags_bits_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/prefix-sid-sub-tlvs/prefix-sid-sub-tlv/mt-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_prefix_sid_sub_tlvs_prefix_sid_sub_tlv_mt_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/prefix-sid-sub-tlvs/prefix-sid-sub-tlv/algorithm",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_prefix_sid_sub_tlvs_prefix_sid_sub_tlv_algorithm_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/prefix-sid-sub-tlvs/prefix-sid-sub-tlv/sid",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_prefix_sid_sub_tlvs_prefix_sid_sub_tlv_sid_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/unknown-tlvs/unknown-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_unknown_tlvs_unknown_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/unknown-tlvs/unknown-tlv/type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_unknown_tlvs_unknown_tlv_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/unknown-tlvs/unknown-tlv/length",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_unknown_tlvs_unknown_tlv_length_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/unknown-tlvs/unknown-tlv/value",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_unknown_tlvs_unknown_tlv_value_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/prefix-length",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_prefix_length_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/af",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_af_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/range-size",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_range_size_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/extended-prefix-range-flags/bits",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_extended_prefix_range_flags_bits_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_extended_prefix_range_flags_bits_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/prefix",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_prefix_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/unknown-tlvs/unknown-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_unknown_tlvs_unknown_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/unknown-tlvs/unknown-tlv/type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_unknown_tlvs_unknown_tlv_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/unknown-tlvs/unknown-tlv/length",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_unknown_tlvs_unknown_tlv_length_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/unknown-tlvs/unknown-tlv/value",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_unknown_tlvs_unknown_tlv_value_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/link-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_link_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/link-data",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_link_data_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/maximum-sid-depth-tlv/msd-type",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_maximum_sid_depth_tlv_msd_type_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/maximum-sid-depth-tlv/msd-type/msd-type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_maximum_sid_depth_tlv_msd_type_msd_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/maximum-sid-depth-tlv/msd-type/msd-value",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_maximum_sid_depth_tlv_msd_type_msd_value_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/adj-sid-sub-tlvs/adj-sid-sub-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_adj_sid_sub_tlvs_adj_sid_sub_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/adj-sid-sub-tlvs/adj-sid-sub-tlv/adj-sid-flags/bits",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_adj_sid_sub_tlvs_adj_sid_sub_tlv_adj_sid_flags_bits_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_adj_sid_sub_tlvs_adj_sid_sub_tlv_adj_sid_flags_bits_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/adj-sid-sub-tlvs/adj-sid-sub-tlv/mt-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_adj_sid_sub_tlvs_adj_sid_sub_tlv_mt_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/adj-sid-sub-tlvs/adj-sid-sub-tlv/weight",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_adj_sid_sub_tlvs_adj_sid_sub_tlv_weight_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/adj-sid-sub-tlvs/adj-sid-sub-tlv/sid",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_adj_sid_sub_tlvs_adj_sid_sub_tlv_sid_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/lan-adj-sid-sub-tlvs/lan-adj-sid-sub-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_lan_adj_sid_sub_tlvs_lan_adj_sid_sub_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/lan-adj-sid-sub-tlvs/lan-adj-sid-sub-tlv/lan-adj-sid-flags/bits",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_lan_adj_sid_sub_tlvs_lan_adj_sid_sub_tlv_lan_adj_sid_flags_bits_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_lan_adj_sid_sub_tlvs_lan_adj_sid_sub_tlv_lan_adj_sid_flags_bits_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/lan-adj-sid-sub-tlvs/lan-adj-sid-sub-tlv/mt-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_lan_adj_sid_sub_tlvs_lan_adj_sid_sub_tlv_mt_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/lan-adj-sid-sub-tlvs/lan-adj-sid-sub-tlv/weight",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_lan_adj_sid_sub_tlvs_lan_adj_sid_sub_tlv_weight_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/lan-adj-sid-sub-tlvs/lan-adj-sid-sub-tlv/neighbor-router-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_lan_adj_sid_sub_tlvs_lan_adj_sid_sub_tlv_neighbor_router_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/lan-adj-sid-sub-tlvs/lan-adj-sid-sub-tlv/sid",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_lan_adj_sid_sub_tlvs_lan_adj_sid_sub_tlv_sid_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/remote-if-address",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_remote_if_address_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/unknown-tlvs/unknown-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_unknown_tlvs_unknown_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/unknown-tlvs/unknown-tlv/type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_unknown_tlvs_unknown_tlv_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/unknown-tlvs/unknown-tlv/length",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_unknown_tlvs_unknown_tlv_length_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/state/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/unknown-tlvs/unknown-tlv/value",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_state_database_area_scope_lsa_type_area_scope_lsas_area_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_unknown_tlvs_unknown_tlv_value_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_destroy,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_get_next,
				.get_keys = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_get_keys,
				.lookup_entry = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_lookup_entry,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/dead-interval",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_dead_interval_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/hello-interval",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_hello_interval_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/retransmit-interval",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_retransmit_interval_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/transmit-delay",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_transmit_delay_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/authentication/type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_authentication_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/authentication/simple-key",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_authentication_simple_key_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_authentication_simple_key_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/authentication/mds-keys/mds-key",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_authentication_mds_keys_mds_key_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_authentication_mds_keys_mds_key_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/state",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_state_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/hello-timer",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_hello_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/wait-timer",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_wait_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/dr-router-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_dr_router_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/dr-ip-addr",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_dr_ip_addr_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/bdr-router-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_bdr_router_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/bdr-ip-addr",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_bdr_ip_addr_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/network-lsa-seqno",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_network_lsa_seqno_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/multicast-groups/ospf-all-routers",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_multicast_groups_ospf_all_routers_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/multicast-groups/ospf-designated-routers",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_multicast_groups_ospf_designated_routers_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/threads/ls-ack",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_threads_ls_ack_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/threads/ls-ack/timer",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_threads_ls_ack_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/threads/ls-ack-direct",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_threads_ls_ack_direct_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/threads/ls-upd-event",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_threads_ls_upd_event_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/threads/opaque-lsa-self",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_threads_opaque_lsa_self_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/threads/opaque-lsa-self/timer",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_threads_opaque_lsa_self_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/statistics/if-event-count",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_statistics_if_event_count_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/statistics/hello-in",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_statistics_hello_in_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/statistics/hello-out",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_statistics_hello_out_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/statistics/db-desc-in",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_statistics_db_desc_in_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/statistics/db-desc-out",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_statistics_db_desc_out_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/statistics/ls-req-in",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_statistics_ls_req_in_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/statistics/ls-req-out",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_statistics_ls_req_out_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/statistics/ls-upd-in",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_statistics_ls_upd_in_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/statistics/ls-upd-out",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_statistics_ls_upd_out_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/statistics/ls-ack-in",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_statistics_ls_ack_in_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/statistics/ls-ack-out",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_statistics_ls_ack_out_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/statistics/discarded",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_statistics_discarded_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/statistics/nbrs",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_statistics_nbrs_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/statistics/full-nbrs",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_statistics_full_nbrs_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/neighbors/neighbor",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_neighbors_neighbor_get_next,
				.get_keys = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_neighbors_neighbor_get_keys,
				.lookup_entry = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_neighbors_neighbor_lookup_entry,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/neighbors/neighbor/neighbor-router-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_neighbors_neighbor_neighbor_router_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/neighbors/neighbor/address",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_neighbors_neighbor_address_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/neighbors/neighbor/dr-router-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_neighbors_neighbor_dr_router_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/neighbors/neighbor/dr-ip-addr",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_neighbors_neighbor_dr_ip_addr_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/neighbors/neighbor/bdr-router-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_neighbors_neighbor_bdr_router_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/neighbors/neighbor/bdr-ip-addr",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_neighbors_neighbor_bdr_ip_addr_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/neighbors/neighbor/state",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_neighbors_neighbor_state_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/neighbors/neighbor/dead-timer",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_neighbors_neighbor_dead_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/neighbors/neighbor/statistics/nbr-retrans-qlen",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_neighbors_neighbor_statistics_nbr_retrans_qlen_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/neighbors/neighbor/statistics/nbr-request-qlen",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_neighbors_neighbor_statistics_nbr_request_qlen_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/neighbors/neighbor/statistics/nbr-summary-len",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_neighbors_neighbor_statistics_nbr_summary_len_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/neighbors/neighbor/statistics/nbr-uptime",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_neighbors_neighbor_statistics_nbr_uptime_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/neighbors/neighbor/statistics/nbr-downtime",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_neighbors_neighbor_statistics_nbr_downtime_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/neighbors/neighbor/statistics/nsm/state-changes",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_neighbors_neighbor_statistics_nsm_state_changes_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/neighbors/neighbor/statistics/nsm/last-progressive",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_neighbors_neighbor_statistics_nsm_last_progressive_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/neighbors/neighbor/statistics/nsm/last-regressive",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_neighbors_neighbor_statistics_nsm_last_regressive_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/neighbors/neighbor/threads/db-desc-retransmission",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_neighbors_neighbor_threads_db_desc_retransmission_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/neighbors/neighbor/threads/db-desc-retransmission/timer",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_neighbors_neighbor_threads_db_desc_retransmission_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/neighbors/neighbor/threads/ls-request-retransmission",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_neighbors_neighbor_threads_ls_request_retransmission_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/neighbors/neighbor/threads/ls-request-retransmission/timer",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_neighbors_neighbor_threads_ls_request_retransmission_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/neighbors/neighbor/threads/ls-update-retransmission",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_neighbors_neighbor_threads_ls_update_retransmission_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/neighbors/neighbor/threads/ls-update-retransmission/timer",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_neighbors_neighbor_threads_ls_update_retransmission_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/neighbors/neighbor/threads/hello-reply",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_neighbors_neighbor_threads_hello_reply_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/neighbors/neighbor/threads/hello-reply/timer",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_neighbors_neighbor_threads_hello_reply_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/neighbors/neighbor/graceful-restart-helper/grace-period",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_neighbors_neighbor_graceful_restart_helper_grace_period_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/neighbors/neighbor/graceful-restart-helper/restart-reason",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_neighbors_neighbor_graceful_restart_helper_restart_reason_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/neighbors/neighbor/graceful-restart-helper/helper-status",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_neighbors_neighbor_graceful_restart_helper_helper_status_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/neighbors/neighbor/graceful-restart-helper/helper-exit-reason",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_neighbors_neighbor_graceful_restart_helper_helper_exit_reason_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/neighbors/neighbor/graceful-restart-helper/helper-rejected-reason",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_neighbors_neighbor_graceful_restart_helper_helper_rejected_reason_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_get_next,
				.get_keys = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_get_keys,
				.lookup_entry = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_lookup_entry,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/lsa-type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_lsa_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_get_next,
				.get_keys = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_get_keys,
				.lookup_entry = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_lookup_entry,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/lsa-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_lsa_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/adv-router",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_adv_router_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/decode-completed",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_decode_completed_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/raw-data",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_raw_data_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/header/lsa-options/lsa-option",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_header_lsa_options_lsa_option_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_header_lsa_options_lsa_option_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/header/lsa-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_header_lsa_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/header/opaque-type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_header_opaque_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/header/opaque-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_header_opaque_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/header/age",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_header_age_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/header/type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_header_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/header/adv-router",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_header_adv_router_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/header/seq-num",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_header_seq_num_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/header/checksum",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_header_checksum_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/header/length",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_header_length_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/router/router-bits/rtr-lsa-bits",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_router_router_bits_rtr_lsa_bits_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_router_router_bits_rtr_lsa_bits_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/router/num-of-links",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_router_num_of_links_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/router/links/link",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_router_links_link_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/router/links/link/link-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_router_links_link_link_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/router/links/link/link-data",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_router_links_link_link_data_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/router/links/link/type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_router_links_link_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/router/links/link/topologies/topology",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_router_links_link_topologies_topology_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/router/links/link/topologies/topology/mt-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_router_links_link_topologies_topology_mt_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/router/links/link/topologies/topology/metric",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_router_links_link_topologies_topology_metric_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/network/network-mask",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_network_network_mask_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/network/attached-routers/attached-router",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_network_attached_routers_attached_router_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_network_attached_routers_attached_router_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/summary/network-mask",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_summary_network_mask_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/summary/topologies/topology",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_summary_topologies_topology_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/summary/topologies/topology/mt-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_summary_topologies_topology_mt_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/summary/topologies/topology/metric",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_summary_topologies_topology_metric_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/external/network-mask",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_external_network_mask_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/external/topologies/topology",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_external_topologies_topology_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/external/topologies/topology/mt-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_external_topologies_topology_mt_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/external/topologies/topology/flags",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_external_topologies_topology_flags_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/external/topologies/topology/metric",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_external_topologies_topology_metric_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/external/topologies/topology/forwarding-address",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_external_topologies_topology_forwarding_address_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/external/topologies/topology/external-route-tag",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_external_topologies_topology_external_route_tag_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/router-capabilities-tlv/router-informational-capabilities/informational-capabilities",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_router_capabilities_tlv_router_informational_capabilities_informational_capabilities_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_router_capabilities_tlv_router_informational_capabilities_informational_capabilities_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/pce-address",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_pce_address_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/path-scope/scope-flags",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_path_scope_scope_flags_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/path-scope/pref-l",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_path_scope_pref_l_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/path-scope/pref-r",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_path_scope_pref_r_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/path-scope/pref-s",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_path_scope_pref_s_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/path-scope/pref-y",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_path_scope_pref_y_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/domain/type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_domain_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/domain/id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_domain_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/neighbors/neighbor",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_neighbors_neighbor_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/neighbors/neighbor/type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_neighbors_neighbor_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/neighbors/neighbor/id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_neighbors_neighbor_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/pced-tlv/capabilities",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_pced_tlv_capabilities_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/sr-algorithm-tlv/sr-algorithm",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_sr_algorithm_tlv_sr_algorithm_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_sr_algorithm_tlv_sr_algorithm_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/sid-range-tlvs/sid-range-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_sid_range_tlvs_sid_range_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/sid-range-tlvs/sid-range-tlv/range-size",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_sid_range_tlvs_sid_range_tlv_range_size_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/sid-range-tlvs/sid-range-tlv/sid-sub-tlv/sid",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_sid_range_tlvs_sid_range_tlv_sid_sub_tlv_sid_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/local-block-tlvs/local-block-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_local_block_tlvs_local_block_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/local-block-tlvs/local-block-tlv/range-size",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_local_block_tlvs_local_block_tlv_range_size_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/local-block-tlvs/local-block-tlv/sid-sub-tlv/sid",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_local_block_tlvs_local_block_tlv_sid_sub_tlv_sid_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/node-msd-tlvs/node-msd-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_node_msd_tlvs_node_msd_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/node-msd-tlvs/node-msd-tlv/type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_node_msd_tlvs_node_msd_tlv_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/node-msd-tlvs/node-msd-tlv/value",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_node_msd_tlvs_node_msd_tlv_value_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/unknown-tlvs/unknown-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_unknown_tlvs_unknown_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/unknown-tlvs/unknown-tlv/type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_unknown_tlvs_unknown_tlv_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/unknown-tlvs/unknown-tlv/length",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_unknown_tlvs_unknown_tlv_length_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/ri-opaque/unknown-tlvs/unknown-tlv/value",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_ri_opaque_unknown_tlvs_unknown_tlv_value_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/router-address-tlv/router-address",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_router_address_tlv_router_address_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/link-type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_link_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/link-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_link_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/local-if-ipv4-addrs/local-if-ipv4-addr",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_local_if_ipv4_addrs_local_if_ipv4_addr_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_local_if_ipv4_addrs_local_if_ipv4_addr_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/remote-if-ipv4-addrs/remote-if-ipv4-addr",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_remote_if_ipv4_addrs_remote_if_ipv4_addr_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_remote_if_ipv4_addrs_remote_if_ipv4_addr_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/te-metric",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_te_metric_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/max-bandwidth",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_max_bandwidth_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/max-reservable-bandwidth",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_max_reservable_bandwidth_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unreserved-bandwidths/unreserved-bandwidth",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unreserved_bandwidths_unreserved_bandwidth_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unreserved-bandwidths/unreserved-bandwidth/priority",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unreserved_bandwidths_unreserved_bandwidth_priority_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unreserved-bandwidths/unreserved-bandwidth/unreserved-bandwidth",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unreserved_bandwidths_unreserved_bandwidth_unreserved_bandwidth_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/admin-group",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_admin_group_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/local-and-remote-te-router-id/local-router-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_local_and_remote_te_router_id_local_router_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/local-and-remote-te-router-id/remote-router-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_local_and_remote_te_router_id_remote_router_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/link-local-remote-id/link-local-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_link_local_remote_id_link_local_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/link-local-remote-id/link-remote-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_link_local_remote_id_link_remote_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/remote-as-number",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_remote_as_number_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/ipv4-remote-asbr-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_ipv4_remote_asbr_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unidirectional-link-delay",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unidirectional_link_delay_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/min-max-unidirectional-link-delay/min-delay",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_min_max_unidirectional_link_delay_min_delay_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/min-max-unidirectional-link-delay/max-delay",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_min_max_unidirectional_link_delay_max_delay_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unidirectional-delay-variation",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unidirectional_delay_variation_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unidirectional-link-loss",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unidirectional_link_loss_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unidirectional-residual-bandwidth",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unidirectional_residual_bandwidth_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unidirectional-available-bandwidth",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unidirectional_available_bandwidth_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unidirectional-utilized-bandwidth",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unidirectional_utilized_bandwidth_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unknown-tlvs/unknown-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unknown_tlvs_unknown_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unknown-tlvs/unknown-tlv/type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unknown_tlvs_unknown_tlv_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unknown-tlvs/unknown-tlv/length",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unknown_tlvs_unknown_tlv_length_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/te-opaque/link-tlv/unknown-tlvs/unknown-tlv/value",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_te_opaque_link_tlv_unknown_tlvs_unknown_tlv_value_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/grace-lsa-opaque/grace-period-tlv/grace-period",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_grace_lsa_opaque_grace_period_tlv_grace_period_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/grace-lsa-opaque/restart-reason-tlv/restart-reason",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_grace_lsa_opaque_restart_reason_tlv_restart_reason_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/grace-lsa-opaque/if-address-tlv/if-address",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_grace_lsa_opaque_if_address_tlv_if_address_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/route-type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_route_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/flags/extended-prefix-flags",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_flags_extended_prefix_flags_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_flags_extended_prefix_flags_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/prefix",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_prefix_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/prefix-sid-sub-tlvs/prefix-sid-sub-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_prefix_sid_sub_tlvs_prefix_sid_sub_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/prefix-sid-sub-tlvs/prefix-sid-sub-tlv/prefix-sid-flags/bits",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_prefix_sid_sub_tlvs_prefix_sid_sub_tlv_prefix_sid_flags_bits_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_prefix_sid_sub_tlvs_prefix_sid_sub_tlv_prefix_sid_flags_bits_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/prefix-sid-sub-tlvs/prefix-sid-sub-tlv/mt-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_prefix_sid_sub_tlvs_prefix_sid_sub_tlv_mt_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/prefix-sid-sub-tlvs/prefix-sid-sub-tlv/algorithm",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_prefix_sid_sub_tlvs_prefix_sid_sub_tlv_algorithm_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/prefix-sid-sub-tlvs/prefix-sid-sub-tlv/sid",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_prefix_sid_sub_tlvs_prefix_sid_sub_tlv_sid_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/unknown-tlvs/unknown-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_unknown_tlvs_unknown_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/unknown-tlvs/unknown-tlv/type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_unknown_tlvs_unknown_tlv_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/unknown-tlvs/unknown-tlv/length",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_unknown_tlvs_unknown_tlv_length_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/unknown-tlvs/unknown-tlv/value",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_tlv_unknown_tlvs_unknown_tlv_value_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/prefix-length",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_prefix_length_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/af",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_af_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/range-size",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_range_size_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/extended-prefix-range-flags/bits",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_extended_prefix_range_flags_bits_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_extended_prefix_range_flags_bits_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/prefix",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_prefix_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/unknown-tlvs/unknown-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_unknown_tlvs_unknown_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/unknown-tlvs/unknown-tlv/type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_unknown_tlvs_unknown_tlv_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/unknown-tlvs/unknown-tlv/length",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_unknown_tlvs_unknown_tlv_length_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-range-tlvs/extended-prefix-range-tlv/unknown-tlvs/unknown-tlv/value",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_prefix_opaque_extended_prefix_range_tlvs_extended_prefix_range_tlv_unknown_tlvs_unknown_tlv_value_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/link-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_link_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/link-data",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_link_data_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/maximum-sid-depth-tlv/msd-type",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_maximum_sid_depth_tlv_msd_type_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/maximum-sid-depth-tlv/msd-type/msd-type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_maximum_sid_depth_tlv_msd_type_msd_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/maximum-sid-depth-tlv/msd-type/msd-value",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_maximum_sid_depth_tlv_msd_type_msd_value_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/adj-sid-sub-tlvs/adj-sid-sub-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_adj_sid_sub_tlvs_adj_sid_sub_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/adj-sid-sub-tlvs/adj-sid-sub-tlv/adj-sid-flags/bits",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_adj_sid_sub_tlvs_adj_sid_sub_tlv_adj_sid_flags_bits_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_adj_sid_sub_tlvs_adj_sid_sub_tlv_adj_sid_flags_bits_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/adj-sid-sub-tlvs/adj-sid-sub-tlv/mt-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_adj_sid_sub_tlvs_adj_sid_sub_tlv_mt_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/adj-sid-sub-tlvs/adj-sid-sub-tlv/weight",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_adj_sid_sub_tlvs_adj_sid_sub_tlv_weight_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/adj-sid-sub-tlvs/adj-sid-sub-tlv/sid",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_adj_sid_sub_tlvs_adj_sid_sub_tlv_sid_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/lan-adj-sid-sub-tlvs/lan-adj-sid-sub-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_lan_adj_sid_sub_tlvs_lan_adj_sid_sub_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/lan-adj-sid-sub-tlvs/lan-adj-sid-sub-tlv/lan-adj-sid-flags/bits",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_lan_adj_sid_sub_tlvs_lan_adj_sid_sub_tlv_lan_adj_sid_flags_bits_get_elem,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_lan_adj_sid_sub_tlvs_lan_adj_sid_sub_tlv_lan_adj_sid_flags_bits_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/lan-adj-sid-sub-tlvs/lan-adj-sid-sub-tlv/mt-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_lan_adj_sid_sub_tlvs_lan_adj_sid_sub_tlv_mt_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/lan-adj-sid-sub-tlvs/lan-adj-sid-sub-tlv/weight",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_lan_adj_sid_sub_tlvs_lan_adj_sid_sub_tlv_weight_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/lan-adj-sid-sub-tlvs/lan-adj-sid-sub-tlv/neighbor-router-id",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_lan_adj_sid_sub_tlvs_lan_adj_sid_sub_tlv_neighbor_router_id_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/lan-adj-sid-sub-tlvs/lan-adj-sid-sub-tlv/sid",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_lan_adj_sid_sub_tlvs_lan_adj_sid_sub_tlv_sid_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/remote-if-address",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_remote_if_address_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/unknown-tlvs/unknown-tlv",
			.cbs = {
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_unknown_tlvs_unknown_tlv_get_next,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/unknown-tlvs/unknown-tlv/type",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_unknown_tlvs_unknown_tlv_type_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/unknown-tlvs/unknown-tlv/length",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_unknown_tlvs_unknown_tlv_length_get_elem,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/state/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/unknown-tlvs/unknown-tlv/value",
			.cbs = {
				.get_elem = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_state_database_link_scope_lsa_type_link_scope_lsas_link_scope_lsa_ospfv2_body_opaque_extended_link_opaque_extended_link_tlv_unknown_tlvs_unknown_tlv_value_get_elem,
			}
		},
		{
			.xpath = "/frr-ospfd:clear-ospf-interface",
			.cbs = {
				.rpc = clear_ospf_interface_rpc,
			}
		},
		{
			.xpath = "/frr-ospfd:clear-ospf-neighbor",
			.cbs = {
				.rpc = clear_ospf_neighbor_rpc,
			}
		},
		{
			.xpath = "/frr-ospfd:clear-ospf-process",
			.cbs = {
				.rpc = clear_ospf_process_rpc,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
