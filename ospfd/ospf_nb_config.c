#include <zebra.h>

#include "northbound.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_nb.h"
#include "ospfd/ospf_dump.h"

/*
 * frr-routing router configurable state
 */

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_create(struct nb_cb_create_args *args)
{
	struct ospf *ospf;
	unsigned short instance;
	const char *vrf_name;
	bool created = false;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vrf_name = yang_dnode_get_string(args->dnode, "./../vrf");
	instance = yang_dnode_get_uint8(args->dnode, "./../name");

	ospf = ospf_get(instance, vrf_name, &created);

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug(
			   "Config command 'router ospf %d' received, vrf %s id %u oi_running %u",
			   ospf->instance, ospf_get_name(ospf), ospf->vrf_id,
			   ospf->oi_running);

	nb_running_set_entry(args->dnode, ospf);

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_ospf_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf = nb_running_unset_entry(args->dnode);

	ospf_finish(ospf);

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/use-arp
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_use_arp_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/explicit-router-id
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_explicit_router_id_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	struct listnode *node;
	struct ospf_area *area;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf = nb_running_get_entry(args->dnode, NULL, true);

        yang_dnode_get_ipv4(&ospf->router_id_static, args->dnode, NULL);

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area))
		if (area->full_nbrs) {
			zlog_warn("For this router-id change to take effect, use \"clear ip ospf process\" command\n");
			return NB_OK;
		}

	ospf_router_id_update(ospf);

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_ospf_explicit_router_id_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;
	struct listnode *node;
	struct ospf_area *area;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf = nb_running_get_entry(args->dnode, NULL, true);

	ospf->router_id_static.s_addr = 0;

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area))
		if (area->full_nbrs) {
			zlog_warn("For this router-id change to take effect, use \"clear ip ospf process\" command\n");
			return NB_OK;
		}

	ospf_router_id_update(ospf);

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/capability-opaque
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_capability_opaque_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/compatible-rfc1583
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_compatible_rfc1583_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf = nb_running_get_entry(args->dnode, NULL, true);

	if (yang_dnode_get_bool(args->dnode, NULL)) {
		if (!CHECK_FLAG(ospf->config, OSPF_RFC1583_COMPATIBLE)) {
			SET_FLAG(ospf->config, OSPF_RFC1583_COMPATIBLE);
			ospf_spf_calculate_schedule(ospf, SPF_FLAG_CONFIG_CHANGE);
		}
	} else {
		if (CHECK_FLAG(ospf->config, OSPF_RFC1583_COMPATIBLE)) {
			UNSET_FLAG(ospf->config, OSPF_RFC1583_COMPATIBLE);
			ospf_spf_calculate_schedule(ospf, SPF_FLAG_CONFIG_CHANGE);
		}
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/log-adjacency-changes
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_log_adjacency_changes_create(struct nb_cb_create_args *args)
{
	struct ospf *ospf;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf = nb_running_get_entry(args->dnode, NULL, true);

	SET_FLAG(ospf->config, OSPF_LOG_ADJACENCY_CHANGES);

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_ospf_log_adjacency_changes_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf = nb_running_get_entry(args->dnode, NULL, true);

	UNSET_FLAG(ospf->config, OSPF_LOG_ADJACENCY_CHANGES);
	UNSET_FLAG(ospf->config, OSPF_LOG_ADJACENCY_DETAIL);

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/log-adjacency-changes/detail
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_log_adjacency_changes_detail_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf = nb_running_get_entry(args->dnode, NULL, true);

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(ospf->config, OSPF_LOG_ADJACENCY_DETAIL);
	else
		UNSET_FLAG(ospf->config, OSPF_LOG_ADJACENCY_DETAIL);

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/send-extra-data-zebra
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_send_extra_data_zebra_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/default-metric
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_default_metric_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_default_metric_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/write-multiplier
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_write_multiplier_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/passive-interface-default
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_passive_interface_default_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/abr-type
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_abr_type_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_create(struct nb_cb_create_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info/as
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_as_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_as_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info/area
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_area_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_area_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info/pce/address
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_address_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_address_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info/pce/scope/scope-flags
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_scope_scope_flags_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_scope_scope_flags_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info/pce/scope/pref-l
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_scope_pref_l_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_scope_pref_l_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info/pce/scope/pref-r
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_scope_pref_r_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_scope_pref_r_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info/pce/scope/pref-s
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_scope_pref_s_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_scope_pref_s_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info/pce/scope/pref-y
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_scope_pref_y_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_scope_pref_y_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info/pce/as/domain
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_as_domain_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_as_domain_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info/pce/as/neighbor
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_as_neighbor_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_as_neighbor_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info/pce/capabilities
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_capabilities_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_capabilities_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/graceful-restart/enable
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_graceful_restart_enable_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/graceful-restart/helper-enable
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_graceful_restart_helper_enable_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/graceful-restart/restart-interval
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_graceful_restart_restart_interval_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/graceful-restart/helper-strict-lsa-checking
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_graceful_restart_helper_strict_lsa_checking_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/graceful-restart/helper-only-planned-restart
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_graceful_restart_helper_only_planned_restart_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/graceful-restart/supported-grace-time
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_graceful_restart_supported_grace_time_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/auto-cost/reference-bandwidth
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_auto_cost_reference_bandwidth_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/default-information/originate
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_default_information_originate_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/default-information/metric
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_default_information_metric_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_default_information_metric_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/default-information/metric-type
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_default_information_metric_type_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_default_information_metric_type_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/default-information/route-map
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_default_information_route_map_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_default_information_route_map_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/redistribute/routes
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_routes_create(struct nb_cb_create_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_routes_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/redistribute/routes/metric
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_routes_metric_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_routes_metric_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/redistribute/routes/metric-type
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_routes_metric_type_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_routes_metric_type_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/redistribute/routes/route-map
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_routes_route_map_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_routes_route_map_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/route-aggregation/summary-routes/summary
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_route_aggregation_summary_routes_summary_create(struct nb_cb_create_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_route_aggregation_summary_routes_summary_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/route-aggregation/summary-routes/summary/tag
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_route_aggregation_summary_routes_summary_tag_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_route_aggregation_summary_routes_summary_tag_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/route-aggregation/summary-routes/summary/no-advertise
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_route_aggregation_summary_routes_summary_no_advertise_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/route-aggregation/timer
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_route_aggregation_timer_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/preference/all
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_preference_all_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_preference_all_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/preference/external
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_preference_external_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_preference_external_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/preference/inter-area
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_preference_inter_area_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_preference_inter_area_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/preference/intra-area
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_preference_intra_area_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_preference_intra_area_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/distribute-from-zebra/distribute
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_distribute_from_zebra_distribute_create(struct nb_cb_create_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_distribute_from_zebra_distribute_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/max-metric/router-lsa/always
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_max_metric_router_lsa_always_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/max-metric/router-lsa/on-shutdown
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_max_metric_router_lsa_on_shutdown_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_max_metric_router_lsa_on_shutdown_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/max-metric/router-lsa/on-startup
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_max_metric_router_lsa_on_startup_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_max_metric_router_lsa_on_startup_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/mpls/te/on
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_mpls_te_on_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/mpls/te/rid
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_mpls_te_rid_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_mpls_te_rid_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/mpls/te/inter-as/as
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_mpls_te_inter_as_as_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_mpls_te_inter_as_as_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/mpls/te/inter-as/area
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_mpls_te_inter_as_area_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_mpls_te_inter_as_area_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/mpls/ldp/igp-sync
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_mpls_ldp_igp_sync_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/mpls/ldp/holddown
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_mpls_ldp_holddown_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/fast-reroute/ti-lfa/protection
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_fast_reroute_ti_lfa_protection_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/spf-control/paths
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_spf_control_paths_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/spf-control/ietf-spf-delay/delay
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_spf_control_ietf_spf_delay_delay_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/spf-control/ietf-spf-delay/initial-holdtime
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_spf_control_ietf_spf_delay_initial_holdtime_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/spf-control/ietf-spf-delay/max-holdtime
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_spf_control_ietf_spf_delay_max_holdtime_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/spf-control/ietf-spf-delay/hold-multiplier
 */
struct yang_data *routing_control_plane_protocols_control_plane_protocol_ospf_spf_control_ietf_spf_delay_hold_multiplier_get_elem(struct nb_cb_get_elem_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/timers/refresh-interval
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_timers_refresh_interval_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/timers/lsa-min-arrival
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_timers_lsa_min_arrival_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/timers/lsa-min-interval
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_timers_lsa_min_interval_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/sr-mpls/srgb/lower-bound
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_sr_mpls_srgb_lower_bound_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/sr-mpls/srgb/upper-bound
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_sr_mpls_srgb_upper_bound_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/sr-mpls/srlb/lower-bound
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_sr_mpls_srlb_lower_bound_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/sr-mpls/srlb/upper-bound
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_sr_mpls_srlb_upper_bound_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/sr-mpls/node-msd
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_sr_mpls_node_msd_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_sr_mpls_node_msd_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/sr-mpls/on
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_sr_mpls_on_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/sr-mpls/bindings/connected-prefix-sid-map/connected-prefix-sid
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_sr_mpls_bindings_connected_prefix_sid_map_connected_prefix_sid_create(struct nb_cb_create_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_sr_mpls_bindings_connected_prefix_sid_map_connected_prefix_sid_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/sr-mpls/bindings/connected-prefix-sid-map/connected-prefix-sid/value-type
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_sr_mpls_bindings_connected_prefix_sid_map_connected_prefix_sid_value_type_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/sr-mpls/bindings/connected-prefix-sid-map/connected-prefix-sid/sid-value
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_sr_mpls_bindings_connected_prefix_sid_map_connected_prefix_sid_sid_value_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/sr-mpls/bindings/connected-prefix-sid-map/connected-prefix-sid/last-hop-behavior
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_sr_mpls_bindings_connected_prefix_sid_map_connected_prefix_sid_last_hop_behavior_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/nbma-neighbors/neighbor
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_nbma_neighbors_neighbor_create(struct nb_cb_create_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_nbma_neighbors_neighbor_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/nbma-neighbors/neighbor/priority
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_nbma_neighbors_neighbor_priority_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/nbma-neighbors/neighbor/poll-interval
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_nbma_neighbors_neighbor_poll_interval_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/ip-networks/network
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_ip_networks_network_create(struct nb_cb_create_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_ip_networks_network_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/ip-networks/network/area
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_ip_networks_network_area_modify(struct nb_cb_modify_args *args)
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
 * frr-routing area configurable state
 */

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_create(struct nb_cb_create_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_destroy(struct nb_cb_destroy_args *args)
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

const void *routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_get_next(struct nb_cb_get_next_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_get_keys(struct nb_cb_get_keys_args *args)
{
	/* TODO: implement me. */
	return NB_OK;
}

const void *routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/area-type
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_area_type_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/authentication
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_authentication_create(struct nb_cb_create_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_authentication_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/authentication/type
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_authentication_type_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/summary
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_summary_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_summary_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/default-cost
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_default_cost_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_default_cost_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/nssa/translate
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_translate_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/nssa/suppress-fa
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_suppress_fa_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/export-list
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_export_list_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_export_list_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/import-list
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_import_list_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_import_list_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/filter-list/in/prefix
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_filter_list_in_prefix_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_filter_list_in_prefix_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/filter-list/out/prefix
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_filter_list_out_prefix_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_filter_list_out_prefix_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/ranges/range
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_ranges_range_create(struct nb_cb_create_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_ranges_range_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/ranges/range/advertise
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_ranges_range_advertise_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/ranges/range/cost
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_ranges_range_cost_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_ranges_range_cost_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/ranges/range/substitute
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_ranges_range_substitute_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_ranges_range_substitute_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/shortcut/configuration
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_shortcut_configuration_modify(struct nb_cb_modify_args *args)
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
 * frr-routing virtual link configurable state
 */

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_create(struct nb_cb_create_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_destroy(struct nb_cb_destroy_args *args)
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

const void *routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_get_next(struct nb_cb_get_next_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_get_keys(struct nb_cb_get_keys_args *args)
{
	/* TODO: implement me. */
	return NB_OK;
}

const void *routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/dead-interval
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_dead_interval_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/hello-interval
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_hello_interval_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/retransmit-interval
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_retransmit_interval_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/transmit-delay
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_transmit_delay_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/authentication/type
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_authentication_type_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/authentication/simple-key
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_authentication_simple_key_modify(struct nb_cb_modify_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_authentication_simple_key_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-links/virtual-link/authentication/mds-keys/mds-key
 */
int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_authentication_mds_keys_mds_key_create(struct nb_cb_create_args *args)
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

int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_links_virtual_link_authentication_mds_keys_mds_key_destroy(struct nb_cb_destroy_args *args)
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
 * frr-interface configurable state
 */

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf
 */
int lib_interface_ospf_create(struct nb_cb_create_args *args)
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

int lib_interface_ospf_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/ospf-id
 */
int lib_interface_ospf_ospf_id_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/area
 */
int lib_interface_ospf_area_modify(struct nb_cb_modify_args *args)
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

int lib_interface_ospf_area_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/cost
 */
int lib_interface_ospf_cost_modify(struct nb_cb_modify_args *args)
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

int lib_interface_ospf_cost_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/passive
 */
int lib_interface_ospf_passive_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/priority
 */
int lib_interface_ospf_priority_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-type
 */
int lib_interface_ospf_interface_type_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/dmvpn
 */
int lib_interface_ospf_dmvpn_modify(struct nb_cb_modify_args *args)
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

int lib_interface_ospf_dmvpn_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/mtu-ignore
 */
int lib_interface_ospf_mtu_ignore_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/dead-interval/interval
 */
int lib_interface_ospf_dead_interval_interval_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/dead-interval/minimal/hello-multiplier
 */
int lib_interface_ospf_dead_interval_minimal_hello_multiplier_modify(struct nb_cb_modify_args *args)
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

int lib_interface_ospf_dead_interval_minimal_hello_multiplier_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/hello-interval
 */
int lib_interface_ospf_hello_interval_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/retransmit-interval
 */
int lib_interface_ospf_retransmit_interval_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/transmit-delay
 */
int lib_interface_ospf_transmit_delay_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/authentication/type
 */
int lib_interface_ospf_authentication_type_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/authentication/simple-key
 */
int lib_interface_ospf_authentication_simple_key_modify(struct nb_cb_modify_args *args)
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

int lib_interface_ospf_authentication_simple_key_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/authentication/mds-keys/mds-key
 */
int lib_interface_ospf_authentication_mds_keys_mds_key_create(struct nb_cb_create_args *args)
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

int lib_interface_ospf_authentication_mds_keys_mds_key_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/mpls/ldp-sync/enable
 */
int lib_interface_ospf_mpls_ldp_sync_enable_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/mpls/ldp-sync/holddown
 */
int lib_interface_ospf_mpls_ldp_sync_holddown_modify(struct nb_cb_modify_args *args)
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

int lib_interface_ospf_mpls_ldp_sync_holddown_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/bfd/enable
 */
int lib_interface_ospf_bfd_enable_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/bfd/local-multiplier
 */
int lib_interface_ospf_bfd_local_multiplier_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/bfd/profile
 */
int lib_interface_ospf_bfd_profile_modify(struct nb_cb_modify_args *args)
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

int lib_interface_ospf_bfd_profile_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/bfd/tx-rx-intervals/desired-min-tx-interval
 */
int lib_interface_ospf_bfd_tx_rx_intervals_desired_min_tx_interval_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/bfd/tx-rx-intervals/required-min-rx-interval
 */
int lib_interface_ospf_bfd_tx_rx_intervals_required_min_rx_interval_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address
 */
int lib_interface_ospf_interface_address_create(struct nb_cb_create_args *args)
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

int lib_interface_ospf_interface_address_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/area
 */
int lib_interface_ospf_interface_address_area_modify(struct nb_cb_modify_args *args)
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

int lib_interface_ospf_interface_address_area_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/cost
 */
int lib_interface_ospf_interface_address_cost_modify(struct nb_cb_modify_args *args)
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

int lib_interface_ospf_interface_address_cost_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/passive
 */
int lib_interface_ospf_interface_address_passive_modify(struct nb_cb_modify_args *args)
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

int lib_interface_ospf_interface_address_passive_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/priority
 */
int lib_interface_ospf_interface_address_priority_modify(struct nb_cb_modify_args *args)
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

int lib_interface_ospf_interface_address_priority_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/interface-type
 */
int lib_interface_ospf_interface_address_interface_type_modify(struct nb_cb_modify_args *args)
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

int lib_interface_ospf_interface_address_interface_type_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/dmvpn
 */
int lib_interface_ospf_interface_address_dmvpn_modify(struct nb_cb_modify_args *args)
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

int lib_interface_ospf_interface_address_dmvpn_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/mtu-ignore
 */
int lib_interface_ospf_interface_address_mtu_ignore_modify(struct nb_cb_modify_args *args)
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

int lib_interface_ospf_interface_address_mtu_ignore_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/dead-interval/interval
 */
int lib_interface_ospf_interface_address_dead_interval_interval_modify(struct nb_cb_modify_args *args)
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

int lib_interface_ospf_interface_address_dead_interval_interval_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/dead-interval/minimal/hello-multiplier
 */
int lib_interface_ospf_interface_address_dead_interval_minimal_hello_multiplier_modify(struct nb_cb_modify_args *args)
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

int lib_interface_ospf_interface_address_dead_interval_minimal_hello_multiplier_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/hello-interval
 */
int lib_interface_ospf_interface_address_hello_interval_modify(struct nb_cb_modify_args *args)
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

int lib_interface_ospf_interface_address_hello_interval_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/retransmit-interval
 */
int lib_interface_ospf_interface_address_retransmit_interval_modify(struct nb_cb_modify_args *args)
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

int lib_interface_ospf_interface_address_retransmit_interval_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/transmit-delay
 */
int lib_interface_ospf_interface_address_transmit_delay_modify(struct nb_cb_modify_args *args)
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

int lib_interface_ospf_interface_address_transmit_delay_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/authentication/type
 */
int lib_interface_ospf_interface_address_authentication_type_modify(struct nb_cb_modify_args *args)
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

int lib_interface_ospf_interface_address_authentication_type_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/authentication/simple-key
 */
int lib_interface_ospf_interface_address_authentication_simple_key_modify(struct nb_cb_modify_args *args)
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

int lib_interface_ospf_interface_address_authentication_simple_key_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/authentication/mds-keys/mds-key
 */
int lib_interface_ospf_interface_address_authentication_mds_keys_mds_key_create(struct nb_cb_create_args *args)
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

int lib_interface_ospf_interface_address_authentication_mds_keys_mds_key_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/mpls/ldp-sync/enable
 */
int lib_interface_ospf_interface_address_mpls_ldp_sync_enable_modify(struct nb_cb_modify_args *args)
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

int lib_interface_ospf_interface_address_mpls_ldp_sync_enable_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/mpls/ldp-sync/holddown
 */
int lib_interface_ospf_interface_address_mpls_ldp_sync_holddown_modify(struct nb_cb_modify_args *args)
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

int lib_interface_ospf_interface_address_mpls_ldp_sync_holddown_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/bfd/enable
 */
int lib_interface_ospf_interface_address_bfd_enable_modify(struct nb_cb_modify_args *args)
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

int lib_interface_ospf_interface_address_bfd_enable_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/bfd/local-multiplier
 */
int lib_interface_ospf_interface_address_bfd_local_multiplier_modify(struct nb_cb_modify_args *args)
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

int lib_interface_ospf_interface_address_bfd_local_multiplier_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/bfd/profile
 */
int lib_interface_ospf_interface_address_bfd_profile_modify(struct nb_cb_modify_args *args)
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

int lib_interface_ospf_interface_address_bfd_profile_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/bfd/tx-rx-intervals/desired-min-tx-interval
 */
int lib_interface_ospf_interface_address_bfd_tx_rx_intervals_desired_min_tx_interval_modify(struct nb_cb_modify_args *args)
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

int lib_interface_ospf_interface_address_bfd_tx_rx_intervals_desired_min_tx_interval_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/bfd/tx-rx-intervals/required-min-rx-interval
 */
int lib_interface_ospf_interface_address_bfd_tx_rx_intervals_required_min_rx_interval_modify(struct nb_cb_modify_args *args)
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

int lib_interface_ospf_interface_address_bfd_tx_rx_intervals_required_min_rx_interval_destroy(struct nb_cb_destroy_args *args)
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
