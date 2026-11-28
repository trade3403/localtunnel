"""Require complete real E2E evidence after successful test execution.
This is a secondary CI gate, not a substitute for executing any E2E.
Do not print report values: only fixed report names and check identifiers.
"""
import argparse
import json
from pathlib import Path
import unittest
import tempfile

REQUIRED = {
    "management": {
        "http.json": [
            "real_loopback_http",
            "migration_and_constraints",
            "restart_persistence_and_readiness",
            "unsafe_path_rejected"
        ],
        "auth.json": [
            "bootstrap_and_argon2id",
            "login_and_authorization",
            "rotation_logout_expiry_revocation",
            "restart_and_bounded_login"
        ],
        "devices.json": [
            "atomic_single_use_and_digest",
            "device_scope_and_admin_ownership",
            "expiry_and_owner_state",
            "restart_and_revocation"
        ],
        "sync.json": [
            "snapshot_revision_and_scope",
            "real_heartbeat_staleness_and_revision",
            "restart_owner_and_device_revocation"
        ],
        "mappings.json": [
            "create_read_scope_and_conflicts",
            "optimistic_update_and_activation_gate",
            "restart_delete_and_mapping_limit",
            "real_committed_audit_owner_cursor_and_local_retention"
        ],
        "domains.json": [
            "local_operator_node_inventory",
            "real_dns_tcp_exact_txt_rotation",
            "mapping_reference_and_activation_gate",
            "restart_and_scoped_delete"
        ],
        "preview.json": [
            "eligible_revision_private_bundle",
            "actual_noise_tunnel_from_managed_draft",
            "real_post_reload_business_probe_failure_and_rollback",
            "actual_gateway_apply_and_failed_apply_preserves_live_route",
            "actual_route_removal_no_false_activation",
            "persistent_attempt_outcomes_and_revoked_apply_denied",
            "actual_supervised_tunnel_revocation_and_gateway_clear",
            "real_gateway_observed_bytes_and_owner_isolation",
            "api_start_stop_scoped_request_real_worker",
            "resident_multiple_real_start_stop_cycles",
            "resident_local_stop_marker_cleans_real_tunnel",
            "resident_child_exit_cleanup_blocks_unknown_restart",
            "real_supervisor_sigkill_parent_death_and_verified_local_recovery"
        ],
        "tls-preview.json": [
            "real_tls_certificate_and_noise_http_body",
            "tls_business_failure_restores_previous_certificate_and_route",
            "revoked_apply_denied_and_explicit_tls_clear",
            "real_supervised_https_revocation_and_handshake_denial",
            "real_https_runtime_api_start_stop",
            "real_https_resident_multiple_start_stop",
            "real_https_child_failure_recovery_rejects_live_listener",
            "real_https_supervisor_sigkill_parent_death_and_recovery",
            "real_https_restart_after_recovery_and_local_stop"
        ],
        "admin-browser.json": [
            "real_login_and_memory_session",
            "real_cursor_pagination",
            "real_node_device_pairing_domain",
            "real_mapping_and_unverified_activation_denied",
            "real_edit_delete_and_domain_reference_guard",
            "real_browser_udp_request_and_cancel",
            "real_browser_tcp_request_and_cancel",
            "real_gateway_traffic_visible_in_browser",
            "real_browser_start_stop_noise_gateway",
            "real_committed_audit_visible_in_browser",
            "logout_no_browser_errors"
        ]
    },
    "desktop": {
        "installer-smoke.json": [
            "installed",
            "bundled_engine_verified",
            "bundled_engine_runs",
            "window_started",
            "uninstalled",
            "installed_gui_e2e"
        ],
        "service-smoke.json": [
            "registered",
            "started",
            "stopped",
            "deleted"
        ],
        "service-tunnel.json": [
            "unsafe_registration_rejected",
            "duplicate_registration_rejected",
            "registered",
            "unsafe_acl_rejected",
            "invalid_profile_rejected",
            "sealed_profile",
            "unsafe_history_rejected",
            "overwrite_rejected",
            "autostart_unsafe_rejected",
            "unsafe_recovery_rejected",
            "unsafe_profile_acl_rejected",
            "autostart_enabled",
            "autostart_disabled",
            "forwarded",
            "history_checkpoint",
            "service_traffic_measured",
            "old_runtime_cleaned",
            "engine_recovered",
            "unknown_runtime_preserved",
            "host_crash_runtime_cleaned",
            "host_crash_restart",
            "history_after_host_recovery",
            "recovered_traffic_measured",
            "automatic_host_recovered",
            "running_unregister_rejected",
            "stopped",
            "idempotent_stop",
            "readonly_scm_status",
            "history_after_stop",
            "runtime_cleaned",
            "normal_stop_no_recovery",
            "recovery_disabled",
            "desktop_service_controls",
            "one_click_provision",
            "profile_update",
            "mixed_service_forwarded",
            "mixed_service_recovered",
            "mixed_service_measured_traffic",
            "mixed_service_stopped",
            "desktop_unregister",
            "unregister_preserved_profile",
            "history_preserved_unregister",
            "deleted"
        ],
        "installed-gui-e2e.json": [
            "ui_ready",
            "native_management_auto_heartbeat_hidden",
            "native_management_restart_clean_exit",
            "native_management_saved_credential_restart",
            "real_management_udp_confirmed_draft_import",
            "real_management_unissued_udp_lease_denied",
            "native_management_revocation_stops_automatic_sync",
            "real_management_pairing_dpapi_heartbeat_and_revocation",
            "mapping_add_remove",
            "port_probe",
            "start_clicked",
            "encrypted_http",
            "traffic_visible",
            "native_close_hides",
            "hidden_tunnel_works",
            "native_restore",
            "tray_first_restore_clicked",
            "stop_clicked",
            "forwarding_stopped",
            "history_visible",
            "real_installed_desktop_mixed_udp_forward_and_measured",
            "real_installed_desktop_mixed_udp_stop_and_tcp_restore",
            "service_provisioned",
            "service_startup_controls",
            "service_recovery_controls",
            "service_real_http",
            "service_traffic_visible",
            "service_stopped",
            "service_config_updated",
            "service_updated_http",
            "service_unregistered",
            "service_data_preserved",
            "tray_original_window_visible",
            "tray_original_window_hidden",
            "tray_second_hidden_http",
            "tray_show_clicked",
            "tray_stop_clicked",
            "tray_quit_clicked",
            "tray_quit_clean_exit",
            "tray_quit_forwarding_stopped",
            "cdp_policy_created",
            "cdp_policy_removed",
            "cdp_http_reachable"
        ]
    }
}

# V0.5 retains the entire V0.4 management gate and adds its own report.
REQUIRED["management-v05"] = {
    **REQUIRED["management"],
    "http.json": [
        *REQUIRED["management"]["http.json"],
        "linux_private_sqlite_modes_and_hardlinks",
    ],
    "auth.json": [
        *REQUIRED["management"]["auth.json"],
        "unsupported_stored_argon2_parameters_rejected",
        "foreign_origin_valid_login_no_session",
    ],
    "devices.json": [
        *REQUIRED["management"]["devices.json"],
        "active_device_quota_transaction_and_pairing_retry",
        "retained_device_quota_concurrent_and_owner_isolated",
    ],
    "preview.json": [
        *REQUIRED["management"]["preview.json"],
        "real_gateway_log_budget_stops_and_preserves_evidence",
        "offline_gateway_log_retention_preserves_recent_and_unrelated",
        "real_http_noise_concurrent_bidirectional_payload_integrity",
        "real_http_commercial_expiry_and_queued_cancellation",
        "real_http_commercial_tcp_bandwidth_and_plan_change_cleanup",
        "real_http_monthly_only_plan_debits_and_stops_without_overspend",
        "real_http_connection_only_plan_denies_extra_backend_stream",
    ],
    "tls-preview.json": [
        *REQUIRED["management"]["tls-preview.json"],
        "real_https_log_count_reservation_rejected",
        "real_https_log_byte_reservation_rejected",
        "real_https_aggregate_log_quota_stops_and_recovers",
        "real_https_log_generation_isolation_after_quota_recovery",
        "real_https_noise_concurrent_bidirectional_payload_integrity",
        "real_https_commercial_suspend_latches_stop_across_renewal",
        "real_https_commercial_tcp_bandwidth_and_plan_change_cleanup",
        "real_https_monthly_only_plan_debits_and_stops_without_overspend",
        "real_https_connection_only_plan_denies_extra_backend_stream",
        "real_four_protocol_shared_connection_slots_and_cleanup",
        "real_https_five_minute_resident_soak_and_resource_bounds",
        "real_https_soak_clean_stop_and_listener_release",
    ],
    "protection.json": [
        "real_request_bounds_and_response_headers",
        "real_concurrent_requests_rejected_without_queue",
        "real_partial_body_deadline_and_capacity_recovery",
        "real_global_rate_limit_and_refill",
        "real_local_host_origin_and_fetch_site_guard",
    ],
    "backup.json": [
        "real_consistent_live_wal_snapshot_and_no_overwrite",
        "real_restored_login_mapping_and_stale_credentials_rejected",
        "corrupt_schema_symlink_and_existing_destination_refused",
        "restored_runtime_and_domain_authority_cleared",
        "snapshot_size_and_sidecar_admission_recovery",
    ],
    "load.json": [
        "real_sustained_mixed_management_workload",
        "real_load_process_resources_sampled_and_recovered",
        "real_post_load_heartbeat_readiness_and_auth",
        "real_sustained_rate_overload_bounded_and_rejected",
        "real_overload_recovery_without_restart_and_authenticated_write",
    ],
    "transport.json": [
        "real_incomplete_header_absolute_deadline",
        "real_keepalive_idle_connection_released",
        "real_connection_cap_and_admitted_request",
        "real_transport_capacity_recovery",
        "real_active_connection_total_lifetime",
        "real_connection_lifetime_same_process_recovery",
    ],
}

# V0.8 extends rather than replaces existing management gates.
REQUIRED["management-v08"] = {
    **REQUIRED["management-v05"],
    "admin-browser.json": [
        *REQUIRED["management-v05"]["admin-browser.json"],
        "real_browser_commercial_entitlement_and_refresh",
        "real_browser_commercial_owner_isolation",
    ],
    "tcp-preview.json": [
        "real_tcp_scoped_queue_and_cancel",
        "real_tcp_noise_shared_bidirectional_cap",
        "real_tcp_stop_closes_listeners_and_bundle",
        "real_tcp_suspend_and_rapid_renewal_stops_generation",
        "real_tcp_plan_change_closes_old_budget",
        "real_tenant_two_tcp_workers_share_fixed_budget",
        "real_tenant_bandwidth_owner_isolation",
        "real_tenant_cross_protocol_over_budget_denied",
        "real_tenant_released_budget_reused_by_other_protocol",
        "real_tenant_crash_reservation_fail_closed",
        "real_bandwidth_recovery_refuses_live_worker",
        "real_bandwidth_recovery_exact_binding_audit_and_no_adoption",
        "real_bandwidth_recovered_capacity_reused_by_real_workers",
        "real_monthly_shared_tcp_debits_and_previous_month_isolation",
        "real_monthly_udp_and_tcp_share_durable_tenant_budget",
        "real_monthly_over_budget_closes_real_tcp_without_overspend",
        "real_monthly_debits_survive_management_restart",
        "real_tenant_tcp_connection_slots_shared_denied_and_reused",
        "real_tenant_tcp_udp_connection_slots_shared_denied_and_reused",
        "real_crashed_connection_slot_retained_until_audited_recovery",
    ],
    "udp-preview.json": [
        "real_udp_commercial_suspend_revokes_lease_and_closes_relay",
        "real_udp_commercial_manual_cap_and_unsupported_rate_denial",
        "real_udp_commercial_cap_tightens_operator_and_limits_payload",
        "real_udp_commercial_plan_change_stops_old_generation",
        "real_udp_managed_monthly_precharge_and_manual_denial",
        "real_udp_device_monthly_shared_budget_exhaustion_and_cleanup",
        "real_udp_device_connection_quota_probe_exempt_and_cleanup",
    ],
    "commercial.json": [
        "real_legacy_upgrade_preserves_existing_owner_data",
        "fresh_bootstrap_and_legacy_tenant_assignment",
        "real_authenticated_owner_inventory_isolation",
        "real_policy_state_and_revoked_session_observation",
        "real_restart_persistence_and_commercial_readiness",
        "real_operator_versioned_immutable_plan_creation",
        "real_operator_atomic_account_and_plan_assignment",
        "real_created_account_login_and_no_http_policy_mutation",
        "real_commercial_foreign_selectors_and_operator_http_boundary",
        "real_assignment_optimistic_concurrency_expiry_and_renewal",
        "real_committed_operator_audit_and_owner_isolation",
        "real_dynamic_active_device_quota_and_pairing_retry",
        "real_concurrent_tenant_mapping_quota_and_owner_isolation",
        "real_expiry_suspension_and_renewal_admission",
        "real_retained_quota_concurrency_and_expired_cleanup",
    ],
}

REQUIRED["management-v09"] = {
    **REQUIRED["management-v08"],
    "tcp-preview.json": [
        *REQUIRED["management-v08"]["tcp-preview.json"],
        "real_node_drain_cancels_unclaimed_and_blocks_new_admission",
        "real_node_drain_preserves_live_tcp_budget_and_resumes_after_stop",
    ],
    "relay-identity.json": [
        "real_independent_relay_identity_and_tenant_boundary",
        "real_relay_generation_rotation_and_revocation",
        "real_relay_disable_no_resurrection_and_audit",
        "real_relay_heartbeat_freshness_generation_and_isolation",
    ],
    "relay-budget.json": [
        "real_cross_node_budget_atomic_race_and_owner_isolation",
        "real_cross_node_budget_independent_caps_and_immutable_non_executable_ledger",
        "real_finite_budget_grant_exact_node_slice_and_legacy_isolation",
         "real_finite_budget_one_shot_claim_and_replay_rejection",
         "real_guarded_intent_explicit_opt_in_and_claim_mode_isolation",
    ],
    "relay-http-claim.json": [
        "real_http_dns_proof_exact_claim_and_protocol_isolation",
        "real_http_proof_rotation_and_shared_transport_port_denial",
        "real_https_certificate_fingerprint_exact_claim_and_port_isolation",
    ],
    "relay-tcp-claim.json": [
        "real_tcp_explicit_intent_exact_claim_and_one_shot_race",
        "real_tcp_claim_port_policy_and_restore_isolation",
    ],
    "grants.json": [
        "real_grant_exact_binding_atomic_generation_and_owner_isolation",
        "real_grant_policy_generation_expiry_and_no_release",
        "real_grant_restore_revoked_and_retained",
    ],
    "scheduling.json": [
        "real_atomic_capacity_and_idempotent_reservation",
        "real_region_port_and_drain_isolation",
        "real_allocation_owner_boundary_and_cancel",
        "real_allocation_restore_retains_reservation",
    ],
    "node-policy.json": [
        "real_node_policy_upgrade_and_constraints",
        "real_operator_policy_revision_audit_and_isolation",
        "real_node_health_capacity_and_generation",
        "real_node_policy_restore_revokes_snapshot_credentials",
    ],
    "relay-tls.json": [
        "real_tls_three_relay_processes_and_restricted_ingress",
        "real_tls_untrusted_ca_hostname_and_private_ca_rejected",
        "real_tls_redirect_no_plaintext_or_proxy_fallback",
        "real_tls_relay_revocation_and_no_credential_diagnostics",
        "real_versioned_control_atomic_policy_and_rejected_mutations",
        "real_relay_process_live_policy_revision_sync",
        "real_tls_node_exact_grant_validation",
        "real_tls_node_conservative_expiry_and_restart_rejection",
        "real_independent_noise_tcp_transfer_and_one_shot_start",
        "real_independent_tcp_engine_expiry_closes_ports",
        "real_independent_udp_datagrams_protocol_and_port_isolation",
        "real_independent_udp_expiry_closes_transport_and_datagram_port",
        "real_independent_http_dns_host_routing_and_header_isolation",
        "real_independent_http_expiry_closes_gateway_and_noise_engine",
        "real_independent_https_certificate_key_fingerprint_and_sni_isolation",
        "real_independent_https_expiry_closes_tls_gateway_and_noise_engine",
        "real_center_process_loss_preserves_existing_tcp_stream_and_denies_new_claim",
        "real_offline_expiry_closes_established_tcp_stream_and_ports",
        "real_center_restart_rejects_expired_claims_and_retains_reservations",
        "real_two_independent_nodes_udp_https_forward_during_center_loss",
        "real_https_supervisor_sigkill_closes_owned_gateway_and_engine_other_node_survives",
        "real_offline_udp_expiry_closes_datagram_port_and_retains_crash_reservation",
        "real_crashed_https_claim_rejected_after_center_recovery",
        "real_tls_finite_budget_node_verification_and_expiry_without_listener",
         "real_tls_finite_budget_one_shot_durable_node_consumption_without_listener",
         "real_tls_guarded_noise_tcp_budget_exhaustion_and_replay_rejection",
    ],
    "relay-process.json": [
        "real_three_independent_relay_control_processes",
        "real_relay_control_center_restart_recovery",
        "real_relay_process_loss_and_health_recovery",
        "real_relay_process_credential_rotation_private_file_and_revocation",
    ],
}

def unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate report field")
        obj[key] = value
    return obj

def validate(group, directory):
    errors = []
    checked = 0
    for filename, keys in REQUIRED[group].items():
        path = directory / filename
        try:
            if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 1048576:
                raise ValueError("invalid report file")
            report = json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=unique_object)
            if not isinstance(report, dict):
                raise ValueError("not a JSON object")
        except (OSError, ValueError, UnicodeError):
            errors.append(filename + ": missing or invalid report")
            continue
        for key in keys:
            if report.get(key) is not True:
                errors.append(filename + ": missing or non-true " + key)
            else:
                checked += 1
    return checked, errors

class EvidenceGateTests(unittest.TestCase):
    def test_incomplete_and_wrong_type_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for filename, keys in REQUIRED["management"].items():
                (root / filename).write_text(json.dumps(dict.fromkeys(keys, True)), encoding="utf-8")
            total, errors = validate("management", root)
            self.assertEqual(total, sum(map(len, REQUIRED["management"].values())))
            self.assertFalse(errors)
            first = root / "http.json"
            sample = dict.fromkeys(REQUIRED["management"]["http.json"], True)
            sample["real_loopback_http"] = 1
            first.write_text(json.dumps(sample), encoding="utf-8")
            self.assertTrue(validate("management", root)[1])
            first.write_text('{"real_loopback_http":true,"real_loopback_http":false}', encoding="utf-8")
            self.assertTrue(validate("management", root)[1])
            first.unlink()
            self.assertTrue(validate("management", root)[1])

    def test_v05_requires_additional_real_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for filename, keys in REQUIRED["management"].items():
                (root / filename).write_text(json.dumps(dict.fromkeys(keys, True)), encoding="utf-8")
            self.assertFalse(validate("management", root)[1])
            self.assertTrue(validate("management-v05", root)[1])
            for name in ("http.json", "auth.json", "devices.json", "preview.json", "tls-preview.json", "protection.json", "transport.json", "backup.json", "load.json"):
                filename = root / name
                keys = REQUIRED["management-v05"][name]
                filename.write_text(json.dumps(dict.fromkeys(keys, True)), encoding="utf-8")
            total, errors = validate("management-v05", root)
            self.assertEqual(total, sum(map(len, REQUIRED["management-v05"].values())))
            self.assertFalse(errors)
            filename.write_text(json.dumps(dict.fromkeys(keys, False)), encoding="utf-8")
            self.assertTrue(validate("management-v05", root)[1])

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("group", choices=REQUIRED)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(EvidenceGateTests)
    if not unittest.TextTestRunner().run(suite).wasSuccessful():
        return 1
    checked, errors = validate(args.group, args.directory)
    if errors:
        for error in errors:
            print(error)
        return 1
    print(f"Verified {checked} required real E2E assertions across {len(REQUIRED[args.group])} reports ({args.group})")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
