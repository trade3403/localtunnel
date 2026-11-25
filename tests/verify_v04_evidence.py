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
    ],
    "protection.json": [
        "real_request_bounds_and_response_headers",
        "real_concurrent_requests_rejected_without_queue",
        "real_partial_body_deadline_and_capacity_recovery",
        "real_global_rate_limit_and_refill",
        "real_local_host_origin_and_fetch_site_guard",
    ],
    "transport.json": [
        "real_incomplete_header_absolute_deadline",
        "real_keepalive_idle_connection_released",
        "real_connection_cap_and_admitted_request",
        "real_transport_capacity_recovery",
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
            for name in ("http.json", "auth.json", "devices.json", "preview.json", "protection.json", "transport.json"):
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
