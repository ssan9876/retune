package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

// Fixed ids, so the seeds can refer to each other across versions.
var (
	upDevice      = uuid.MustParse("10000000-0000-0000-0000-000000000001")
	upRetired     = uuid.MustParse("10000000-0000-0000-0000-000000000002")
	upUnenrolled  = uuid.MustParse("10000000-0000-0000-0000-000000000003")
	upToken       = uuid.MustParse("20000000-0000-0000-0000-000000000001")
	upDoneCmd     = uuid.MustParse("30000000-0000-0000-0000-000000000001")
	upQueuedCmd   = uuid.MustParse("30000000-0000-0000-0000-000000000002")
	upAdmin       = uuid.MustParse("40000000-0000-0000-0000-000000000001")
	upGroup       = uuid.MustParse("50000000-0000-0000-0000-000000000001")
	upAssignment  = uuid.MustParse("50000000-0000-0000-0000-000000000002")
	upScript      = uuid.MustParse("60000000-0000-0000-0000-000000000001")
	upProfile     = uuid.MustParse("60000000-0000-0000-0000-000000000002")
	upApp         = uuid.MustParse("60000000-0000-0000-0000-000000000003")
	upAgentBuild  = uuid.MustParse("60000000-0000-0000-0000-000000000004")
	upPolicy      = uuid.MustParse("70000000-0000-0000-0000-000000000001")
	upChannel     = uuid.MustParse("70000000-0000-0000-0000-000000000002")
	upRule        = uuid.MustParse("70000000-0000-0000-0000-000000000003")
	upRegistrated = uuid.MustParse("80000000-0000-0000-0000-000000000001")
)

// upgradeSeeds holds rows written while the schema is at exactly the given
// version, each valid for that version and no later one's additions, so every
// migration after it runs over data an earlier release wrote. Values the
// seeds leave out are the ones later migrations must default.
var upgradeSeeds = map[uint][]string{
	1: {
		`INSERT INTO devices (id, tenant_id, hostname, serial, smbios_uuid, os_version, status, cert_serial, cert_expires_at, last_seen_at, agent_version, enrolled_at)
		 VALUES ('` + upDevice.String() + `', '00000000-0000-0000-0000-000000000001', 'PC-OLD', 'SN-OLD', 'UUID-OLD', '10.0.19045', 'active', 'c1', now() + interval '300 days', now(), '0.0.1', now() - interval '1 year')`,
		`INSERT INTO devices (id, tenant_id, hostname, status, cert_serial, cert_expires_at, enrolled_at)
		 VALUES ('` + upRetired.String() + `', '00000000-0000-0000-0000-000000000001', 'PC-GONE', 'retired', 'c2', now(), now() - interval '2 years')`,
		`INSERT INTO enrollment_tokens (id, tenant_id, token_hash, label, max_uses, use_count, created_by)
		 VALUES ('` + upToken.String() + `', '00000000-0000-0000-0000-000000000001', '\x01', 'imaging', 50, 2, 'admin@example.com')`,
		`INSERT INTO audit_log (id, tenant_id, actor, action, target_kind, target_id, details)
		 VALUES (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'admin@example.com', 'device.enroll', 'device', '` + upDevice.String() + `', '{"hostname":"PC-OLD"}')`,
	},
	2: {
		`INSERT INTO devices (id, tenant_id, hostname, status, cert_serial, cert_expires_at, enrolled_at)
		 VALUES ('` + upUnenrolled.String() + `', '00000000-0000-0000-0000-000000000001', 'PC-LEFT', 'unenrolled', 'c3', now(), now() - interval '1 year')`,
		`INSERT INTO device_inventory (device_id, tenant_id, collected_at, received_at, hash, software_hash, data, ram_gb, disk_free_gb)
		 VALUES ('` + upDevice.String() + `', '00000000-0000-0000-0000-000000000001', now(), now(), 'h', 'sh', '{"os":{"caption":"Windows 10"}}', 16, 120)`,
		`INSERT INTO device_software (device_id, tenant_id, name, version, publisher)
		 VALUES ('` + upDevice.String() + `', '00000000-0000-0000-0000-000000000001', 'Google Chrome', '119.0', 'Google')`,
		`INSERT INTO commands (id, tenant_id, device_id, type, payload, status, created_by, created_at, delivered_at, started_at, completed_at, expires_at)
		 VALUES ('` + upDoneCmd.String() + `', '00000000-0000-0000-0000-000000000001', '` + upDevice.String() + `', 'run_script', '{"script":"hostname"}', 'succeeded', 'admin@example.com', now() - interval '1 hour', now(), now(), now(), now() + interval '1 day')`,
		`INSERT INTO command_results (command_id, tenant_id, exit_code, stdout, started_at, finished_at)
		 VALUES ('` + upDoneCmd.String() + `', '00000000-0000-0000-0000-000000000001', 0, 'PC-OLD', now(), now())`,
		`INSERT INTO commands (id, tenant_id, device_id, type, status, created_by, created_at, expires_at)
		 VALUES ('` + upQueuedCmd.String() + `', '00000000-0000-0000-0000-000000000001', '` + upDevice.String() + `', 'refresh_inventory', 'queued', 'admin@example.com', now(), now() + interval '1 day')`,
	},
	3: {
		`INSERT INTO admins (id, tenant_id, email, password_hash, role, created_at)
		 VALUES ('` + upAdmin.String() + `', '00000000-0000-0000-0000-000000000001', 'Old.Admin@example.com', '$argon2id$placeholder', 'admin', now())`,
		`INSERT INTO sessions (token_hash, tenant_id, admin_id, csrf_token, created_at, expires_at, last_seen_at)
		 VALUES ('\x02', '00000000-0000-0000-0000-000000000001', '` + upAdmin.String() + `', 'csrf', now(), now() + interval '1 day', now())`,
	},
	4: {
		`INSERT INTO device_groups (id, tenant_id, name, kind, created_at, updated_at)
		 VALUES ('` + upGroup.String() + `', '00000000-0000-0000-0000-000000000001', 'Finance', 'static', now(), now())`,
		`INSERT INTO group_members (group_id, device_id, tenant_id, added_at)
		 VALUES ('` + upGroup.String() + `', '` + upDevice.String() + `', '00000000-0000-0000-0000-000000000001', now())`,
		// An assignment written before scripts existed: no options, no rollout.
		`INSERT INTO assignments (id, tenant_id, item_kind, item_id, group_id, mode, created_at, created_by)
		 VALUES ('` + upAssignment.String() + `', '00000000-0000-0000-0000-000000000001', 'script', '` + upScript.String() + `', '` + upGroup.String() + `', 'include', now(), 'admin@example.com')`,
		`INSERT INTO device_item_status (device_id, tenant_id, item_kind, item_id, status, updated_at)
		 VALUES ('` + upDevice.String() + `', '00000000-0000-0000-0000-000000000001', 'script', '` + upScript.String() + `', 'succeeded', now())`,
	},
	5: {
		`INSERT INTO scripts (id, tenant_id, name, current_version, created_at, updated_at, created_by)
		 VALUES ('` + upScript.String() + `', '00000000-0000-0000-0000-000000000001', 'Clear temp', 1, now(), now(), 'admin@example.com')`,
		`INSERT INTO script_versions (script_id, version, tenant_id, body, hash, created_at, created_by)
		 VALUES ('` + upScript.String() + `', 1, '00000000-0000-0000-0000-000000000001', 'Remove-Item $env:TEMP\* -Recurse', 'sha', now(), 'admin@example.com')`,
		`INSERT INTO script_runs (id, tenant_id, script_id, version, device_id, status, phase, exit_code, started_at, finished_at)
		 VALUES (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', '` + upScript.String() + `', 1, '` + upDevice.String() + `', 'succeeded', 'script', 0, now(), now())`,
	},
	6: {
		`INSERT INTO profiles (id, tenant_id, name, current_version, created_at, updated_at, created_by)
		 VALUES ('` + upProfile.String() + `', '00000000-0000-0000-0000-000000000001', 'Baseline', 1, now(), now(), 'admin@example.com')`,
		`INSERT INTO profile_versions (profile_id, version, tenant_id, settings, hash, created_at, created_by)
		 VALUES ('` + upProfile.String() + `', 1, '00000000-0000-0000-0000-000000000001', '[]', 'ph', now(), 'admin@example.com')`,
		`INSERT INTO profile_setting_status (device_id, tenant_id, profile_id, identity, version, status, updated_at)
		 VALUES ('` + upDevice.String() + `', '00000000-0000-0000-0000-000000000001', '` + upProfile.String() + `', 'service:Spooler', 1, 'compliant', now())`,
	},
	7: {
		`INSERT INTO bitlocker_keys (id, tenant_id, device_id, volume_id, method, ciphertext, nonce, created_at, updated_at)
		 VALUES (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', '` + upDevice.String() + `', 'C:', 'XtsAes128', '\x03', '\x04', now(), now())`,
	},
	8: {
		`INSERT INTO apps (id, tenant_id, name, current_version, created_at, updated_at, created_by)
		 VALUES ('` + upApp.String() + `', '00000000-0000-0000-0000-000000000001', 'Firefox', 1, now(), now(), 'admin@example.com')`,
		`INSERT INTO app_versions (app_id, version, tenant_id, package_id, hash, created_at, created_by)
		 VALUES ('` + upApp.String() + `', 1, '00000000-0000-0000-0000-000000000001', 'Mozilla.Firefox', 'ah', now(), 'admin@example.com')`,
		`INSERT INTO app_installs (id, tenant_id, app_id, version, device_id, intent, status, exit_code, started_at, finished_at)
		 VALUES (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', '` + upApp.String() + `', 1, '` + upDevice.String() + `', 'install', 'succeeded', 0, now(), now())`,
	},
	// Not at 9: 0010 adds required signature columns with no default, which
	// its comment explains no deployment ever needed.
	10: {
		`INSERT INTO agent_versions (id, tenant_id, version, sha256, size_bytes, created_at, created_by, key_id, signature)
		 VALUES ('` + upAgentBuild.String() + `', '00000000-0000-0000-0000-000000000001', '0.1.5', 'abc', 1024, now(), 'admin@example.com', 'k1', 'sig')`,
	},
	11: {
		`INSERT INTO compliance_policies (id, tenant_id, name, rules, created_at, updated_at, created_by)
		 VALUES ('` + upPolicy.String() + `', '00000000-0000-0000-0000-000000000001', 'Encryption', '[]', now(), now(), 'admin@example.com')`,
		`INSERT INTO device_compliance (device_id, policy_id, tenant_id, state, evaluated_at)
		 VALUES ('` + upDevice.String() + `', '` + upPolicy.String() + `', '00000000-0000-0000-0000-000000000001', 'non_compliant', now())`,
	},
	12: {
		`INSERT INTO notification_channels (id, tenant_id, name, kind, config, created_at, updated_at, created_by)
		 VALUES ('` + upChannel.String() + `', '00000000-0000-0000-0000-000000000001', 'Ops', 'email', '{"to":["ops@example.com"]}', now(), now(), 'admin@example.com')`,
		`INSERT INTO alert_rules (id, tenant_id, name, kind, channel_id, created_at, updated_at, created_by)
		 VALUES ('` + upRule.String() + `', '00000000-0000-0000-0000-000000000001', 'Stale', 'device_stale', '` + upChannel.String() + `', now(), now(), 'admin@example.com')`,
		`INSERT INTO alert_state (rule_id, subject_key, tenant_id, subject, firing_since)
		 VALUES ('` + upRule.String() + `', '` + upDevice.String() + `', '00000000-0000-0000-0000-000000000001', 'PC-OLD', now())`,
	},
	15: {
		`INSERT INTO api_tokens (id, tenant_id, name, token_hash, role, created_by_id, created_by, created_at, expires_at)
		 VALUES (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'ci', '\x05', 'read_only', '` + upAdmin.String() + `', 'Old.Admin@example.com', now(), now() + interval '90 days')`,
	},
	21: {
		`INSERT INTO local_admin_passwords (id, tenant_id, device_id, account, ciphertext, nonce, state, command_id, created_at)
		 VALUES (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', '` + upDevice.String() + `', 'retune-admin', '\x06', '\x07', 'active', gen_random_uuid(), now())`,
	},
	25: {
		`INSERT INTO approvals (id, tenant_id, kind, request, summary, requested_by, requester_id, created_at, expires_at)
		 VALUES (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'command', '{}', 'Wipe PC-OLD', 'Old.Admin@example.com', '` + upAdmin.String() + `', now(), now() + interval '1 day')`,
	},
	28: {
		`INSERT INTO scheduled_reports (id, tenant_id, name, kind, policy_id, recipients, frequency, hour, next_run_at, created_at, updated_at, created_by)
		 VALUES (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'Weekly encryption', 'compliance', '` + upPolicy.String() + `', '{ops@example.com}', 'weekly', 7, now(), now(), now(), 'admin@example.com')`,
	},
	30: {
		`INSERT INTO device_registrations (id, tenant_id, serial, created_at, created_by)
		 VALUES ('` + upRegistrated.String() + `', '00000000-0000-0000-0000-000000000001', 'SN-NEW', now(), 'admin@example.com')`,
	},
}

// TestMigrateOverEarlierData applies the migrations one at a time, writing
// rows at each version the way the release that stopped there would have,
// then reads them back through today's store.
func TestMigrateOverEarlierData(t *testing.T) {
	ctx := context.Background()
	url := storetest.DatabaseURL(t)
	latest, err := store.LatestMigration()
	if err != nil {
		t.Fatal(err)
	}
	for v := range upgradeSeeds {
		if v > latest {
			t.Fatalf("seed for version %d, but the latest migration is %d", v, latest)
		}
	}

	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	for v := uint(1); v <= latest; v++ {
		if err := store.MigrateTo(url, v); err != nil {
			t.Fatalf("migration %d over earlier data: %v", v, err)
		}
		for i, stmt := range upgradeSeeds[v] {
			if _, err := conn.Exec(ctx, stmt); err != nil {
				t.Fatalf("seed %d at version %d: %v", i, v, err)
			}
		}
	}

	// What a server does on every start: nothing left to apply.
	if err := store.Migrate(url); err != nil {
		t.Fatalf("migrate at head: %v", err)
	}
	if v, dirty, err := store.SchemaVersion(url); err != nil || v != latest || dirty {
		t.Fatalf("schema version = %d dirty=%v err=%v, want %d clean", v, dirty, err, latest)
	}

	s, err := store.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	q := s.Q()
	tenant := store.DefaultTenantID

	d, err := q.GetDevice(ctx, tenant, upDevice)
	if err != nil || d.Hostname != "PC-OLD" || d.Status != store.DeviceActive || d.Manufacturer != "" {
		t.Errorf("device = %+v, %v", d, err)
	}
	retired, total, err := q.ListDevicesPage(ctx, store.DeviceFilter{Bucket: "retired", StaleCutoff: time.Now().Add(-time.Hour)})
	if err != nil || total != 2 || len(retired) != 2 {
		t.Errorf("retired bucket = %d devices (total %d), %v; want PC-GONE and PC-LEFT", len(retired), total, err)
	}
	nonCompliant, total, err := q.ListDevicesPage(ctx, store.DeviceFilter{Compliance: store.ComplianceNonCompliant})
	if err != nil || total != 1 || nonCompliant[0].ID != upDevice {
		t.Errorf("non-compliant devices = %+v (total %d), %v", nonCompliant, total, err)
	}

	cmds, total, err := q.ListCommandsPage(ctx, store.CommandFilter{})
	if err != nil || total != 2 {
		t.Fatalf("commands = %d, %v; want 2", total, err)
	}
	for _, c := range cmds {
		if c.Hostname != "PC-OLD" {
			t.Errorf("command %s hostname = %q, want PC-OLD", c.ID, c.Hostname)
		}
	}
	if res, err := q.GetCommandResult(ctx, tenant, upDoneCmd); err != nil || res.Stdout != "PC-OLD" {
		t.Errorf("command result = %+v, %v", res, err)
	}

	a, err := q.GetAdminByEmail(ctx, tenant, "old.admin@example.com")
	if err != nil || a.Role != "admin" || a.AuthSource != "local" || a.Scoped || a.OIDCSubject != "" {
		t.Errorf("admin = %+v, %v", a, err)
	}

	as, err := q.ListAssignments(ctx, "script", upScript)
	if err != nil || len(as) != 1 {
		t.Fatalf("assignments = %+v, %v", as, err)
	}
	if string(as[0].Options) != "{}" || as[0].Rollout.Phased() {
		t.Errorf("pre-options assignment: options %s, rollout %+v; want {} and not phased", as[0].Options, as[0].Rollout)
	}
	if sv, err := q.GetScriptVersion(ctx, tenant, upScript, 1); err != nil || sv.Signature != nil {
		t.Errorf("script version = %+v, %v; want no signature", sv, err)
	}
	if _, err := q.GetProfileVersion(ctx, tenant, upProfile, 1); err != nil {
		t.Errorf("profile version: %v", err)
	}
	av, err := q.GetAppVersion(ctx, tenant, upApp, 1)
	if err != nil || av.Source != "winget" || av.InstallerType != "" || len(av.SuccessExitCodes) != 0 || av.UninstallPrevious {
		t.Errorf("app version = %+v, %v; want a winget package with defaults", av, err)
	}
	if keys, err := q.ListBitLockerKeys(ctx, upDevice); err != nil || len(keys) != 1 {
		t.Errorf("bitlocker keys = %d, %v", len(keys), err)
	}
	if builds, total, err := q.ListAgentVersions(ctx, store.Page{}); err != nil || total != 1 || builds[0].KeyID != "k1" {
		t.Errorf("agent versions = %+v, %v", builds, err)
	}
	if dc, err := q.ListDeviceCompliance(ctx, upDevice); err != nil || len(dc) != 1 || dc[0].State != store.ComplianceNonCompliant {
		t.Errorf("device compliance = %+v, %v", dc, err)
	}
	if rules, err := q.ListAlertRules(ctx, false); err != nil || len(rules) != 1 || rules[0].ChannelName != "Ops" {
		t.Errorf("alert rules = %+v, %v", rules, err)
	}

	var registeredOnly bool
	if err := conn.QueryRow(ctx, `SELECT registered_only FROM enrollment_tokens WHERE id = $1`, upToken).Scan(&registeredOnly); err != nil || registeredOnly {
		t.Errorf("old token registered_only = %v, %v; want false", registeredOnly, err)
	}
	var builtins int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM device_groups WHERE kind = 'builtin'`).Scan(&builtins); err != nil || builtins != 1 {
		t.Errorf("built-in groups = %d, %v; want 1", builtins, err)
	}
}

// TestMigrateDownAndUp reverts every migration and applies them again, so
// each down file is at least valid and leaves nothing the up file trips on.
func TestMigrateDownAndUp(t *testing.T) {
	url := storetest.DatabaseURL(t)
	if err := store.Migrate(url); err != nil {
		t.Fatal(err)
	}
	if err := store.MigrateDown(url); err != nil {
		t.Fatalf("down: %v", err)
	}
	if err := store.Migrate(url); err != nil {
		t.Fatalf("up after down: %v", err)
	}
	latest, err := store.LatestMigration()
	if err != nil {
		t.Fatal(err)
	}
	if v, dirty, err := store.SchemaVersion(url); err != nil || v != latest || dirty {
		t.Fatalf("schema version = %d dirty=%v err=%v, want %d clean", v, dirty, err, latest)
	}
}
