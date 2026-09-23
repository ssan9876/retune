export type Role = "admin" | "read_only";

export interface Admin {
  id: string;
  email: string;
  role: Role;
  totp_enabled: boolean;
  disabled: boolean;
  created_at: string;
  last_login_at?: string;
}

export interface Device {
  id: string;
  hostname: string;
  status: "active" | "retired" | "replaced" | "unenrolled";
  os_version: string;
  os_build: string;
  manufacturer: string;
  model: string;
  serial: string;
  smbios_uuid: string;
  agent_version: string;
  enrolled_at: string;
  last_seen_at?: string;
  cert_expires_at: string;
  stale: boolean;
  compliance: string;
}

export interface Software {
  name: string;
  version: string;
  publisher: string;
  install_date: string;
  scope: string;
}

export interface Inventory {
  collected_at: string;
  received_at: string;
  ram_gb: number;
  disk_free_gb: number;
  document: unknown;
}

/** DefenderStatus is Microsoft Defender's own report, inside an inventory
 * document (internal/protocol/inventory.go). */
export interface DefenderStatus {
  running_mode: string;
  antivirus_enabled: boolean;
  realtime_enabled: boolean;
  tamper_protected: boolean;
  signature_version: string;
  signature_updated_at?: string;
  last_quick_scan_at?: string;
  last_full_scan_at?: string;
}

export interface FirewallProfileState {
  profile: string;
  enabled: boolean;
}

export interface Command {
  id: string;
  device_id: string;
  type: string;
  status: string;
  payload: unknown;
  created_by: string;
  created_at: string;
  delivered_at?: string;
  started_at?: string;
  completed_at?: string;
  expires_at: string;
}

export interface CommandResult {
  exit_code: number;
  stdout: string;
  stderr: string;
  stdout_truncated: boolean;
  stderr_truncated: boolean;
  error: string;
  started_at: string;
  finished_at: string;
}

export interface DeviceDetail {
  device: Device;
  inventory: Inventory | null;
  software: Software[];
  commands: Command[];
}

export interface Token {
  id: string;
  label: string;
  max_uses?: number;
  use_count: number;
  expires_at?: string;
  revoked_at?: string;
  created_by: string;
  created_at: string;
}

export interface AuditEntry {
  actor: string;
  action: string;
  target_kind: string;
  target_id: string;
  details: Record<string, unknown>;
  at: string;
}

export interface ListResponse<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface SessionResponse {
  admin: Admin;
  csrf_token: string;
  expires_at: string;
}

export interface Group {
  id: string;
  name: string;
  description: string;
  kind: "static" | "dynamic" | "builtin";
  rule: string;
  member_count: number;
  created_at: string;
  updated_at: string;
  evaluated_at: string | null;
}

export interface Script {
  id: string;
  name: string;
  description: string;
  current_version: number;
  body?: string;
  detection_body?: string;
  created_at: string;
  updated_at: string;
  created_by: string;
}

export interface ScriptRun {
  id: string;
  device_id: string;
  hostname: string;
  version: number;
  status: string;
  phase: string;
  remediated: boolean;
  exit_code: number;
  stdout: string;
  stderr: string;
  error: string;
  started_at: string;
  finished_at: string;
}

export interface App {
  id: string;
  name: string;
  description: string;
  package_id: string;
  pinned_version?: string;
  scope?: string;
  install_args?: string;
  current_version: number;
  created_at: string;
  updated_at: string;
  created_by: string;
}

export interface AppInstall {
  id: string;
  device_id: string;
  hostname: string;
  version: number;
  intent: string;
  status: string;
  installed_version: string;
  exit_code: number;
  stdout: string;
  stderr: string;
  error: string;
  detail: string;
  started_at: string;
  finished_at: string;
}

export interface AgentVersion {
  id: string;
  version: string;
  sha256: string;
  size_bytes: number;
  notes: string;
  key_id: string;
  signature: string;
  created_at: string;
  created_by: string;
}

export interface Setting {
  kind: string;
  hive?: string;
  key?: string;
  name?: string;
  type?: string;
  data?: string;
  startup?: string;
  state?: string;
  group?: string;
  members?: string[];
  mode?: string;
  path?: string;
  content_base64?: string;
  ensure?: string;
  profile?: string;
  direction?: string;
  action?: string;
  protocol?: string;
  local_port?: string;
  program?: string;
  quality_deferral_days?: number;
  feature_deferral_days?: number;
  active_hours_start?: number;
  active_hours_end?: number;
  auto_restart?: boolean;
  require_encryption?: boolean;
  method?: string;
  escrow_recovery_key?: boolean;
  realtime_monitoring?: boolean;
  cloud_protection?: string;
  sample_submission?: string;
  pua_protection?: string;
  cloud_block_level?: string;
}

export interface BitLockerKey {
  id: string;
  device_id: string;
  hostname: string;
  volume_id: string;
  method: string;
  created_at: string;
  updated_at: string;
}

export interface Profile {
  id: string;
  name: string;
  description: string;
  current_version: number;
  settings?: Setting[];
  created_at: string;
  updated_at: string;
  created_by: string;
}

export interface DashboardDevices {
  active: number;
  stale: number;
  retired: number;
  total: number;
}

export interface DashboardCompliance {
  compliant: number;
  non_compliant: number;
  unknown: number;
  not_evaluated: number;
}

export interface DashboardFailedDeployments {
  script: number;
  app: number;
  profile: number;
  agent: number;
}

/** The dashboard's two count lists have different key names on the wire, so
 * they get a type each rather than one shape with both keys optional - which
 * made every reader deal with an absent key that is never actually absent. */
export interface AgentVersionCount {
  version: string;
  count: number;
}

export interface OSBuildCount {
  build: string;
  count: number;
}

/** How long since each active device last checked in. The buckets are
 * exclusive - a device in `day` checked in within a day but not within an
 * hour - so they sum to the active fleet and draw as one bar. */
export interface CheckinRecency {
  hour: number;
  day: number;
  week: number;
  older: number;
  never: number;
}

/** One day of the enrolment trend. `day` is a plain YYYY-MM-DD bucket, not an
 * instant: it is rendered in UTC so a column cannot slide into the next day. */
export interface DayCount {
  day: string;
  count: number;
}

export interface Dashboard {
  devices: DashboardDevices;
  compliance: DashboardCompliance;
  failed_deployments: DashboardFailedDeployments;
  checkin_recency: CheckinRecency;
  enrollment_trend: DayCount[];
  agent_versions: AgentVersionCount[];
  os_builds: OSBuildCount[];
}

export interface ComplianceFailure {
  rule: string;
  state: string;
  detail: string;
}

export interface DeviceCompliancePolicy {
  policy_id: string;
  policy_name: string;
  state: string;
  failures: ComplianceFailure[];
  evaluated_at: string;
}

export interface DeviceCompliance {
  overall: string;
  policies: DeviceCompliancePolicy[];
}

/** ComplianceRule is one line of a policy's rules array. Only the fields its
 * `type` uses are populated, mirroring how the server's Rule struct and
 * MarshalJSON work: a fresh object per type, never a stray field left over
 * from a different type. */
export interface ComplianceRule {
  type: string;
  build?: string;
  version?: string;
  volumes?: string;
  min_version?: string;
  hours?: number;
  days?: number;
  count?: number;
  name?: string;
  profile_id?: string;
  /** firewall_enabled: the profiles to check; absent means all three. */
  profiles?: string[];
}

export interface CompliancePolicy {
  id: string;
  name: string;
  description: string;
  rules: ComplianceRule[];
  created_at: string;
  updated_at: string;
  created_by: string;
  // device_counts is only present on the list endpoint's items: a
  // compliant/non_compliant/unknown rollup batched over the whole page in
  // one query, not one request per policy. Absent on get/create/update.
  device_counts?: Record<string, number>;
}

export interface PolicyDeviceCompliance {
  device_id: string;
  hostname: string;
  state: string;
  failures: ComplianceFailure[];
  evaluated_at: string;
}

export interface SettingStatus {
  device_id: string;
  hostname: string;
  identity: string;
  version: number;
  status: string;
  detail: string;
  updated_at: string;
}

/** A notification channel never carries its own secret: the server reports
 *  only whether one is set, because a shared signing key the console can read
 *  back is a key every read-only account has. */
export interface NotificationChannel {
  id: string;
  name: string;
  kind: "email" | "webhook";
  config: { to?: string[]; url?: string };
  enabled: boolean;
  has_secret: boolean;
  created_at: string;
  updated_at: string;
  created_by: string;
}

export interface AlertRule {
  id: string;
  name: string;
  kind: string;
  params: { policy_id?: string; hours?: number; item_kind?: string };
  /** description is the server's own sentence for what this rule watches, so
   *  the console and the email it sends never disagree. */
  description: string;
  channel_id: string;
  channel_name: string;
  channel_kind: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
  created_by: string;
}

export interface FiringAlert {
  rule_id: string;
  rule_name: string;
  rule_kind: string;
  subject_key: string;
  subject: string;
  firing_since: string;
  notified_at: string | null;
}

export interface AlertDelivery {
  id: string;
  rule_id: string;
  rule_name: string;
  channel_name: string;
  at: string;
  ok: boolean;
  detail: string;
  firing: number;
  resolved: number;
}
