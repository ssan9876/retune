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

export interface SettingStatus {
  device_id: string;
  hostname: string;
  identity: string;
  version: number;
  status: string;
  detail: string;
  updated_at: string;
}
