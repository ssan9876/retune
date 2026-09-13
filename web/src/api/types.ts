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
