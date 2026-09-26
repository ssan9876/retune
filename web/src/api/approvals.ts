/** Approval is a request held until a second administrator decides it. */
export interface Approval {
  id: string;
  kind: "command" | "assignment" | "version" | "group_member" | "group_rule" | "server_update";
  request: Record<string, unknown>;
  summary: string;
  requested_by: string;
  created_at: string;
  expires_at: string;
  status: "pending" | "approved" | "rejected" | "expired" | "failed";
  decided_by?: string;
  decided_at?: string;
  reason?: string;
  result?: { error?: string; commands?: { id: string; device_id: string }[] };
}

/** heldForApproval says a request was held for a second administrator (202)
 * rather than carried out. */
export function heldForApproval(res: unknown): res is { approval: Approval } {
  return typeof res === "object" && res !== null && "approval" in res;
}
