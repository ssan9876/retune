/** UpdateState is how an update of the server itself is going, or how it went. */
export interface UpdateState {
  id: string;
  version: string;
  from_version?: string;
  phase: "queued" | "verifying" | "backing_up" | "pulling" | "restarting" | "healthy" | "rolled_back" | "failed";
  detail?: string;
  error?: string;
  backup?: string;
  requested_by?: string;
  started_at: string;
  updated_at: string;
  finished_at?: string;
}

/** ServerInfo is GET /server: the running version and what can be installed. */
export interface ServerInfo {
  version: string;
  stamped: boolean;
  mode: "docker" | "binary" | "none";
  mode_note?: string;
  latest?: { version: string; prerelease: boolean; published_at: string; notes: string };
  latest_error?: string;
  update_available: boolean;
  state?: UpdateState;
  pending_approval_id?: string;
  approvals_required: boolean;
}

/** updateDone reports whether an update has finished, one way or the other. */
export function updateDone(state?: UpdateState): boolean {
  return !state || state.phase === "healthy" || state.phase === "rolled_back" || state.phase === "failed";
}
