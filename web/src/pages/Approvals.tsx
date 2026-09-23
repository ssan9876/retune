import { useState } from "react";

import type { Approval } from "../api/approvals";
import { api } from "../api/client";
import { StatusDot } from "../components/StatusDot";
import { Button, EmptyState, ErrorNote, Spinner } from "../components/ui";
import { useList } from "../hooks/useList";
import { useSession } from "../session/SessionContext";
import { relative } from "./Devices";

const DOT: Record<Approval["status"], string> = {
  pending: "queued",
  approved: "active",
  rejected: "retired",
  expired: "expired",
  failed: "failed",
};

/** Approvals lists requests held for a second administrator: every wipe, and
 * code sent to more devices than the threshold. Whoever asked can withdraw a
 * request but not approve it. */
export default function Approvals() {
  const { admin, canWrite } = useSession();
  const [status, setStatus] = useState("pending");
  const { items, loading, error, reload } = useList<Approval>("/approvals", { status: status || undefined });
  const [actionError, setActionError] = useState<unknown>(null);

  async function decide(approval: Approval, verb: "approve" | "reject") {
    const own = approval.requested_by === admin?.email;
    const question =
      verb === "approve"
        ? `Approve "${approval.summary}", requested by ${approval.requested_by}? It is carried out at once.`
        : own
          ? `Withdraw "${approval.summary}"?`
          : `Reject "${approval.summary}"?`;
    if (!window.confirm(question)) return;
    setActionError(null);
    try {
      const res = await api.post<{ approval: Approval }>(`/approvals/${approval.id}/${verb}`, {});
      if (res.approval.status === "failed") {
        setActionError(new Error(`Approved, but it could not be carried out: ${res.approval.result?.error ?? "unknown error"}`));
      }
    } catch (err) {
      setActionError(err);
    }
    reload();
  }

  return (
    <>
      <div className="content__head">
        <h1>Approvals</h1>
        <select value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Show">
          <option value="pending">Waiting</option>
          <option value="">All</option>
        </select>
      </div>

      <p className="hint" style={{ marginTop: 0 }}>
        With two-person approval on, every wipe, and a script or app sent to more devices than the threshold, waits
        here until an administrator other than the one who asked approves it. Requests lapse after a day.
      </p>

      <ErrorNote error={error ?? actionError} />
      {loading ? <Spinner /> : null}
      {!loading && items.length === 0 ? (
        <EmptyState title={status === "pending" ? "Nothing is waiting for approval." : "No requests yet."} />
      ) : null}

      {items.length > 0 ? (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Request</th>
                <th>Requested by</th>
                <th>Asked</th>
                <th>State</th>
                <th>Decided by</th>
                {canWrite ? <th></th> : null}
              </tr>
            </thead>
            <tbody>
              {items.map((approval) => {
                const own = approval.requested_by === admin?.email;
                return (
                  <tr key={approval.id}>
                    <td>{approval.summary}</td>
                    <td>{approval.requested_by}</td>
                    <td>{relative(approval.created_at)}</td>
                    <td>
                      <StatusDot status={DOT[approval.status]} label={approval.status} />
                      {approval.result?.error ? <div className="hint">{approval.result.error}</div> : null}
                    </td>
                    <td>{approval.decided_by ?? ""}</td>
                    {canWrite ? (
                      <td>
                        {approval.status === "pending" ? (
                          <div className="actions" style={{ marginTop: 0 }}>
                            {!own ? (
                              <Button variant="primary" onClick={() => void decide(approval, "approve")}>
                                Approve
                              </Button>
                            ) : null}
                            <Button variant="quiet" onClick={() => void decide(approval, "reject")}>
                              {own ? "Withdraw" : "Reject"}
                            </Button>
                          </div>
                        ) : null}
                      </td>
                    ) : null}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : null}
    </>
  );
}
