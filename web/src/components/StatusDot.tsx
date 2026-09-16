/** StatusDot pairs a colour with its word, so colour is never the only signal. */
export function StatusDot({ status, label }: { status: string; label?: string }) {
  const tone =
    status === "active" || status === "succeeded" || status === "compliant"
      ? "active"
      : status === "stale" ||
          status === "queued" ||
          status === "delivered" ||
          status === "running" ||
          status === "unknown"
        ? "stale"
        : status === "retired" ||
            status === "failed" ||
            status === "timed_out" ||
            status === "unenrolled" ||
            status === "expired" ||
            status === "replaced" ||
            status === "non_compliant"
          ? "retired"
          : "neutral";
  return <span className={`status status--${tone}`}>{label ?? status.replace(/_/g, " ")}</span>;
}
