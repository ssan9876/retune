import { useEffect, useState } from "react";
import type { ReactNode } from "react";

import { api } from "../api/client";
import type { Dashboard } from "../api/types";
import { BarList, Columns, Donut, Kpi, StackBar } from "../components/Charts";
import { ErrorNote, Spinner } from "../components/ui";
import "./Overview.css";

/** Tile is one framed answer on the dashboard: a heading, an optional line
 * saying what the numbers are counted over, and the chart itself. */
function Tile({
  title,
  hint,
  wide,
  children,
}: {
  title: string;
  hint?: string;
  wide?: boolean;
  children: ReactNode;
}) {
  return (
    <section className={`tile${wide ? " tile--wide" : ""}`}>
      <div className="tile__head">
        <h2>{title}</h2>
        {hint ? <span className="tile__hint">{hint}</span> : null}
      </div>
      {children}
    </section>
  );
}

/** shortDay is what the trend's axis and tooltips show: "15 Sep" reads at a
 * glance where "2026-09-15" has to be parsed. The date is a bucket the server
 * already chose, so it is formatted in UTC - rendering it in the browser's
 * zone would slide a column into the neighbouring day. */
function shortDay(iso: string): string {
  const [y, m, d] = iso.split("-").map(Number);
  if (!y || !m || !d) return iso;
  return new Date(Date.UTC(y, m - 1, d)).toLocaleDateString(undefined, {
    day: "numeric",
    month: "short",
    timeZone: "UTC",
  });
}

export default function Overview() {
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .get<Dashboard>("/dashboard")
      .then((next) => {
        if (cancelled) return;
        setDashboard(next);
        setError(null);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (error && !dashboard) return <ErrorNote error={error} />;
  if (!dashboard) return <Spinner />;

  const {
    devices,
    compliance,
    failed_deployments: failed,
    checkin_recency: recency,
    enrollment_trend: trend,
    agent_versions: agentVersions,
    os_builds: osBuilds,
  } = dashboard;

  const scored = compliance.compliant + compliance.non_compliant + compliance.unknown;
  // A percentage of nothing is not 0%, it is no answer: a fleet with no policy
  // assigned has not failed compliance, it has not been asked.
  const compliantPct = scored > 0 ? Math.round((compliance.compliant / scored) * 100) : null;
  const failedTotal = failed.script + failed.app + failed.profile + failed.agent;
  const enrolledRecently = trend.reduce((sum, d) => sum + d.count, 0);

  return (
    <>
      <div className="content__head">
        <h1>Overview</h1>
      </div>

      <ErrorNote error={error} />

      {/* The five numbers an administrator opens the console to check, before
          any chart explains them. */}
      <div className="kpis">
        <Kpi label="Devices" value={devices.total} note={`${devices.active} active now`} to="/devices" />
        <Kpi
          label="Compliant"
          value={compliantPct === null ? "—" : `${compliantPct}%`}
          note={
            compliantPct === null ? "no policy assigned yet" : `${compliance.compliant} of ${scored} scored`
          }
          tone={compliantPct !== null && compliantPct < 100 ? "non_compliant" : "compliant"}
          to="/compliance"
        />
        <Kpi
          label="Non-compliant"
          value={compliance.non_compliant}
          note="devices failing a policy"
          tone={compliance.non_compliant > 0 ? "non_compliant" : "compliant"}
          to="/compliance"
        />
        <Kpi
          label="Stale"
          value={devices.stale}
          note="no check-in lately"
          tone={devices.stale > 0 ? "stale" : "compliant"}
          to="/devices"
        />
        <Kpi
          label="Failed deployments"
          value={failedTotal}
          note="scripts, apps, profiles, agent"
          tone={failedTotal > 0 ? "non_compliant" : "compliant"}
          to="/scripts"
        />
      </div>

      <div className="tiles">
        <Tile title="Compliance" hint="Active devices">
          <Donut
            caption={`${compliance.compliant} compliant, ${compliance.non_compliant} non-compliant, ${compliance.unknown} unknown, ${compliance.not_evaluated} not evaluated`}
            centre={
              <>
                <span className="donut__figure">{compliantPct === null ? "—" : `${compliantPct}%`}</span>
                <span className="donut__caption">compliant</span>
              </>
            }
            segments={[
              { label: "Compliant", value: compliance.compliant, tone: "compliant" },
              { label: "Non-compliant", value: compliance.non_compliant, tone: "non_compliant" },
              { label: "Unknown", value: compliance.unknown, tone: "unknown" },
              { label: "Not evaluated", value: compliance.not_evaluated, tone: "not_evaluated" },
            ]}
          />
        </Tile>

        <Tile title="Fleet" hint="Every enrolled device">
          <Donut
            caption={`${devices.active} active, ${devices.stale} stale, ${devices.retired} retired`}
            centre={
              <>
                <span className="donut__figure">{devices.total}</span>
                <span className="donut__caption">devices</span>
              </>
            }
            segments={[
              { label: "Active", value: devices.active, tone: "active" },
              { label: "Stale", value: devices.stale, tone: "stale" },
              { label: "Retired", value: devices.retired, tone: "retired" },
            ]}
          />
        </Tile>

        <Tile title="Last check-in" hint="Active devices">
          <StackBar
            caption={`${recency.hour} within the hour, ${recency.day} within a day, ${recency.week} within a week, ${recency.older} older, ${recency.never} never`}
            segments={[
              { label: "< 1 hour", value: recency.hour, tone: "active" },
              { label: "< 1 day", value: recency.day, tone: "succeeded" },
              { label: "< 1 week", value: recency.week, tone: "stale" },
              { label: "Older", value: recency.older, tone: "failed" },
              { label: "Never", value: recency.never, tone: "neutral" },
            ]}
          />
        </Tile>

        <Tile title="Failed deployments" hint="Active devices">
          <BarList
            empty="Nothing has failed."
            rows={[
              { label: "Scripts", value: failed.script, to: "/scripts" },
              { label: "Apps", value: failed.app, to: "/apps" },
              { label: "Profiles", value: failed.profile, to: "/profiles" },
              { label: "Agent", value: failed.agent, to: "/agent-versions" },
            ]}
          />
        </Tile>

        <Tile title="Enrollments" hint="Last 30 days" wide>
          <Columns
            caption="Devices enrolled per day"
            data={trend.map((d) => ({ label: shortDay(d.day), value: d.count }))}
          />
          <p className="tile__foot">
            {enrolledRecently} device{enrolledRecently === 1 ? "" : "s"} enrolled in the last 30 days.
          </p>
        </Tile>

        <Tile title="Agent versions" hint="Active devices">
          <BarList
            empty="No data reported yet."
            rows={agentVersions.map((entry) => ({ label: entry.version, value: entry.count }))}
          />
        </Tile>

        <Tile title="OS builds" hint="Active devices">
          <BarList
            empty="No data reported yet."
            rows={osBuilds.map((entry) => ({ label: entry.build, value: entry.count }))}
          />
        </Tile>
      </div>
    </>
  );
}
