import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { api } from "../api/client";
import type { Dashboard } from "../api/types";
import { StatusDot } from "../components/StatusDot";
import { ErrorNote, Spinner } from "../components/ui";
import "./Overview.css";

/** Stat pairs a StatusDot-labelled count with its number, the same idiom
 * FleetBar's legend uses, so a reader learns one visual language once. Given
 * a `to`, the whole stat becomes a link to the page that can explain the
 * number: the overview says how many app deployments failed, and the apps
 * page says which. The number itself is the count of failures, while the
 * page it opens is the full list - the link is a way in, not a filter. */
function Stat({ status, label, count, to }: { status: string; label: string; count: number; to?: string }) {
  const body = (
    <>
      <StatusDot status={status} label={label} /> <b>{count}</b>
    </>
  );
  if (!to) return <span className="overview__stat">{body}</span>;
  return (
    <Link className="overview__stat overview__stat--link" to={to}>
      {body}
    </Link>
  );
}

function CountTable({ columnLabel, rows }: { columnLabel: string; rows: { key: string; count: number }[] }) {
  if (rows.length === 0) {
    return <p className="overview__muted">No data reported yet.</p>;
  }
  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>{columnLabel}</th>
            <th className="numeric">Devices</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.key}>
              <td className="mono">{row.key}</td>
              <td className="numeric">{row.count}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
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

  const { devices, compliance, failed_deployments: failed, agent_versions: agentVersions, os_builds: osBuilds } =
    dashboard;

  return (
    <>
      <div className="content__head">
        <h1>Overview</h1>
      </div>

      <ErrorNote error={error} />

      <section className="overview__section">
        <h2>Fleet</h2>
        <div className="overview__stats">
          <Stat status="active" label="Active" count={devices.active} to="/devices" />
          <Stat status="stale" label="Stale" count={devices.stale} to="/devices" />
          <Stat status="retired" label="Retired" count={devices.retired} to="/devices" />
          <span className="overview__stat">
            Total <b>{devices.total}</b>
          </span>
        </div>
      </section>

      <section className="overview__section">
        <h2>Compliance</h2>
        <p className="overview__hint">Active devices only.</p>
        <div className="overview__stats">
          <Stat status="compliant" label="Compliant" count={compliance.compliant} to="/compliance" />
          <Stat status="non_compliant" label="Non-compliant" count={compliance.non_compliant} to="/compliance" />
          <Stat status="unknown" label="Unknown" count={compliance.unknown} to="/compliance" />
          <Stat status="not_evaluated" label="Not evaluated" count={compliance.not_evaluated} to="/compliance" />
        </div>
      </section>

      <section className="overview__section">
        <h2>Failed deployments</h2>
        <p className="overview__hint">Active devices only.</p>
        <div className="overview__stats">
          <Stat status="failed" label="Scripts" count={failed.script} to="/scripts" />
          <Stat status="failed" label="Apps" count={failed.app} to="/apps" />
          <Stat status="failed" label="Profiles" count={failed.profile} to="/profiles" />
          <Stat status="failed" label="Agent" count={failed.agent} to="/agent-versions" />
        </div>
      </section>

      <section className="overview__section">
        <h2>Agent versions</h2>
        <CountTable
          columnLabel="Version"
          rows={agentVersions.map((entry) => ({ key: entry.version, count: entry.count }))}
        />
      </section>

      <section className="overview__section">
        <h2>OS builds</h2>
        <CountTable
          columnLabel="Build"
          rows={osBuilds.map((entry) => ({ key: entry.build, count: entry.count }))}
        />
      </section>
    </>
  );
}
