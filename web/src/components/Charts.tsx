import type { ReactNode } from "react";
import { Link } from "react-router-dom";

import "./Charts.css";

/** Every chart here is hand-drawn SVG: the shapes are a ring, a bar and a
 * column, none of which is worth a charting library, and a library's default
 * palette would fight the status colours the rest of the console uses.
 *
 * The rule they all follow: colour is never the only carrier. Each chart is
 * paired with its own numbers - a legend, a value at the end of a bar, a
 * caption - so the page still answers the question in a screen reader, in
 * print, and to anyone who cannot tell the two reds apart. */

export type Segment = { label: string; value: number; tone: string };

const TONE_VAR: Record<string, string> = {
  compliant: "--status-active",
  active: "--status-active",
  succeeded: "--status-active",
  stale: "--status-stale",
  unknown: "--status-stale",
  pending: "--status-stale",
  non_compliant: "--status-retired",
  retired: "--status-retired",
  failed: "--status-retired",
  not_evaluated: "--status-neutral",
  neutral: "--status-neutral",
};

function colorFor(tone: string): string {
  return `var(${TONE_VAR[tone] ?? "--status-neutral"})`;
}

/** Donut shows a whole split into parts, with the headline in the hole. An
 * empty total draws one grey ring rather than nothing, so the tile keeps its
 * shape on a fleet that has not reported yet. */
export function Donut({
  segments,
  centre,
  caption,
}: {
  segments: Segment[];
  centre: ReactNode;
  caption: string;
}) {
  const total = segments.reduce((sum, s) => sum + s.value, 0);
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;

  return (
    <div className="chart chart--donut">
      <div className="donut">
        <svg viewBox="0 0 140 140" role="img" aria-label={caption}>
          <circle className="donut__track" cx="70" cy="70" r={radius} strokeWidth="18" />
          {total > 0
            ? segments
                .filter((s) => s.value > 0)
                .map((s) => {
                  const length = (s.value / total) * circumference;
                  const dash = `${length} ${circumference - length}`;
                  const start = -offset;
                  offset += length;
                  return (
                    <circle
                      key={s.label}
                      cx="70"
                      cy="70"
                      r={radius}
                      strokeWidth="18"
                      stroke={colorFor(s.tone)}
                      strokeDasharray={dash}
                      strokeDashoffset={start}
                      fill="none"
                    />
                  );
                })
            : null}
        </svg>
        <div className="donut__centre">{centre}</div>
      </div>
      <ul className="legend">
        {segments.map((s) => (
          <li key={s.label}>
            <span className="legend__swatch" style={{ background: colorFor(s.tone) }} aria-hidden="true" />
            <span className="legend__label">{s.label}</span>
            <b>{s.value}</b>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** StackBar is one bar split into its parts, for a whole that is a sequence -
 * how recently the fleet checked in - rather than a set of unrelated slices. */
export function StackBar({ segments, caption }: { segments: Segment[]; caption: string }) {
  const total = segments.reduce((sum, s) => sum + s.value, 0);
  return (
    <div className="chart">
      <div className="stackbar" role="img" aria-label={caption}>
        {total === 0 ? <span className="stackbar__empty" /> : null}
        {segments
          .filter((s) => s.value > 0)
          .map((s) => (
            <span
              key={s.label}
              className="stackbar__part"
              style={{ width: `${(s.value / total) * 100}%`, background: colorFor(s.tone) }}
            />
          ))}
      </div>
      <ul className="legend legend--row">
        {segments.map((s) => (
          <li key={s.label}>
            <span className="legend__swatch" style={{ background: colorFor(s.tone) }} aria-hidden="true" />
            <span className="legend__label">{s.label}</span>
            <b>{s.value}</b>
          </li>
        ))}
      </ul>
    </div>
  );
}

export type BarRow = { label: string; value: number; to?: string };

/** BarList ranks things against each other: bars are drawn against the
 * largest row, not the total, because the question is "which is biggest",
 * not "what share of the whole is this". */
export function BarList({ rows, empty }: { rows: BarRow[]; empty: string }) {
  if (rows.length === 0) return <p className="chart__empty">{empty}</p>;
  const max = Math.max(...rows.map((r) => r.value), 1);
  return (
    <ul className="barlist">
      {rows.map((row) => (
        <li key={row.label}>
          <span className="barlist__label mono">
            {row.to ? <Link to={row.to}>{row.label}</Link> : row.label}
          </span>
          <span className="barlist__track">
            <span className="barlist__fill" style={{ width: `${(row.value / max) * 100}%` }} />
          </span>
          <b>{row.value}</b>
        </li>
      ))}
    </ul>
  );
}

export type Column = { label: string; value: number };

/** Columns is the trend: one column per day, labelled at its ends only. The
 * tallest column sets the scale, so a quiet month is not flattened into a
 * line by one busy day in a different chart. */
export function Columns({ data, caption }: { data: Column[]; caption: string }) {
  if (data.length === 0) return <p className="chart__empty">Nothing enrolled yet.</p>;
  const max = Math.max(...data.map((d) => d.value), 1);
  const total = data.reduce((sum, d) => sum + d.value, 0);
  return (
    <div className="chart">
      <div className="columns" role="img" aria-label={`${caption}: ${total} in total`}>
        {data.map((d) => (
          <span
            key={d.label}
            className={`columns__bar${d.value === 0 ? " columns__bar--zero" : ""}`}
            style={{ height: `${Math.max((d.value / max) * 100, 2)}%` }}
            title={`${d.label}: ${d.value}`}
          />
        ))}
      </div>
      <div className="columns__axis">
        <span>{data[0]?.label}</span>
        <span>{total} enrolled</span>
        <span>{data[data.length - 1]?.label}</span>
      </div>
    </div>
  );
}

/** Kpi is one headline number with its name, and optionally a line of
 * context under it - the number that answers the question, and the sentence
 * that says whether the answer is good. */
export function Kpi({
  label,
  value,
  note,
  tone,
  to,
}: {
  label: string;
  value: ReactNode;
  note?: string;
  tone?: string;
  to?: string;
}) {
  const body = (
    <>
      <span className="kpi__label">{label}</span>
      <span className="kpi__value" style={tone ? { color: colorFor(tone) } : undefined}>
        {value}
      </span>
      {note ? <span className="kpi__note">{note}</span> : null}
    </>
  );
  return to ? (
    <Link className="kpi kpi--link" to={to}>
      {body}
    </Link>
  ) : (
    <div className="kpi">{body}</div>
  );
}
