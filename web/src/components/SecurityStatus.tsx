import type { DefenderStatus, FirewallProfileState } from "../api/types";
import { relative } from "../pages/Devices";

/** The part of an inventory document this section reads. Older agents send
 * neither block, which is "not reported", never "off". */
interface SecurityDocument {
  defender?: DefenderStatus;
  firewall?: FirewallProfileState[];
}

const NOT_REPORTED = "not reported";

function onOff(value: boolean | undefined): string {
  return value === undefined ? NOT_REPORTED : value ? "on" : "off";
}

/** signatureAge says how old the signatures are now, measured the way the
 * defender_signatures_within rule measures it: from the update time, not
 * from an age the agent reported when it last spoke. */
function signatureAge(updatedAt: string | undefined): string {
  if (!updatedAt) return NOT_REPORTED;
  return `updated ${relative(updatedAt)}`;
}

export function SecurityStatus({ document }: { document: unknown }) {
  const doc = (document ?? {}) as SecurityDocument;
  const d = doc.defender;
  const firewall = new Map((doc.firewall ?? []).map((p) => [p.profile, p.enabled]));
  const firewallReported = doc.firewall !== undefined;

  return (
    <section className="security" aria-labelledby="security-heading">
      <h2 id="security-heading">Security</h2>
      <dl className="detail__grid">
        <div>
          <dt>Defender</dt>
          <dd>{d ? d.running_mode || "running mode not reported" : NOT_REPORTED}</dd>
        </div>
        <div>
          <dt>Real-time protection</dt>
          <dd>{d ? onOff(d.antivirus_enabled && d.realtime_enabled) : NOT_REPORTED}</dd>
        </div>
        <div>
          <dt>Tamper Protection</dt>
          <dd>{d ? onOff(d.tamper_protected) : NOT_REPORTED}</dd>
        </div>
        <div>
          <dt>Signatures</dt>
          <dd>
            {d ? (
              <>
                <span className="mono">{d.signature_version || "—"}</span>, {signatureAge(d.signature_updated_at)}
              </>
            ) : (
              NOT_REPORTED
            )}
          </dd>
        </div>
        <div>
          <dt>Last scans</dt>
          <dd>
            {d
              ? `quick ${d.last_quick_scan_at ? relative(d.last_quick_scan_at) : "never"}, full ${
                  d.last_full_scan_at ? relative(d.last_full_scan_at) : "never"
                }`
              : NOT_REPORTED}
          </dd>
        </div>
        {(["domain", "private", "public"] as const).map((profile) => (
          <div key={profile}>
            <dt>Firewall, {profile}</dt>
            <dd>{firewallReported ? onOff(firewall.get(profile)) : NOT_REPORTED}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}
