import { useCallback, useEffect, useState } from "react";
import type { ReactNode } from "react";

import { api } from "../api/client";
import type { AlertDelivery, AlertRule, FiringAlert, NotificationChannel } from "../api/types";
import { StatusDot } from "../components/StatusDot";
import { Button, Dialog, EmptyState, ErrorNote, Field, Spinner } from "../components/ui";
import { useSession } from "../session/SessionContext";
import "./Alerts.css";

/** The rule kinds the server understands, with the one parameter each takes.
 *  Keeping the list here rather than deriving it from the rules already
 *  stored means the form can offer a kind nobody has used yet. */
const RULE_KINDS = [
  { value: "device_non_compliant", label: "A device is non-compliant" },
  { value: "device_stale", label: "A device stops checking in" },
  { value: "deployment_failed", label: "A deployment fails" },
] as const;

const ITEM_KINDS = [
  { value: "", label: "Any kind" },
  { value: "script", label: "Scripts" },
  { value: "app", label: "Apps" },
  { value: "profile", label: "Configuration profiles" },
  { value: "agent", label: "Agent versions" },
];

function Section({ title, hint, action, children }: {
  title: string;
  hint?: string;
  action?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="alerts__section">
      <div className="alerts__head">
        <div>
          <h2>{title}</h2>
          {hint ? <p className="alerts__hint">{hint}</p> : null}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}

function when(iso: string): string {
  return new Date(iso).toLocaleString();
}

export default function Alerts() {
  const { canWrite } = useSession();
  const [firing, setFiring] = useState<FiringAlert[]>([]);
  const [rules, setRules] = useState<AlertRule[]>([]);
  const [channels, setChannels] = useState<NotificationChannel[]>([]);
  const [deliveries, setDeliveries] = useState<AlertDelivery[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [note, setNote] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      // Four small listings, asked for together: the page is one answer, not
      // four that arrive at different times.
      const [f, r, c, d] = await Promise.all([
        api.get<{ items: FiringAlert[] }>("/alerts"),
        api.get<{ items: AlertRule[] }>("/alert-rules"),
        api.get<{ items: NotificationChannel[] }>("/notification-channels"),
        api.get<{ items: AlertDelivery[] }>("/alert-deliveries"),
      ]);
      setFiring(f.items);
      setRules(r.items);
      setChannels(c.items);
      setDeliveries(d.items);
      setError(null);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const [channelOpen, setChannelOpen] = useState(false);
  const [ruleOpen, setRuleOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState<unknown>(null);

  const [channelName, setChannelName] = useState("");
  const [channelKind, setChannelKind] = useState<"email" | "webhook">("email");
  const [recipients, setRecipients] = useState("");
  const [webhookURL, setWebhookURL] = useState("");
  const [webhookSecret, setWebhookSecret] = useState("");

  const [ruleName, setRuleName] = useState("");
  const [ruleKind, setRuleKind] = useState<string>(RULE_KINDS[0].value);
  const [ruleHours, setRuleHours] = useState("24");
  const [ruleItemKind, setRuleItemKind] = useState("");
  const [ruleChannel, setRuleChannel] = useState("");

  async function addChannel() {
    setBusy(true);
    setFormError(null);
    try {
      const config =
        channelKind === "email"
          ? { to: recipients.split(",").map((s) => s.trim()).filter(Boolean) }
          : { url: webhookURL.trim() };
      await api.post("/notification-channels", {
        name: channelName,
        kind: channelKind,
        config,
        ...(channelKind === "webhook" && webhookSecret ? { secret: webhookSecret } : {}),
      });
      setChannelOpen(false);
      setChannelName("");
      setRecipients("");
      setWebhookURL("");
      setWebhookSecret("");
      await load();
    } catch (err) {
      setFormError(err);
    } finally {
      setBusy(false);
    }
  }

  async function addRule() {
    setBusy(true);
    setFormError(null);
    try {
      const params =
        ruleKind === "device_stale"
          ? { hours: Number(ruleHours) }
          : ruleKind === "deployment_failed" && ruleItemKind
            ? { item_kind: ruleItemKind }
            : {};
      await api.post("/alert-rules", {
        name: ruleName,
        kind: ruleKind,
        params,
        channel_id: ruleChannel || channels[0]?.id,
      });
      setRuleOpen(false);
      setRuleName("");
      await load();
    } catch (err) {
      setFormError(err);
    } finally {
      setBusy(false);
    }
  }

  async function act(run: () => Promise<unknown>, message?: string) {
    setFormError(null);
    setNote(null);
    try {
      await run();
      if (message) setNote(message);
      await load();
    } catch (err) {
      setFormError(err);
    }
  }

  const canAddRule = canWrite && channels.length > 0;

  return (
    <>
      <div className="content__head">
        <h1>Alerts</h1>
        {canWrite ? (
          <div className="actions" style={{ marginTop: 0 }}>
            <Button onClick={() => setChannelOpen(true)}>Add channel</Button>
            <Button variant="primary" disabled={!canAddRule} onClick={() => setRuleOpen(true)}>
              Add rule
            </Button>
          </div>
        ) : null}
      </div>

      <ErrorNote error={error ?? formError} />
      {note ? <p className="alerts__note">{note}</p> : null}
      {loading ? <Spinner /> : null}

      <Section title="Firing now" hint="What each rule is currently unhappy about.">
        {firing.length === 0 ? (
          <EmptyState title="Nothing is firing.">
            {rules.length === 0 ? "No rules are watching for anything yet." : "Every rule is quiet."}
          </EmptyState>
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>What is wrong</th>
                  <th>Since</th>
                  <th>Told anyone</th>
                </tr>
              </thead>
              <tbody>
                {firing.map((alert) => (
                  <tr key={`${alert.rule_id}:${alert.subject_key}`}>
                    <td>{alert.rule_name}</td>
                    <td>{alert.subject}</td>
                    <td>{when(alert.firing_since)}</td>
                    <td>
                      <StatusDot
                        status={alert.notified_at ? "succeeded" : "queued"}
                        label={alert.notified_at ? "sent" : "not sent yet"}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      <Section title="Rules" hint="Each rule watches one condition and delivers to one channel.">
        {rules.length === 0 ? (
          <EmptyState title="No rules yet.">
            {channels.length === 0
              ? "Add a channel first: a rule needs somewhere to deliver."
              : "Add a rule to be told when something goes wrong."}
          </EmptyState>
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Fires when</th>
                  <th>Delivers to</th>
                  <th>Status</th>
                  {canWrite ? <th></th> : null}
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => (
                  <tr key={rule.id}>
                    <td>{rule.name}</td>
                    <td className="alerts__muted">{rule.description}</td>
                    <td>{rule.channel_name}</td>
                    <td>
                      <StatusDot
                        status={rule.enabled ? "active" : "retired"}
                        label={rule.enabled ? "enabled" : "paused"}
                      />
                    </td>
                    {canWrite ? (
                      <td>
                        <div className="actions" style={{ marginTop: 0 }}>
                          <Button
                            variant="quiet"
                            onClick={() =>
                              void act(() =>
                                api.post(`/alert-rules/${rule.id}`, { enabled: !rule.enabled }),
                              )
                            }
                          >
                            {rule.enabled ? "Pause" : "Resume"}
                          </Button>
                          <Button
                            variant="quiet"
                            onClick={() => {
                              if (!window.confirm(`Delete the rule "${rule.name}"?`)) return;
                              void act(() => api.del(`/alert-rules/${rule.id}`));
                            }}
                          >
                            Delete
                          </Button>
                        </div>
                      </td>
                    ) : null}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      <Section title="Channels" hint="Where alerts go. A webhook's secret can be set but never read back.">
        {channels.length === 0 ? (
          <EmptyState title="No channels yet.">Add an email or webhook channel to deliver to.</EmptyState>
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Kind</th>
                  <th>Where</th>
                  <th>Status</th>
                  {canWrite ? <th></th> : null}
                </tr>
              </thead>
              <tbody>
                {channels.map((channel) => (
                  <tr key={channel.id}>
                    <td>{channel.name}</td>
                    <td>{channel.kind === "email" ? "Email" : "Webhook"}</td>
                    <td className="alerts__muted">
                      {channel.kind === "email"
                        ? (channel.config.to ?? []).join(", ")
                        : channel.config.url}
                      {channel.has_secret ? <span className="alerts__badge">signed</span> : null}
                    </td>
                    <td>
                      <StatusDot
                        status={channel.enabled ? "active" : "retired"}
                        label={channel.enabled ? "enabled" : "paused"}
                      />
                    </td>
                    {canWrite ? (
                      <td>
                        <div className="actions" style={{ marginTop: 0 }}>
                          <Button
                            variant="quiet"
                            onClick={() =>
                              void act(
                                () => api.post(`/notification-channels/${channel.id}/test`, {}),
                                `Test message sent through ${channel.name}.`,
                              )
                            }
                          >
                            Send test
                          </Button>
                          <Button
                            variant="quiet"
                            onClick={() =>
                              void act(() =>
                                api.post(`/notification-channels/${channel.id}`, {
                                  enabled: !channel.enabled,
                                }),
                              )
                            }
                          >
                            {channel.enabled ? "Pause" : "Resume"}
                          </Button>
                          <Button
                            variant="quiet"
                            onClick={() => {
                              if (!window.confirm(`Delete the channel "${channel.name}"?`)) return;
                              void act(() => api.del(`/notification-channels/${channel.id}`));
                            }}
                          >
                            Delete
                          </Button>
                        </div>
                      </td>
                    ) : null}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      <Section title="Recent deliveries" hint="Kept for 30 days, so “why did I not get an email” has an answer.">
        {deliveries.length === 0 ? (
          <EmptyState title="Nothing has been sent yet." />
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>When</th>
                  <th>Rule</th>
                  <th>Channel</th>
                  <th>Carried</th>
                  <th>Result</th>
                </tr>
              </thead>
              <tbody>
                {deliveries.map((delivery) => (
                  <tr key={delivery.id}>
                    <td>{when(delivery.at)}</td>
                    <td>{delivery.rule_name}</td>
                    <td>{delivery.channel_name}</td>
                    <td className="alerts__muted">
                      {delivery.firing} new, {delivery.resolved} resolved
                    </td>
                    <td>
                      <StatusDot status={delivery.ok ? "succeeded" : "failed"} />
                      {delivery.detail ? (
                        <span className="alerts__muted"> {delivery.detail}</span>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      <Dialog title="Add a channel" open={channelOpen} onClose={() => setChannelOpen(false)}>
        <Field label="Name">
          <input value={channelName} onChange={(event) => setChannelName(event.target.value)} />
        </Field>
        <Field label="Kind">
          <select
            value={channelKind}
            onChange={(event) => setChannelKind(event.target.value as "email" | "webhook")}
          >
            <option value="email">Email</option>
            <option value="webhook">Webhook</option>
          </select>
        </Field>
        {channelKind === "email" ? (
          <Field label="Recipients" hint="Comma separated. A distribution list beats a long list here.">
            <input value={recipients} onChange={(event) => setRecipients(event.target.value)} />
          </Field>
        ) : (
          <>
            <Field label="URL" hint="https only.">
              <input value={webhookURL} onChange={(event) => setWebhookURL(event.target.value)} />
            </Field>
            <Field
              label="Shared secret"
              hint="Optional. Signs each request as X-Retune-Signature; it is never shown again."
            >
              <input
                type="password"
                value={webhookSecret}
                onChange={(event) => setWebhookSecret(event.target.value)}
              />
            </Field>
          </>
        )}
        <ErrorNote error={formError} />
        <div className="actions">
          <Button variant="primary" disabled={busy} onClick={() => void addChannel()}>
            {busy ? "Adding…" : "Add channel"}
          </Button>
          <Button variant="quiet" onClick={() => setChannelOpen(false)}>
            Cancel
          </Button>
        </div>
      </Dialog>

      <Dialog title="Add a rule" open={ruleOpen} onClose={() => setRuleOpen(false)}>
        <Field label="Name">
          <input value={ruleName} onChange={(event) => setRuleName(event.target.value)} />
        </Field>
        <Field label="Fires when">
          <select value={ruleKind} onChange={(event) => setRuleKind(event.target.value)}>
            {RULE_KINDS.map((kind) => (
              <option key={kind.value} value={kind.value}>
                {kind.label}
              </option>
            ))}
          </select>
        </Field>
        {ruleKind === "device_stale" ? (
          <Field label="Hours of silence" hint="Between 1 and 8760.">
            <input
              type="number"
              min={1}
              max={8760}
              value={ruleHours}
              onChange={(event) => setRuleHours(event.target.value)}
            />
          </Field>
        ) : null}
        {ruleKind === "deployment_failed" ? (
          <Field label="Which deployments">
            <select value={ruleItemKind} onChange={(event) => setRuleItemKind(event.target.value)}>
              {ITEM_KINDS.map((kind) => (
                <option key={kind.value} value={kind.value}>
                  {kind.label}
                </option>
              ))}
            </select>
          </Field>
        ) : null}
        <Field label="Deliver to">
          <select value={ruleChannel} onChange={(event) => setRuleChannel(event.target.value)}>
            {channels.map((channel) => (
              <option key={channel.id} value={channel.id}>
                {channel.name}
              </option>
            ))}
          </select>
        </Field>
        <ErrorNote error={formError} />
        <div className="actions">
          <Button variant="primary" disabled={busy} onClick={() => void addRule()}>
            {busy ? "Adding…" : "Add rule"}
          </Button>
          <Button variant="quiet" onClick={() => setRuleOpen(false)}>
            Cancel
          </Button>
        </div>
      </Dialog>
    </>
  );
}
