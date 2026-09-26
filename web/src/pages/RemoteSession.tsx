import { useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";

import { api } from "../api/client";
import { StatusDot } from "../components/StatusDot";
import { Button, ErrorNote, Spinner } from "../components/ui";
import { useSession } from "../session/SessionContext";

export interface RemoteSessionInfo {
  id: string;
  device_id: string;
  started_by: string;
  reason: string;
  status: "waiting" | "active" | "ended";
  created_at: string;
  started_at?: string;
  ended_at?: string;
  end_reason?: string;
}

export interface RemoteChunk {
  seq: number;
  stream: "in" | "out" | "err";
  data: string;
  at: string;
}

interface Transcript {
  session: RemoteSessionInfo;
  chunks: RemoteChunk[];
}

const STATUS_WORDS: Record<RemoteSessionInfo["status"], string> = {
  waiting: "waiting for the device to join",
  active: "connected",
  ended: "ended",
};

/** RemoteSession is an administrator's shell on a device - PowerShell as
 * SYSTEM on Windows, zsh as root on a Mac:
 * everything typed and written is kept as the session's record. */
export default function RemoteSession() {
  const { id = "" } = useParams();
  const { admin } = useSession();
  const [session, setSession] = useState<RemoteSessionInfo | null>(null);
  const [chunks, setChunks] = useState<RemoteChunk[]>([]);
  const [line, setLine] = useState("");
  const [error, setError] = useState<unknown>(null);
  const bottom = useRef<HTMLDivElement>(null);

  // Load the transcript, then wait for more until the session ends.
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      let after = 0;
      let first = true;
      while (!cancelled) {
        try {
          const t = await api.get<Transcript>(`/remote-sessions/${id}?after=${after}${first ? "" : "&wait=1"}`);
          if (cancelled) return;
          first = false;
          setSession(t.session);
          if (t.chunks.length > 0) {
            after = t.chunks[t.chunks.length - 1].seq;
            setChunks((cur) => [...cur, ...t.chunks]);
          }
          if (t.session.status === "ended") return;
        } catch (err) {
          if (cancelled) return;
          setError(err);
          await new Promise((r) => setTimeout(r, 3000));
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [id]);

  useEffect(() => {
    bottom.current?.scrollIntoView?.({ block: "end" });
  }, [chunks.length]);

  async function send() {
    if (!line) return;
    const data = line + "\n";
    setLine("");
    try {
      await api.post(`/remote-sessions/${id}/input`, { data });
    } catch (err) {
      setError(err);
    }
  }

  async function end() {
    try {
      await api.post(`/remote-sessions/${id}/end`, {});
    } catch (err) {
      setError(err);
    }
  }

  if (!session && !error) return <Spinner />;
  const ended = session?.status === "ended";
  // Anyone who can see the device may watch; only whoever started the
  // session types in it, so everything that runs is on one name.
  const mine = !!session && admin?.email === session.started_by;
  return (
    <>
      <div className="content__head">
        <h1>Remote session</h1>
        {session && !ended ? (
          <Button variant="danger" onClick={() => void end()}>
            End session
          </Button>
        ) : null}
      </div>
      {session ? (
        <p className="hint" style={{ marginTop: 0 }}>
          <Link to={`/devices/${session.device_id}`}>Back to the device</Link> · started by {session.started_by}:{" "}
          {session.reason} ·{" "}
          <StatusDot
            status={ended ? "retired" : session.status === "active" ? "active" : "queued"}
            label={STATUS_WORDS[session.status]}
          />
          {ended && session.end_reason ? ` (${session.end_reason})` : ""}
        </p>
      ) : null}
      <p className="hint">
        PowerShell as SYSTEM on Windows, zsh as root on a Mac. A line runs when you press Enter; end a multi-line
        PowerShell block with an empty line. Everything typed and shown here is kept with the session.
      </p>
      <ErrorNote error={error} />
      <pre
        className="mono"
        aria-label="Transcript"
        style={{
          minHeight: "20rem",
          maxHeight: "60vh",
          overflow: "auto",
          background: "var(--surface)",
          border: "1px solid var(--rule)",
          borderRadius: "var(--radius)",
          padding: "var(--space-3)",
          whiteSpace: "pre-wrap",
        }}
      >
        {chunks.map((c) => (
          <span
            key={c.seq}
            style={c.stream === "in" ? { fontWeight: 600 } : c.stream === "err" ? { color: "var(--danger, #b3261e)" } : undefined}
          >
            {c.stream === "in" ? `PS> ${c.data}` : c.data}
          </span>
        ))}
        <div ref={bottom} />
      </pre>
      {!ended && !mine && session ? (
        <p className="hint">You are watching. Only {session.started_by} can type in this session.</p>
      ) : null}
      {!ended && mine ? (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void send();
          }}
          style={{ display: "flex", gap: "var(--space-2)" }}
        >
          <input
            className="mono"
            aria-label="Command"
            value={line}
            onChange={(e) => setLine(e.target.value)}
            style={{ flex: 1 }}
            autoFocus
          />
          <Button type="submit" variant="primary">
            Run
          </Button>
        </form>
      ) : null}
    </>
  );
}
