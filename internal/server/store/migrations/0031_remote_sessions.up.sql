-- Remote sessions: an administrator's interactive PowerShell on a device.
-- Every chunk typed and written is kept, in order: the transcript is the
-- record of what was done.
CREATE TABLE remote_sessions (
    id          uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenants(id),
    device_id   uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    started_by  text NOT NULL,
    reason      text NOT NULL,
    status      text NOT NULL DEFAULT 'waiting' CHECK (status IN ('waiting', 'active', 'ended')),
    created_at  timestamptz NOT NULL,
    started_at  timestamptz,
    ended_at    timestamptz,
    end_reason  text NOT NULL DEFAULT ''
);
CREATE INDEX remote_sessions_device ON remote_sessions (tenant_id, device_id, created_at DESC);

CREATE TABLE remote_session_chunks (
    seq         bigserial PRIMARY KEY,
    session_id  uuid NOT NULL REFERENCES remote_sessions(id) ON DELETE CASCADE,
    stream      text NOT NULL CHECK (stream IN ('in', 'out', 'err')),
    data        text NOT NULL,
    at          timestamptz NOT NULL
);
CREATE INDEX remote_session_chunks_session ON remote_session_chunks (session_id, seq);
