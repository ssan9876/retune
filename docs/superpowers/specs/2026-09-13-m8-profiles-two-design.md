# M8 — Configuration Profiles II Design

**Parent spec:** `docs/superpowers/specs/2026-09-12-core-platform-design.md` (section 10, plus `bitlocker_keys` in 11 and the audit list in 6)
**Roadmap row:** `docs/superpowers/plans/2026-09-12-roadmap.md` — M8
**Builds on:** merged M1–M7.

## 1. Summary

M8 finishes the setting kinds: `firewall`, `windows_update` and `bitlocker`.
The engine, conflict detection and revert are already built, so each of these is
one `Handler` implementation plus whatever the kind needs around it.

`bitlocker` needs the most around it, because escrowing a recovery key means
the server holds something that unlocks a laptop. That key is encrypted at rest
with a server key, it is never returned by a listing, and revealing it is a
deliberate, audited act.

## 2. Decisions

| Decision | Choice | Why |
|---|---|---|
| Firewall settings | Split into two kinds, `firewall_profile` and `firewall_rule` | The parent spec lists one `firewall` kind covering both the per-profile switch and named rules. They have different identities — one per profile, one per rule name — and conflict detection works on identity, so one kind would have to carry a discriminator anyway. Two kinds make "these two profiles disagree about the Domain firewall" expressible. |
| Firewall implementation | PowerShell's `NetSecurity` cmdlets, not `netsh` | Only the cmdlets can set a rule's **Group**, which is how the parent spec says Retune's rules are tagged so they can be found and removed later. They also return JSON, which beats parsing `netsh` output. |
| `windows_update` | Composed of registry values under `HKLM\SOFTWARE\Policies`, applied by reusing the registry handler | The parent spec says it is implemented through the policy keys. Expressing it as a small translation to registry settings means one implementation of the fiddly part, and the translation is a pure function that can be tested exhaustively. |
| BitLocker encryption | The handler **never starts encryption** unless the setting explicitly requires it, and never decrypts | Encrypting a system drive is disruptive and slow; doing it because a profile was vague would be unforgivable. Turning it off on request would be worse, so `Revert` is not implemented for this kind. |
| Recovery keys at rest | AES-GCM with a server key kept beside the CA | A recovery key unlocks a laptop. Holding it in plain text in a database that gets backed up and copied is not defensible. |
| Revealing a key | A separate `POST .../reveal`, admin role only, audited every time | Reading a device list should never hand out recovery keys. Making the reveal its own act is what makes the audit entry meaningful. |
| Escrow scope | Only the recovery password protector, only for volumes the profile covers | It is the only protector that is useful to a help desk and the only one worth the risk of storing. |

## 3. `firewall_profile`

| Field | Values |
|---|---|
| `profile` | `domain`, `private`, `public` |
| `state` | `on`, `off` |

Identity: `firewall_profile:<profile>`. Reverting restores the previous state.

## 4. `firewall_rule`

| Field | Meaning |
|---|---|
| `name` | the rule's display name; also its identity |
| `direction` | `inbound` or `outbound` |
| `action` | `allow` or `block` |
| `protocol` | `tcp`, `udp` or `any` |
| `local_port` | a port, a range, or empty for any |
| `program` | a program path, or empty for any |
| `ensure` | `present` or `absent` |

Identity: `firewall_rule:<name>`.

Every rule Retune creates is put in the group **Retune**, which is how they are
recognised later. A rule with `ensure: absent` is removed **only if it is in
that group**: a profile must not be able to delete a firewall rule that
something else on the machine is relying on.

Reverting a rule Retune created removes it; reverting one it modified puts the
previous definition back.

## 5. `windows_update`

| Field | Meaning |
|---|---|
| `quality_deferral_days` | 0–30, how long quality updates wait |
| `feature_deferral_days` | 0–365, how long feature updates wait |
| `active_hours_start`, `active_hours_end` | 0–23, when the machine must not restart |
| `auto_restart` | whether Windows may restart with a user signed in |

Identity: `windows_update:policy` — there is one update policy per machine, so
two profiles configuring it differently is exactly the conflict the engine
already detects.

The handler translates the setting into registry values under
`HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate` and applies them with
the registry handler M7 built. `Test` passes when every value matches; `Revert`
restores each one to what was there before, which for a machine with no policy
means removing them.

## 6. `bitlocker`

| Field | Meaning |
|---|---|
| `require_encryption` | whether the OS drive must be encrypted |
| `method` | `XtsAes128` or `XtsAes256` |
| `escrow_recovery_key` | whether to send the recovery password to the server |

Identity: `bitlocker:os`.

`Test` passes when the OS volume's protection matches what is required and, if
escrow is on, the server already holds a key for that volume. `Set` enables
encryption only when `require_encryption` is set, adds a recovery password
protector if there is none, and escrows it. There is no `Revert`: this kind
never decrypts a drive.

A machine with no TPM, or a volume already encrypted by something else, reports
an error explaining which — it does not try to take over.

## 7. Recovery key escrow

```
POST /api/agent/v1/bitlocker   { volume_id, method, recovery_password }
```

The server encrypts the password with AES-GCM under a key held in
`DATA_DIR/secret.key` (mode 0600, created on first use, or read from
`SECRET_KEY` when `CA_KEY_SOURCE=env`), and stores the ciphertext:

```sql
CREATE TABLE bitlocker_keys (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    device_id  uuid NOT NULL REFERENCES devices(id),
    volume_id  text NOT NULL,
    ciphertext bytea NOT NULL,
    nonce      bytea NOT NULL,
    created_at timestamptz NOT NULL
);
CREATE UNIQUE INDEX bitlocker_keys_volume ON bitlocker_keys (device_id, volume_id);
```

**Losing `secret.key` makes every escrowed recovery key unreadable.** It sits in
the same volume as the CA key, which the deployment documentation already says
to back up, and the documentation now says why this one matters too.

Admin API:

- `GET /api/admin/v1/devices/{id}/bitlocker-keys` lists volumes and when each
  key was escrowed. It never includes a key.
- `POST /api/admin/v1/bitlocker-keys/{id}/reveal` returns one recovery password,
  requires the admin role, and writes an audit entry naming the admin, the
  device and the volume. A read-only admin cannot call it.

The console shows the escrowed volumes on a device, with a reveal button that
warns what it is about to do and shows the key once.

## 8. Verification

Per the decision taken before implementation: a firewall rule is created and
removed for real on an unused port, tagged `Retune`. Windows Update and
BitLocker are verified on their read paths against this machine's real state,
with their writes covered by unit tests against fakes. **No drive is encrypted
and no update policy is changed.**

## 9. Out of scope

Decrypting a drive, escrowing anything but the recovery password, rotating the
server key that protects escrowed keys, firewall rules matched on anything but
port and program, and any setting kind for macOS or Linux.
