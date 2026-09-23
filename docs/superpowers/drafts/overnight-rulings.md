# Overnight program ledger (2026-09-14 night)
User directive (/goal): "please work on all of this while i go to bed" — "all of this" = the remaining-work list given just before.
Integration branch: `overnight` from master 400f367. Each milestone: branch `mNN-*` off `overnight`, merged back into `overnight` after review + full suite. master and GitHub untouched (push/merge-to-master need the user's approval in the morning).

Standing constraints (from earlier milestones, still binding): no real software installed/upgraded/removed during implementation; no disk encrypted; no update policy changed; firewall-only real changes; no real service touched by implementers; controller does any on-machine verification, and overnight only read-only verification (user asleep: no screen lock, no password rotation, no wipe, no network-profile changes on this machine).

Ruling: design approval gates are self-approved overnight; every design decision is ledgered as a Ruling for morning review — user explicitly asked for unattended work — cost if wrong: rework of a milestone the user would have designed differently; mitigated by nothing reaching master.

## Queue (priority order; status updated as they complete)
- [ ] M12 compliance rules + dashboard + CSV export
- [ ] M13 remote actions: lock, collect logs, LAPS rotation, wipe (built + tested, never executed here)
- [ ] M14 alerts (webhook + SMTP), metrics endpoint, retention/pruning
- [ ] M15 Defender/antivirus status + policy
- [ ] M16 certificate / Wi-Fi / VPN profile kinds (never applied to this machine)
- [ ] M17 OIDC SSO + group-scoped admin roles
- [ ] M18 signed command payloads
- [ ] M19 apps beyond winget: uploaded MSI/EXE, supersedence, available apps + end-user portal
- [ ] M20 Windows Update rings
- [ ] Cleanup: tenant-scope FindActiveDeviceByHardware + multi-row id queries; CI publishes .sig; weak-reason tests; M10 minors
- Deferred with notes (need hardware/purchases/user decisions): BitLocker+WU VM verification, Authenticode cert, TPM keys, macOS/Linux agents, zero-touch provisioning, multi-tenancy UI, phone-width browser check, load testing

## M12 compliance (branch m12-compliance)
Ruling: compliance is a server-evaluated item kind reusing the assignment engine; no agent change — everything needed is already reported — cost if wrong: rules needing new device data (firewall state) wait for an agent change.
Ruling: results mirrored into device_item_status (compliant→succeeded, non_compliant→failed, unknown→pending) so existing rollups/console components work — cost if wrong: the generic status vocabulary shows "succeeded" where "compliant" is meant in any view that does not relabel.
Ruling: no policy versions, no grace periods, no enforcement — YAGNI for a first cut — cost if wrong: an admin edit re-evaluates immediately with no history.
Ruling: overview page becomes the landing route "/" — cost if wrong: users who expect Devices first click once more.
Ruling: CSV export guards spreadsheet formula injection by prefixing risky cells with ' — cost if wrong: a hostname legitimately starting with '-' shows a leading quote in Excel.
Ruling: sweeper re-evaluates all active devices every 15 min — catches silent devices for time-based rules — cost if wrong: load on very large fleets (untested at scale anyway).

CI 34923915132 on 400f367 (M11 follow-up, on master/GitHub): both jobs green, -race clean.

## M13 remote actions (draft spec at .superpowers/sdd/overnight/m13-spec-draft.md; branch after M12 merges)
Ruling: all four actions ride the existing command pipeline — reuses delivery, expiry, results, Commands page — cost if wrong: none identified.
Ruling: LAPS is Retune-managed (random password set via NetUserSetInfo, escrowed first) rather than driving Windows LAPS — Windows LAPS needs its own policy/AD or Entra backing that Retune does not have — cost if wrong: a customer already on Windows LAPS gets a parallel mechanism.
Ruling: escrow before set; pending→active on success, abandoned on failure — a password set but not escrowed is a lockout — cost if wrong: a pending row can outlive a set that succeeded but whose result was never delivered (shown as pending, still revealable? no — only active/superseded are revealable; a stuck pending needs an admin re-rotate).
Ruling: wipe via MDM_RemoteWipe (doWipeMethod / doWipeProtectedMethod), reported "started" before invoking; guarded by typed hostname + reason + admin role + 24h delivery expiry — cost if wrong: MDM_RemoteWipe may require the MDM bridge to be available on some SKUs; the command then fails with the WMI error, visibly.
Ruling: none of lock/rotate/wipe is executed on this machine; fakes only — user asleep, standing sandbox rules — cost: the real Windows calls are unproven until a VM pass.

## Sweeper lock-id reservations (fixed numbers in internal/server/sweeper/jobs.go)
5274001–5274003 existing; 5274004 M12 compliance; 5274005 M13 artifact retention; 5274006 M14 alerts.detect; 5274007 M14 alerts.deliver; 5274008–5274011 M14 retention jobs; 5274012+ free.

## M14 alerts/metrics/retention (draft spec at .superpowers/sdd/overnight/m14-spec-draft.md)
Ruling: alert detection polls (cursors + alert_state transitions) rather than hooking every status writer — five services write item status; one detector cannot miss a later writer — cost if wrong: up to a minute of alert latency.
Ruling: webhook targets must be https and may not resolve to loopback/link-local/private ranges unless ALERT_ALLOW_PRIVATE_TARGETS=true, checked at dial time — admin-supplied URLs are otherwise an SSRF — cost if wrong: an on-prem admin with an internal webhook receiver must set the flag.
Ruling: HMAC-SHA256 webhook signing with a per-channel secret shown once — cost: a lost secret means recreating the channel.
Ruling: email via stdlib net/smtp with server-wide SMTP config, STARTTLS required — no dependency — cost if wrong: no OAuth2 SMTP (e.g. Microsoft 365 modern auth) support.
Ruling: /metrics hand-written Prometheus text, disabled unless METRICS_TOKEN set, bearer auth — no client library dependency — cost if wrong: fewer metric types than a library would give.
Ruling: retention defaults audit 365d, commands 90d, script runs 90d, outbox 30d; 0 disables; batched deletes — cost if wrong: an operator needing longer audit history must raise the setting before the first daily run.

## M15 Defender/firewall (drafts: m15-spec-draft.md, m15-plan-draft.md)
Ruling: firewall profile state is added to inventory in M15 (not only Defender) — it closes the gap M12 could not cover and costs one more read-only WMI query — cost if wrong: none identified.
Ruling: the `defender` setting kind covers five preferences only (real-time, cloud protection, sample submission, PUA, cloud block level) — a small, well-understood surface; exclusions/ASR rules deferred — cost if wrong: admins needing ASR or exclusions wait for a later kind.
Ruling: Set re-reads after writing and reports non-compliant if the value did not stick (Tamper Protection) — never claims success it cannot see — cost: one extra PowerShell call per apply.
Ruling: Defender absent/third-party AV reports nil → rules evaluate unknown, never guessed — cost if wrong: a fleet on third-party AV shows unknown for Defender rules (correct, but noisy if such a rule is assigned).

## M14 plan drafted (m14-plan-draft.md)

## M16 certificate/Wi-Fi/VPN (draft spec m16-spec-draft.md; plan to follow)
Ruling: certificates are public-only (root/CA/trusted publisher); PKCS#12 client certs and SCEP/PKCS issuance deferred — no key-protection story yet — cost if wrong: 802.1X EAP-TLS needs a client cert that Retune cannot deliver yet.
Ruling: Wi-Fi via rendered WLAN XML + netsh (golden-file tested); VPN via the VpnClient cmdlets, all-user only — cost if wrong: per-user VPN profiles unsupported.
Ruling: Wi-Fi passphrases and L2TP PSKs sealed with secrets.Key inside profile settings, write-only in the admin API, unsealed only for the agent definition — first secrets inside settings — cost if wrong: a bug in redaction leaks a Wi-Fi passphrase to read-only admins; covered by a test on every admin response.
Ruling: devices without a wireless adapter report Wi-Fi settings not_applicable, not failed — cost if wrong: none.

## M16 plan drafted (m16-plan-draft.md)

## M18 signed command payloads (draft spec m18-spec-draft.md)
Ruling: enforcement is embedded in the agent at build time (OperationsKeysRaw), never a server setting — a compromised server must not be able to switch it off — cost if wrong: turning enforcement on or off requires shipping an agent build.
Ruling: separate operations trust list from the release trust list — different people typically hold "ship the agent" and "approve code to run" — cost: two keys to manage.
Ruling: script signatures are content-only (re-runnable anywhere); wipe signatures bind device+command+expiry ≤24h — approved code is approved code, but a destructive order must not be replayable — cost if wrong: a signed script remains runnable on any device until its key is rotated out.
Ruling: signed wipe is a two-step flow via a new awaiting_signature command state — the signature must bind the command id, which exists only after queueing — cost: one extra step for an operator in enforcing mode.
Ruling: profiles, app deployments, lock, log collection and password rotation are not signed in M18 — typed bounded handlers, or non-destructive — cost if wrong: a compromised server can still push a malicious registry/file setting or winget package.

## M17 OIDC SSO + scoped admins (draft spec m17-spec-draft.md)
Ruling: use github.com/coreos/go-oidc/v3 + golang.org/x/oauth2 rather than a hand-written JWT verifier — ID-token verification is security-critical — cost: two new dependencies (the first since M9).
Ruling: JIT provisioning, role re-derived from the groups claim at every sign-in; unmapped users refused and not created — cost if wrong: a user removed from the IdP group keeps an existing session until next login (sessions are deleted only at that point) — bounded by SESSION_TTL_HOURS.
Ruling: local login stays as break-glass unless OIDC_DISABLE_LOCAL_LOGIN=true; bootstrap-admin always works — cost if wrong: an org wanting SSO-only must remember to set the flag.
Ruling: scoped admins see devices only in their groups (404 outside), can assign only to their groups, and have read-only access to item definitions — cost if wrong: a site admin cannot author their own scripts/profiles.
Ruling: a route-enumeration test forces every admin route to declare scope-aware or unscoped-only — a new route cannot silently leak across scopes — cost: one line per new route.

## M17 plan drafted (m17-plan-draft.md)

## M19 uploaded packages (draft spec m19-spec-draft.md)
Ruling: end-user self-service portal ("available" apps) split out of M19 into its own later milestone — it needs a user-session component on the device — cost: the list item is only partly delivered by M19.
Ruling: MSI product code supplied by the admin; server does not parse MSI tables — avoids an OLE compound-file parser — cost if wrong: admins must look up the product code themselves (console explains how).
Ruling: exit codes 3010/1641 reported succeeded with "restart required"; Retune never reboots on its own — cost if wrong: installs needing a reboot stay half-finished until the user or an admin restarts.
Ruling: package files ≤ 2 GiB, hash recorded at upload and verified by the agent (M10 artifact pattern) — packages are not release-signed (M18 operations signing does not cover apps) — cost if wrong: a compromised server can push a package; noted with M18's scope.

## M20 update rings (draft spec m20-spec-draft.md)
Ruling: rings are an extension of the existing windows_update setting (deadlines, grace, pause, target release) plus patch-level compliance rules, not a new item kind — a ring is a profile with a windows_update setting assigned to a group, which the engine already does — cost if wrong: no dedicated "Rings" page; rings are managed as profiles.
Ruling: pause is time-boxed (≤35 days, the OS maximum) and expires on its own — cost: none.

## Drafts complete (all in .superpowers/sdd/overnight/): specs+plans M13–M20 (M13/M14/M15/M16/M17/M18/M19/M20), cleanup-plan-draft.md, deferred.md. Execution order after M12: M13, M14, M15, M16, M17, M18, M19, M20, cleanup. Each draft moves to docs/superpowers/{specs,plans}/ and is committed on its milestone branch when that milestone starts.
