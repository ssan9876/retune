# M16 — Certificate, Wi-Fi and VPN profile settings

Status: self-approved overnight under the user's standing directive; decisions ledgered for morning review. Builds on M1–M15. **No certificate, Wi-Fi or VPN setting is applied to this machine** — network changes could cut the machine off; handlers are built and tested with fakes only.

## 1. What and why

Intune's most-used configuration profiles after security baselines are the ones that get a device onto the organisation's network: trusted root certificates, Wi-Fi profiles and VPN connections. Retune's configuration profiles (M7/M8) cover registry, services, files, local groups, firewall, Windows Update and BitLocker. This milestone adds three setting kinds to the same engine, so they inherit assignment, conflict detection, status reporting and revert-on-removal.

## 2. Setting kinds

### 2.1 `certificate`

| field | meaning |
|---|---|
| `store` | `root` (LocalMachine\Root), `ca` (LocalMachine\CA, intermediates), `trusted_publisher` (LocalMachine\TrustedPublisher) |
| `certificate_pem` | one PEM certificate, ≤ 16 KiB, must parse as X.509; **private keys are refused** (a PEM containing a `PRIVATE KEY` block is invalid) |

Identity key `certificate:<store>:<sha1 thumbprint>` (computed server-side at validation and stored with the setting). `Get`: present in the store by thumbprint. `Set`: `Import-Certificate` into `Cert:\LocalMachine\<store>` from a temp file. Revert: remove only the certificate this setting added (if it was already present before first apply, revert leaves it — the engine's captured prior state says so).

Client certificates with private keys (PKCS#12) and SCEP/PKCS certificate issuance are out of scope: they need a key-protection story (the PFX password, or a CA connector) that this milestone does not have.

### 2.2 `wifi`

| field | meaning |
|---|---|
| `ssid` | 1–32 bytes |
| `security` | `open`, `wpa2_personal`, `wpa3_personal`, `wpa2_enterprise` |
| `passphrase` | required for the personal types, 8–63 chars; sealed at rest with `secrets.Key` and delivered to the agent only in the profile definition over mTLS; never returned by the admin API after creation (write-only field, shown as "set") |
| `auto_connect` | bool, default true |
| `hidden` | bool, default false |
| `eap` (enterprise only) | `peap_mschapv2` or `eap_tls`, plus `server_names` (list) and `trusted_root_thumbprint` (a `certificate` setting's thumbprint) |

Identity key `wifi:<ssid>`. The agent renders a WLAN profile XML (pure function, golden-file tested) and applies it with `netsh wlan add profile filename=<tmp> user=all`; `Get` reads `netsh wlan show profile name=<ssid> key=clear` and compares the fields it manages. Revert deletes the profile (`netsh wlan delete profile name=<ssid>`) unless it pre-existed. Machines without a wireless adapter report the setting `not_applicable` rather than failed.

### 2.3 `vpn`

| field | meaning |
|---|---|
| `name` | connection name, 1–64 |
| `server` | hostname or IP |
| `tunnel` | `ikev2`, `sstp`, `l2tp` (l2tp requires `psk`, sealed like the Wi-Fi passphrase) |
| `authentication` | `eap`, `machine_certificate`, `mschapv2` |
| `split_tunneling` | bool |
| `dns_suffix` | optional |
| `all_users` | always true (device-wide) |

Identity key `vpn:<name>`. `Add-VpnConnection -AllUserConnection …` / `Set-VpnConnection` / `Remove-VpnConnection -AllUserConnection -Force` for revert; `Get` from `Get-VpnConnection -AllUserConnection -Name`.

## 3. Secrets in settings

Wi-Fi passphrases and L2TP pre-shared keys are the first secrets stored inside profile settings. They are sealed with `secrets.Key` (additional data `"<profile-id>/<setting-key>"`) in the profile version's stored JSON, replaced by `{"sealed": true}` in every admin API response, and unsealed only when the agent API builds that device's profile definition. Audit records never contain them.

## 4. Console

The profile editor gains the three kinds: a PEM paste box with the parsed subject, issuer, expiry and thumbprint shown before saving; Wi-Fi and VPN forms with write-only secret inputs ("Change passphrase").

## 5. Testing

Protocol validation per kind (incl. PEM with a private key refused, SSID length in bytes, passphrase bounds, enterprise requiring EAP fields); server sealing round-trip and redaction in every admin response; agent handlers with fake PowerShell/netsh runners covering get/set/revert/pre-existing/not-applicable; WLAN XML golden files for each security type. No on-machine application.
