# M19 — Uploaded application packages (MSI/EXE), detection rules, supersedence

Status: built in the app-packages PR, with the changes listed under "As built" below. Originally self-approved overnight under the user's standing directive; decisions ledgered for morning review. Builds on M1–M18 (extends M9's `app` item kind). **No package is installed on this machine during implementation or overnight verification.**

## 1. What and why

M9 deploys winget packages only. Most line-of-business software is an MSI or a setup EXE that is not in any winget source. This milestone lets an administrator upload a package, describe how to install and detect it, and deploy it through the same `app` item kind, assignment engine, install/uninstall intents and status reporting M9 built.

The end-user self-service portal ("available" apps a user installs themselves) is **not** in this milestone: it needs a component in the user's session on the device (a tray app or local web page) and is its own milestone.

## 2. Model

- An app gains `source`: `winget` (M9, unchanged) or `package`.
- A `package` app version carries: the uploaded file (≤ 2 GiB, stored under `DATA_DIR/app-packages/<app-id>/<version>/<original-name>`, SHA-256 recorded at upload — the M10 artifact pattern), `installer_type` (`msi` | `exe`), `install_args` / `uninstall_command` (EXE; MSI uses fixed `msiexec /i <file> /qn /norestart` and `msiexec /x <product-code> /qn /norestart`), `success_exit_codes` (default `0, 3010, 1641`; 3010/1641 mean "succeeded, reboot required" and are reported as such), `timeout_seconds` (60–7200), and one **detection rule**.
- Versions are immutable (as in M9); editing means uploading a new version.
- **Supersedence:** a version may name the version it supersedes (`supersedes_version_id`). A device that has the superseded version detected is upgraded by running the new install (optionally uninstalling the old first: `uninstall_previous` bool).

## 3. Detection rules

One per version, evaluated by the agent before and after install:

| rule | fields | detected when |
|---|---|---|
| `msi_product_code` | `product_code` (GUID), optional `min_version` | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\<code>` (and the WOW6432Node view) exists, with `DisplayVersion` ≥ `min_version` if given |
| `registry` | `hive` (HKLM), `key`, optional `value`, optional `equals` / `version_at_least` | key (and value) exists and matches |
| `file` | `path` (environment variables allowed), optional `version_at_least` (file version resource) | file exists and matches |

For MSI uploads the server does not parse the MSI; the administrator supplies the product code (the console explains where to find it). Parsing MSI tables server-side is deferred.

## 4. Agent

The M9 `apps.Syncer` gains a `package` path beside winget: fetch the definition, check detection; if install intent and not detected → download the file (hash-verified against the recorded SHA-256, the M10 client pattern, into `DATA_DIR/app-cache/`), run the installer as SYSTEM with the timeout, map exit codes, re-check detection, report; if uninstall intent and detected → run the uninstall, re-check, report. The cache keeps the file until the version is no longer assigned. A reboot-required result is reported `succeeded` with detail "installed; a restart is required to finish" — Retune does not reboot on its own.

## 5. Server and console

- Upload endpoint for package versions (raw body, as agent versions do, ≤ 2 GiB via `MaxBytesReader`), agent download endpoint gated on `DeviceHasItem` (M9/M10 pattern).
- Console Apps page: "Add app" chooses winget or package; the package form has the upload, installer type, arguments, exit codes, timeout, detection rule builder, and supersedes selector.

## 6. Testing

Detection rules as pure functions over a fake registry/filesystem reader; exit-code mapping; the syncer's package path with a fake runner and fake downloader (install when missing, skip when detected, uninstall, supersede with and without uninstalling the previous, hash mismatch refusal, timeout); server upload/download gating; console forms. No real installer is ever executed.

## As built

- **Storage.** Uploads are content-addressed (`DATA_DIR/app-packages/<sha256>`) and uploaded before the app form is saved: `POST /app-packages?file_name=` returns the hash that the app version names. Unused files are pruned after 24 hours by the `apps.prune_packages` sweeper job. The upload's read deadline is extended to two hours.
- **Timeouts.** The agent timeout range is M9's 60–14400 seconds, not 60–7200.
- **Agent cache.** The agent deletes the installer right after running it rather than caching it: re-downloading on a retry is cheaper than tracking which cached files are still assigned.
- **Supersedence.** This is within one app (a new version replaces the old). `uninstall_previous` removes only the version the agent itself last installed (`InstalledByAgent` in its local state). Cross-app supersedence, "app B replaces app A", is not built.
- **Detection.** The registry `version_at_least` compares the value, and MSI detection reads `DisplayVersion`. Both registry views are checked.
