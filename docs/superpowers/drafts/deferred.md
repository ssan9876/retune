# Deferred items — why they are not built overnight, and what each needs

| item | why deferred | what it needs from you |
|---|---|---|
| BitLocker + Windows Update verification on real hardware | standing rule: no disk encrypted, no update policy changed on this machine | a disposable Windows VM (Hyper-V or similar) the verification can run on |
| Authenticode-signed MSI and agent | needs a code-signing certificate from a CA (a purchase) | a certificate (or a decision to use a self-signed one for internal deployments only) |
| TPM-backed device keys | touches the machine's TPM; changing key storage on the one real device is not reversible without re-enrolment | approval to experiment on a VM, and a decision on the fallback for TPM-less machines |
| macOS and Linux agents | the largest item; the Windows-specific seams (service control, registry, winget, WMI) need separating first | which OS matters first, and a machine to test on |
| Zero-touch provisioning (Autopilot-like) | needs an OEM or imaging integration point Retune does not have | how your devices arrive (imaging, OEM, hand-built) |
| Multi-tenancy UI | the data model is tenant-scoped (M11); the UI and tenant administration are product decisions (who creates tenants, billing, isolation of the CA) | whether Retune is single-org or a service for many orgs |
| End-user self-service portal | needs a component in the user's session (tray app or local web page) | whether end users should install software themselves at all |
| Console at phone width | needs a real browser check | nothing — can be done in the morning with the browser tools |
| Load testing | needs a target fleet size and a machine to run a load generator | the fleet size you care about |
