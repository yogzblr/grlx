# Wave 0 Build Status

Tracks the nine Wave 0 workstreams from `docs/claude-code-parallel-build-plan.md`
section 1 (task briefs 1.1–1.9). Six were already implemented and merged in
this repo before this dispatch ran — they were verified against the current
`master` tree and skipped rather than re-dispatched. The remaining three were
dispatched as new `claude --cloud` sessions.

| Workstream | Description | Cloud session ID | Status | Needs security review |
|---|---|---|---|---|
| B | Replace custom NKey allow-list with NATS decentralized JWT auth (Operator → Account-per-tenant → User-per-sprout) in `internal/pki/` | already merged — PR #3 (`d1c66a6`, `ccddc1d`) + PR #8 (`2e8788d`, `3dd7247`); not dispatched this run, no session ID recorded | merged | y |
| D | Queue-group fix: `nc.Subscribe` → `nc.QueueSubscribe(subject, "grlx-core", ...)` in `internal/natsapi/router.go`, plus reviewed `internal/jobs/listener.go` / `internal/facts/listener.go` fan-out | already merged — PR #2 (`26c8c05`); not dispatched this run, no session ID recorded | merged | n |
| F | Replace `internal/certs/tls.go`'s self-signed local CA (`genCACert`, `GenCert`, `RotateTLSCerts`, `forceRegenCert`) with OpenBao's PKI secrets engine + lease-renewal rotation | session_01SP3JBj5AYgDn2rh5hND3t1 | dispatched | y |
| G.1+G.3 | Windows SCM-backed service provider (`golang.org/x/sys/windows/svc/mgr`) + new registry ingredient (`golang.org/x/sys/windows/registry`) | already merged — PR #5 (`7e537ee`); not dispatched this run, no session ID recorded | merged | n |
| G.5+G.8+G.9 | Windows SMBIOS hardware/BIOS facts, PowerShell-module batch (win_servermanager, win_dsc, win_psget, win_iis, win_pki, win_snmp, win_smtp_server, win_appx), CLI-tool batch (win_firewall/netsh, win_dns_client, win_auditpol, win_powercfg, win_certutil) | already merged — PR #7 (`940368b`); not dispatched this run, no session ID recorded | merged | n |
| H.4+H.5 | Linux mount/fstab ingredient (`golang.org/x/sys/unix` + `/etc/fstab` parser, cmd fallback for NFS/CIFS) + per-user crontab ingredient | already merged — PR #4 (`d47e429`, `0f5479a`); not dispatched this run, no session ID recorded | merged | n |
| L | Sprout atomic ingredients (`probe.http`, `probe.database`, `wait`, `file.sync`, `file.line`, `file.copy` enrichment) + cook-engine primitives (`cond`, `on_exit`, variable registration/passing with `sensitive:true`, runtime context vars) | session_01USpHZSU9DKecaet3HpxduN | dispatched | y (redaction path only) |
| K | Sprout-side `SecretProvider` v1 tier behind `sdb://` (OpenBao/customer Vault via client cert, Azure/AWS/GCP via managed identity) | already merged — PR #6 (`ebe3be3`); not dispatched this run, no session ID recorded | merged | n |
| SaaS-API-scaffold | New SaaS API service: `/tenants` CRUD + status, `/tenants/{tenant_id}/enrollment-keys` (key_id/key_hash split), GORM against the `saas` schema | session_01QrtzRidQPugaJ8HgWRfoEC | dispatched | y (enrollment-key hashing/lookup) |

## Notes

- "Needs security review" reflects only workstreams whose task brief in
  `claude-code-parallel-build-plan.md` includes the literal line
  "FLAG FOR SECURITY REVIEW." Per `CLAUDE.md`, none of the flagged
  workstreams should be treated as "done" or "safe to merge" even after
  their tests pass — only as "ready for review."
- The six merged workstreams were confirmed directly against the repo
  (code present, tests present, commits/PRs identified in `git log`) rather
  than re-run, per instruction to skip work already done.
- Wave 1 workstreams (A, C, H — Envoy/enrollment) and Wave 2 (E, I, J) were
  **not** dispatched, since they depend on B (and A) being merged to `main`
  first. Dispatch them once told B and A are merged.
