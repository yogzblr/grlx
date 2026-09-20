# Envoy DMZ gateway (workstream H)

`envoy.yaml` is the reference config for
`docs/design/grlx-envoy-enrollment-design.md` — Envoy sitting at the DMZ
edge in front of nats-server's websocket listener and a recipe-download
route, both gated by `jwt_authn`, plus an ungated, rate-limited
`/v1/enroll` route. Read the file's own header comment first; this file
covers what a deployer needs to fill in before it's usable.

**FLAG FOR SECURITY REVIEW** — see the task brief this was built from.
Treat this as a reviewed starting point, not a drop-in production config.

## Before deploying this

- **TLS material**: `/etc/envoy/tls/dmz-cert.pem`/`dmz-key.pem` are
  placeholder paths for the DMZ edge's own downstream certificate (what
  sprouts' `wss://` connections terminate against) — not farmer's own
  cert (`config.CertFile`/`KeyFile`), which is used for the *upstream*
  hop to farmer/nats-server instead.
- **Upstream hostnames**: `farmer.internal` throughout the `clusters:`
  section is a placeholder. Point it at wherever farmer/nats-server
  actually run relative to this Envoy instance.
- **Ports**: `5405` (farmer API / recipe download interim target) and
  `5407` (nats-server websocket) match this repo's config defaults
  (`config.FarmerAPIPort`, `config.FarmerWSPort`) — keep them in sync if
  those are overridden at deploy time.
- **JWKS endpoint** — the biggest open gap, called out in `envoy.yaml`'s
  header comment: sprout JWTs are NATS User JWTs
  (`github.com/nats-io/jwt/v2`), signed with the tenant Account's Ed25519
  NKey signing key, not published as a standard JWKS document anywhere in
  this repo today. `remote_jwks` in the config points at a
  `/.well-known/jwks.json` path on farmer's API server that doesn't exist
  yet. This needs one of:
  - a new handler on farmer's existing HTTPS API
    (`internal/api`/`cmd/farmer/main.go`) that derives an OKP/Ed25519 JWK
    from `internal/pki/jwtauth.go`'s tenant Account signing key and keeps
    it in sync across signing-key rotation, or
  - a `local_jwks` fed by the same key material at deploy time, refreshed
    out-of-band.

  Until one of those lands, the two `jwt_authn`-gated routes in this
  config will reject every connection — that's a safe failure mode (fails
  closed), but it means this config isn't yet end-to-end functional on
  its own.
- **Envoy version**: confirm the deployed Envoy build supports `EdDSA` in
  `jwt_authn` (added in a relatively recent release) — NATS User JWTs are
  Ed25519-signed, not RS256/ES256.
- **Recipe route target**: `/v1/recipes` currently proxies to farmer's own
  `GET /files/` (`internal/api/handlers/recipes.go`) as the nearest
  existing analogue. `docs/design/grlx-fork-roadmap.md` workstream I
  ("Recipe storage migration") describes a dedicated, non-DMZ recipe
  service this route is meant to front instead — repoint the
  `recipe_service` cluster once that exists.
- **Rate limiting on `/v1/enroll`**: the `local_ratelimit` filter here is
  per-Envoy-worker and per-instance — real protection at scale (multiple
  Envoy replicas) needs a shared/global rate-limit service, not this
  config alone.

## What this pairs with in the Go codebase

- `internal/api/handlers/enroll.go` / `internal/api/routers.go` — the
  farmer-side `POST /v1/enroll` handler this config's enroll route
  proxies to.
- `internal/pki/enroll.go` — the token validation, atomic redemption, and
  minting logic behind that handler.
- `internal/pki/nats.go`'s `ConfigureNats` — the nats-server websocket
  listener (`config.FarmerWSPort`) this config's default route proxies
  to.
