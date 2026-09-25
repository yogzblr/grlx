# saasapi deployment reference: enrollment-key rate limit

Same precedent as `deploy/farmer/` and `deploy/envoy/`: these are reviewed
*reference* files. **saasapi's real Deployment and Helm chart are not in
this repo.** They live in the separate ops repo. Nothing in grlx applies
or renders the YAML here.

| File | What it is |
|---|---|
| `values.rate-limit.yaml` | Values block to merge into the chart's `values.yaml` |
| `deployment.env.rate-limit.yaml` | Template fragment to paste under the saasapi container's `env:` list |

## What it configures

`POST /v1/tenants/{tenant_id}/enrollment-keys` is rate-limited per tenant
(keyed by the verified JWT's `organization.id`). Two env vars tune it,
both read once at startup by `saasapi.LoadConfig`:

| Env var | Helm value | Default | Valid values |
|---|---|---|---|
| `SAASAPI_ENROLLMENT_KEY_RATE_LIMIT` | `enrollmentKeys.rateLimit.perSecond` | `1` | decimal > 0 (`0.5` = one every 2 s) |
| `SAASAPI_ENROLLMENT_KEY_RATE_BURST` | `enrollmentKeys.rateLimit.burst` | `5` | integer >= 1 |

A tenant that exceeds the limit gets `429` with error code `rate_limited`.

## How bad values fail

- **Unset or null** in values: the fragment emits no env var and saasapi
  uses the default.
- **Fractional burst** (e.g. `2.5`): `helm template`/`helm upgrade` fails
  with `enrollmentKeys.rateLimit.burst must be a whole number`.
- **Anything else invalid** (`0`, negative, not a number): the pod fails
  at startup with an error naming the env var, instead of quietly
  running with a default. With `helm upgrade --atomic` or a readiness
  gate, the rollout stops there.

## The limit is per pod

Each replica keeps its own in-memory buckets; nothing is shared across
pods. With `replicaCount: N` behind a load balancer that spreads a
tenant's requests evenly, the tenant's effective limit is up to **N x**
the configured rate and burst. Size the values for the replica count you
run (and remember HPA scale-out raises the effective limit). A
cluster-wide limit would need shared state (e.g. Valkey) and isn't
implemented.

## Changing the values

Env vars are read only at startup, so a new value takes effect when the
Deployment rolls. Changing the Helm value changes the pod template, and
`helm upgrade` rolls it. Each new pod starts with full buckets.
