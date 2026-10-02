[English](AGENTS.md) · [中文](AGENTS.zh.md)

# infra/iam-casdoor

The AI guide to developing this component. How to use it, its boundaries and contracts: BRICKKIT.md. Why it is shaped this way: `docs/design.md`. Dependencies, configuration and deployment: component.yaml.

## Code map

| Path | Owns |
|---|---|
| `backend/module/module.go` | The only entry, `New(ctx, rt)`: builds repo → service → HTTP + gRPC; `Start` registers the key IDs, starts the Casdoor connection and the OIDC discovery in the background, then runs the outbox pump, the consumer and the partition loop. Same function standalone and in a shell |
| `backend/module/settings.go` | `loadSettings`: reads and parses every config key once (missing keys, bad TTLs, bad PEMs → an error naming the key, never a panic) |
| `backend/module/casdoor.go` | The two background loops that wait for Casdoor: admin login + start-up reconciliation, OIDC discovery (`rebaseHost`) |
| `backend/module/retry.go` | `retryUntilOK`: exponential backoff up to 30 s, a cancel is not a failure |
| `backend/cmd/server/main.go` | One line, `besdk.RunStandalone(module.New)` |
| `backend/cmd/migrate/main.go` | One line, `migrate.Main(migrations.FS)`: the migration container's entry (`./migrate up`) |
| `backend/internal/features/` | `FromLockfile`: `ENABLED_COMPONENTS` (the project's `brickkit.yaml`) → the installed component IDs |
| `backend/internal/keys/` | PEM parsing, the RFC 7638 key ID, JWK serialisation |
| `backend/internal/tokens/` | Signing and verifying this component's own JWTs: application tokens and refresh tokens (`typ: refresh`) |
| `backend/internal/casdoor/admin.go` | Casdoor admin API: one session, re-login on "Please login first", 15 s per call, `IsUnreachable` |
| `backend/internal/casdoor/discovery.go` | OIDC discovery: issuer and `jwks_uri` |
| `backend/internal/casdoor/idtoken.go` | Verifying Casdoor id_tokens (RS256 only, issuer checked) |
| `backend/internal/bootstrap/` | Start-up reconciliation of the Casdoor organisation, application and webhook |
| `backend/internal/repo/` | `refresh_tokens` (issue, rotate with reuse detection, revoke), `signing_keys`, `webhook_deliveries` (dedup under an advisory lock), `user_event_versions` (per-user event version, the row lock that orders read-backs), `bootstrap_state` |
| `backend/internal/service/` | Token exchange, refresh, logout, webhook handling; sentinel errors and their gRPC status (`status.go`); shared by REST and gRPC |
| `backend/internal/http/http.go` | REST routes, each registered through `besdk.GET` / `besdk.POST`; the webhook's shared-secret check; `dedupKeyFor` |
| `backend/internal/grpc/grpc.go` | `infra.iam.v1.IamService`: `BatchGetUsers`, `GetTenantFeatures` |
| `backend/internal/consumer/` | `infra.authz.user_role.changed.v1`: `kicked` revokes the user's refresh tokens |
| `backend/internal/partition/` | Background loop: weekly partitions of `event_outbox` / `event_inbox` four weeks ahead, monthly partitions of `webhook_deliveries` three months ahead |
| `migrations/` | SQL migrations, embedded by `migrations/embed.go` |
| `contracts/` | proto, OpenAPI, event schema |
| `gen/infra/iam/` | Generated Go code: a nested Go module, tagged on its own as gen/infra/iam/v1.x.y; never edited by hand |
| `scripts/` | `seed.sh` / `seed-clean.sh`: local test users and a password-grant test application in Casdoor |

| Feature | Start here | Then |
|---|---|---|
| What goes into the application token | `backend/internal/service/service.go` (`signAccessTokenFor`) | `backend/internal/tokens/tokens.go` (`Claims`), the authz contract package |
| Refresh token rotation or reuse detection | `backend/internal/repo/refreshtokens.go` (`RotateRefreshToken`) | `backend/internal/service/service.go` (`RefreshToken`), `backend/internal/repo/repo_test.go` |
| Signing key rotation | `backend/module/settings.go` | `backend/internal/tokens/tokens.go` (`NewVerifier`), `backend/internal/http/http_test.go` |
| Parsing a Casdoor webhook, or what a user event says | `backend/internal/service/webhook.go` (`userRef`, `userEventFor`) | `backend/internal/service/service.go` (`HandleWebhookDelivery`), `backend/internal/repo/usereventversions.go`, `contracts/events/iam.events.json` |
| What Casdoor objects are created at start | `backend/internal/bootstrap/bootstrap.go` | `backend/internal/casdoor/admin.go`, `backend/module/casdoor.go` |
| The features list | `backend/internal/features/features.go` | `backend/internal/http/http.go` (`tenantFeaturesHandler`) |
| An error answering with the wrong status | `backend/internal/service/status.go` | `backend/internal/service/errors.go` |

## Build and test

```bash
# tests run against the test database brickkit_test_db, never brickkit_db (make test-db-init ID=infra/iam-casdoor at the project root)
# the password is POSTGRES_PASSWORD in the project's .env; don't source .env (Compose syntax, multi-line PEM)
export TEST_PG_DSN="postgres://postgres:<password>@localhost:5432/brickkit_test_db?sslmode=disable"
make test                    # every package ends in "ok"; refuses to run without TEST_PG_DSN
go test ./... -count=1 -v | grep -- '--- SKIP'
#   6 skips without Casdoor and authz: 3 in bootstrap, 2 in casdoor, the end-to-end test in service
TEST_CASDOOR_BASE_URL=http://localhost:8000 go test ./... -count=1 -v | grep -- '--- SKIP'
#   1 skip left: TestExchangeTokenAndRefreshToken_端到端对着真实infra_authz走一遍, which needs
#   INFRA_AUTHZ_GRPC_ENDPOINT (make test-cross ID=infra/iam-casdoor at the project root sets it)
make check-version dag-check contract-check import-scan module-check   # each prints one ✓ line
make docs-check              # "0 with errors, 0 warnings"
```

The Casdoor tests create organisations, applications, users and webhooks with timestamped names in the shared Casdoor and delete them afterwards. After `buf generate` (contracts changed) the contract package needs a new tag: see Pitfalls. On a real machine, from the project root: `make verify ID=infra/iam-casdoor ROUTE='POST /api/iam/logout' FOCUS=1` builds the image, starts only what this component needs, checks migration, health and the protected route, runs a focus run, and tears down.

## Design decisions

- **Two tokens.** Casdoor's id_token only proves identity; the application token is signed here, with claims asked from `infra/authz` at that moment. Login and every refresh call `ResolveClaims`; nothing caches claims.
- **Fail closed on authz.** While authz is unreachable, exchange and refresh answer `503`; the refresh is checked and the claims fetched before the rotation, so a failed refresh uses nothing up.
- **No user table, no role table.** Users are read from Casdoor on demand (`BatchGetUsers`, and every webhook delivery); roles live in authz. `user_event_versions` holds versions and names, no profile data.
- **A delivery says who, Casdoor says what.** Every user event is the user read back from Casdoor at processing time, with a per-user version taken under a row lock before the read; delivery order doesn't matter.
- **Casdoor is waited for, not required at start.** Admin login, reconciliation and OIDC discovery retry in the background; a Casdoor that is merely down logs at Warn, a Casdoor that rejects the request logs at Error once.
- **Reconcile on every start** (`bootstrap`): look first, create what is missing, rewrite the webhook when address, secret or enabled state differ. Every step is safe to repeat.
- **Strict about who sent a webhook, lenient about what it says.** Wrong secret → `401`; an unparseable or unknown delivery is stored as `IGNORED` / `ERROR` and answered `200`.
- **`ENABLED_COMPONENTS` is the lock file itself** (`file://brickkit.yaml`), so adding a component needs no extra step; only `components[].id` and `kind` are decoded.

## Pitfalls

| Never | Symptom | Why |
|---|---|---|
| Cache the result of `ResolveClaims`, or fall back to the last known claims when authz is down | Nothing fails; after a role change the refreshed token still carries the old roles, the component answers `401 token_stale`, the frontend refreshes again, forever | The claims must be the current ones; an outage is answered with `503`, not with stale roles |
| Rotate the refresh token before the claims are fetched | One authz hiccup: the refresh answers `503`, the client retries with the same token, hits reuse detection, and every session of that user is revoked | `RefreshToken` verifies, fetches claims and signs first, rotates last; `TestREST_authz不可达时刷新回503且不消耗refreshToken` |
| Dedup webhook deliveries with a unique constraint, or drop the advisory lock in `RecordDelivery` | Duplicates pass silently; the same user event reaches downstream twice | `webhook_deliveries` is partitioned, so its unique index must include `received_at`, which differs on every redelivery |
| Make `webhook_deliveries.payload` JSONB, or reject deliveries that don't parse | A malformed delivery makes the insert fail; the event is lost and Casdoor retries forever | Only some actions have been seen on a real Casdoor (see `docs/design.md`); the payload is stored as `TEXT` and marked `IGNORED` / `ERROR` |
| Decode the delivery's `object` only as a JSON object | Every real delivery is stored as `IGNORED` ("no user identifier"); no `infra.iam.user.*.v1` event is ever published, and every gate is green | Casdoor sends `object` as a JSON-encoded string; `decodeUserRef` accepts both forms, `TestWebhookUserPayload_object是JSON字符串时也能认出是谁` |
| Publish a user event from the delivery body, or read Casdoor before `NextUserEventVersionTx` | Casdoor delivers two changes of one second newest first; downstream keeps the older one. Single-delivery tests stay green | Each event is read back after the version row is locked; `TestWebhook_两次修改倒序到达_下游留下的是最新状态`, `TestWebhook_同一用户两次投递并发_后回读的拿到更大的版本号` |
| Record a delivery whose read-back failed | Casdoor does not retry; a recorded failure would also make any redelivery a duplicate | The transaction rolls back and the webhook answers `503`; `TestWebhook_Casdoor会话未就绪_回Unavailable且不登记` |
| Hard-code Casdoor's JWKS address, or use the `jwks_uri` from discovery as it is | Token exchange answers `503` forever; keyfunc reports `404` or connects to itself | Casdoor serves `/.well-known/jwks` (no `.json`), and the discovery host is Casdoor's `origin`, which this container may not reach; `rebaseHost` keeps the path and uses `CASDOOR_BASE_URL`'s host |
| Add the `password` grant to the application `bootstrap` creates | Works, and turns the login application into one that accepts passwords sent by anyone | Browsers use the authorization code flow; only the test application in `casdoor_integration_test.go` and `scripts/seed.sh` has the password grant |
| Give refresh tokens and application tokens the same claims without the `typ` check | An application token is accepted as a refresh token, or the other way round | Both are signed with the same key; `TestVerifyRefreshToken_不接受应用token冒充` |
| Generate the signing key at start, or let replicas use different keys | Every restart logs every user out; on two replicas, half of the requests fail verification | The key comes from `APP_TOKEN_SIGNING_KEY_PEM`; its key ID is the deterministic RFC 7638 thumbprint |
| Change a comment or option in `contracts/infra/iam/v1/iam.proto` without tagging the contract package | Builds pass locally (the `replace` hides it); a shell fetching `infra-iam-casdoor/v2` compiles against the old `gen/` | Any change under `gen/infra/iam/` needs a new tag gen/infra/iam/v1.x.y and the root `go.mod` requiring it |

## Before changing code

1. Does the change make claims older than "now"? Then it reintroduces the stale-token loop; stop.
2. Does it add a table of users or roles? Users belong to Casdoor and roles to authz; read them, don't copy them.
3. Does a webhook change turn "an unknown shape" into an error? Only the shared-secret check may reject.
4. Does a new rpc or event fit another IAM implementation (Keycloak) too? The contract is the IAM family's, not Casdoor's.
5. Is someone adding a dependency on this component? Other components use `IAM_JWKS_URL` and the user events, never an edge.
6. Does a new Casdoor object carry the password grant? Only test applications may.

<!-- brickkit:managed:begin lang=en -->
<!-- maintained by brickkit (init, add, remove, upgrade, skills update): edits between these markers are overwritten -->

## BrickKit

This is a BrickKit component: `component.yaml` is all the platform reads. The rules it relies on:

- `configSchema` keys are the environment variable names the code reads. Never use a reserved name: `COMPONENT_ID`, `COMPONENT_VERSION`, `PORT`, `BRICKKIT_SERVED_MEMBERS`, `BRICKKIT_SERVED_MEMBERS_CONFIG`, or any `*_ENDPOINT`.
- Dependencies are exact versions. A dependency's address arrives as `<ID>_ENDPOINT`; an optional dependency that is absent has no variable at all, so read it with a fallback.
- `/healthz` checks only this process, never a dependency. The migration command runs from the same image and must fail on an argument it does not know.
- `BRICKKIT.md` travels to every project that uses this component and is read there without the repository: keep it in step with the code, with no relative links.
- Release: raise `metadata.version`, commit, push, `brickkit release`. `brickkit lint` checks the manifest and these docs — inside a project, run in this directory, it checks only this component (`--all` for the whole project).
- The full rules are in the `brickkit-component` skill (`.claude/skills/brickkit-component/SKILL.md` at the root of the project or repository where skills are installed; `brickkit skills update` installs it); for flags ask `brickkit <command> --help`; BrickKit's own documentation is `brickkit docs`.
<!-- brickkit:managed:end -->
