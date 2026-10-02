# infra/iam-casdoor

## Purpose

The adapter between Casdoor and the rest of the project. Casdoor proves who a user is; this component turns that proof into the project's own application token, which carries the user's roles, department path and organisation as `infra/authz` resolves them at that moment, and which every other component verifies locally against this component's JWKS. It also tells the frontend which components are installed, and turns Casdoor's user webhooks into events.

**Owns**

- Issuing, refreshing and revoking application tokens: `POST /api/iam/token` exchanges a Casdoor id_token issued for a trusted Casdoor application for an application token plus a refresh token; refreshing rotates the refresh token within a session that ends `REFRESH_TOKEN_TTL_SECONDS` after login (a reused one revokes every refresh token of that user); logout revokes one; disabling or deleting a user in Casdoor revokes all of theirs.
- The signing key's public half, served at `/.well-known/jwks.json` (the current key and, during a rotation, the previous one).
- `GET /api/tenant/features`: the components installed in the project, read from the project's `brickkit.yaml`.
- The Casdoor organisation, application and webhook this component needs, reconciled with the configuration on every start.
- The events `infra.iam.user.created.v1`, `infra.iam.user.updated.v1`, `infra.iam.user.disabled.v1`, bridged from Casdoor's webhook.

**Does not own**

- Users, passwords, the login page, MFA and social login: Casdoor. The browser talks to Casdoor directly; this component neither proxies nor forwards the login.
- Roles, role permissions and who has which role: `infra/authz`. Asked at every issue and refresh, never cached here.
- Checking a token or a permission on a request: every component does it in process, with the SDK, against the JWKS and the authorisation bundle.
- Notification preferences and channel addresses: `infra/notification`, which keeps its own copy from the `infra.iam.user.*.v1` events.

## Before you deploy

- **PostgreSQL**: a schema `infra_iam_casdoor` (plus `infra_iam_casdoor_archive` if your schema convention creates one; nothing writes to it yet), a login role `infra_iam_casdoor_rw` with `USAGE` and `CREATE` on the schema, and its password. The migration runs as this role and creates the tables, so the role owns them; the running component creates future partitions itself, which needs that ownership. BrickKit creates none of this; in the BrickEnterprise assembly project `make dev-env` writes the password into `.env` and `make db-init` creates the schema, role and grants.
- **NATS** reachable at `NATS_URL`: events go out through an outbox table and a background pump; the component starts without NATS and the events wait.
- **Casdoor** running, reachable from this component at `CASDOOR_BASE_URL`, with an administrator account in Casdoor's built-in organisation (`CASDOOR_ADMIN_USERNAME` / `CASDOOR_ADMIN_PASSWORD`). Casdoor's image ships with a well-known default administrator password: in production, change the Casdoor administrator's password and `CASDOOR_ADMIN_PASSWORD` together (with a mismatch the admin login is retried in the background and logs an Error at every attempt, at most every 30 seconds, until the password is fixed; meanwhile the organisation, application and webhook are not reconciled, `BatchGetUsers` answers `UNAVAILABLE`, and webhook deliveries wait in the queue and go out once the login succeeds; token exchange keeps working if an earlier start recorded the application's client ID, and answers `503` on a first install). Casdoor's `origin` setting must be a full URL including the port: the issuer and the JWKS address in its OIDC discovery document are built from it. The component creates the organisation `CASDOOR_ORG_NAME`, the application `CASDOOR_APP_NAME` and the webhook itself; it keeps retrying in the background while Casdoor is not up yet, and token exchange answers `503` until it has reached Casdoor once.
- **A signing key**: an RSA private key in PEM (PKCS #1 or PKCS #8), for example `openssl genrsa 2048`. It must be the same across restarts and replicas, or every token issued before a restart stops verifying. Keep it as a secret file and reference it with `file://`.
- **A webhook callback route**: Casdoor must be able to reach this component. Attach the Casdoor container to the project's network (`brickkit-<project>-net`, created by `brickkit up`; create it beforehand with the same Compose labels if Casdoor starts first) and set `WEBHOOK_CALLBACK_URL` to this component's own versioned service name, `http://infra-iam-casdoor-2-0-0:8200/api/iam/webhooks/casdoor`. The name resolves both standalone and while a shell hosts this component (members' service names are network aliases of the shell), so no port is exposed; change it with every version of this component, like `IAM_JWKS_URL`. Leaving the callback empty is valid: users still log in, but no `infra.iam.user.*.v1` events are published.
- **`infra/authz`** running (the one dependency, below).

## Dependencies

- `infra/authz` (required): this component calls its gRPC `ResolveClaims` at every token issue and every refresh, to put the user's current roles, department path and organisation into the application token. There is no cached fallback: while authz is unreachable, logging in and refreshing answer `503` (the refresh token is not used up, so the same one works once authz is back), while users who already hold an application token keep working until it expires (`APP_TOKEN_TTL_SECONDS`).

No component should depend on this one. Other components verify application tokens against the JWKS at their `IAM_JWKS_URL` and learn about users from the `infra.iam.user.*.v1` events: configuration and events, not dependency edges. That is what keeps the IAM implementation replaceable.

Casdoor itself is not a dependency: it is a resource outside the project, reached at `CASDOOR_BASE_URL`.

## Configuration

| Variable | Meaning |
|---|---|
| `PG_HOST` | PostgreSQL host. Usually the project's shared value (`$var:PG_HOST`). |
| `PG_PORT` | PostgreSQL port; default `5432`. |
| `PG_DATABASE` | The database holding the `infra_iam_casdoor` schema (`$var:PG_DATABASE`). |
| `PG_USER` | The login role, `infra_iam_casdoor_rw` as a literal. Inside a shell the shell logs in with its own role and switches to this one per transaction (`SET LOCAL ROLE`), so the role name must be `<PG_SCHEMA>_rw`. |
| `PG_PASSWORD` | Password of `PG_USER`. Secret: write `${INFRA_IAM_CASDOOR_DB_PASSWORD}` (or your secret store's reference), never the value. |
| `PG_SCHEMA` | Schema of all tables, the outbox and the migration state table (`schema_migrations_infra_iam_casdoor`); default `infra_iam_casdoor`. Write the literal anyway. |
| `NATS_URL` | NATS server the outbox pump publishes to and the consumer reads from (`$var:NATS_URL`). |
| `OTEL_BASE_URL` | OpenTelemetry collector base URL; empty (the default) exports nothing. |
| `IAM_JWKS_URL` | This component's own JWKS, for example `http://infra-iam-casdoor-2-0-0:8200/.well-known/jwks.json`: the SDK verifies the token on `POST /api/iam/logout` like any other component does. Required; empty or unreachable, logout answers `403`. Use the same project-wide value as every other component. |
| `CASDOOR_BASE_URL` | Casdoor as reached from this component, for example `http://host.docker.internal:8000` when Casdoor runs on the host. Used for the admin API and for OIDC discovery. Required. |
| `CASDOOR_ADMIN_USERNAME` | Casdoor administrator in the built-in organisation; default `admin`. |
| `CASDOOR_ADMIN_PASSWORD` | Its password. Secret: a `${…}` reference. Required. |
| `CASDOOR_ORG_NAME` | The Casdoor organisation that holds the project's users; default `brickkit`. Created if missing. |
| `CASDOOR_APP_NAME` | The Casdoor application users log in through (authorization code flow, no password grant); default `brickkit-app`. Created if missing; an existing one is left as it is. Its client ID is the audience a Casdoor id_token must carry to be exchanged. |
| `CASDOOR_EXTRA_CLIENT_IDS` | Client IDs of other Casdoor applications whose id_tokens are exchanged too, comma-separated; default empty. For several frontends that are separate Casdoor applications, or a local test application. Never list an application with the password grant in production. |
| `WEBHOOK_SHARED_SECRET` | The value Casdoor sends in the `X-Shared-Secret` header of every webhook call; a call without it, or with another value, is rejected with `401`. Secret: a `${…}` reference to a long random string. Required. |
| `WEBHOOK_CALLBACK_URL` | Where Casdoor sends user webhooks, as seen from Casdoor, ending in `/api/iam/webhooks/casdoor`. On every start the webhook is created, or rewritten when its address, secret or enabled state differ from the configuration. Empty (the default) creates nothing and leaves an existing webhook untouched: no user events. Use this component's versioned service name (see Before you deploy), which also works inside a shell; a host port does not, because a shell member's port cannot be exposed on its own. |
| `APP_TOKEN_SIGNING_KEY_PEM` | The RSA private key that signs application and refresh tokens, PEM. Secret, multi-line: `file://` a secret file. Required. Its key ID in the JWKS is the RFC 7638 thumbprint, so it is stable across restarts. |
| `APP_TOKEN_PREVIOUS_PUBLIC_KEY_PEM` | During a key rotation, the previous key's public half (PEM public key or certificate); default empty. The JWKS then serves both keys and refresh tokens signed with the previous key are still accepted. Clear it once the longest token lifetime has passed since the switch. |
| `APP_TOKEN_TTL_SECONDS` | Lifetime of an application token, a positive whole number of seconds; default `600`. Also how long users keep working while `infra/authz` is down. A value that is not a positive integer stops the component at start. |
| `REFRESH_TOKEN_TTL_SECONDS` | Lifetime of a session, a positive whole number of seconds counted from login; default `604800` (seven days). Refreshing rotates the refresh token but never extends the session: at this point after login the user logs in again. |
| `ENABLED_COMPONENTS` | The project's `brickkit.yaml`, as `file://brickkit.yaml`. `GET /api/tenant/features` answers with the IDs of its `components` that are not shells, each once, sorted. That means installed, not running: a component turned off in the deploy file is still listed. Only the component IDs and kinds are read; the rest of the file is not decoded. Required; the old comma-separated list is rejected at start. |

## Contracts

- `contracts/infra/iam/v1/iam.proto` — gRPC `infra.iam.v1.IamService`, the IAM family's contract (no Casdoor in the name, so another IAM implementation can serve it unchanged): `BatchGetUsers` (subs → display name, email, phone, IM accounts; read from Casdoor on each call, unknown subs left out; `UNAVAILABLE` while the Casdoor admin session is not ready or Casdoor fails) and `GetTenantFeatures` (the same list as the REST route). The Go package is the separate module `github.com/brickKit/infra-iam-casdoor/gen/infra/iam`.
- `contracts/iam.openapi.yaml` — REST, at fixed paths shared by the IAM family. None of them needs a permission key: this component is the door between "no identity yet" and "an identity". `POST /api/iam/token` (public; `400` bad body, `401` invalid Casdoor token, a token issued for an application that is not trusted, or a user disabled in Casdoor, `503` Casdoor or authz not reachable, or the application's client ID not yet known), `POST /api/iam/token/refresh` (public; `401` invalid, revoked, expired or reused refresh token, including a session past its end and a user disabled in Casdoor, `503` authz not reachable), `POST /api/iam/logout` (signed in; idempotent), `GET /.well-known/jwks.json` (public; for other components, not routed through the gateway), `GET /api/tenant/features` (public; the frontend reads it before login), `POST /api/iam/webhooks/casdoor` (public route, authenticated by the shared secret header; `200` once the delivery is recorded, whether or not Casdoor can be read back at that moment; `503` stays declared but this version no longer answers it; for Casdoor only, not routed through the gateway).
- `contracts/events/iam.events.json` — published through the outbox: `infra.iam.user.created.v1`, `infra.iam.user.updated.v1` (with a `version` that only grows), `infra.iam.user.disabled.v1` (also sent when a user is deleted or forbidden; the same transaction revokes every refresh token of that user). Each event carries the user as Casdoor holds them when the delivery is processed, read back through the admin API, so deliveries that arrive out of order still leave downstream with the latest state; `version` grows strictly per user. Deliveries are processed from a queue by a background loop: while Casdoor cannot be read they wait and go out once it can; a delivery Casdoor keeps failing for is marked `FAILED` after 10 attempts, with a Warn. A delivery with only owner and name is resolved through Casdoor; a minimal-body `delete-user` of a user this component never had an event for is stored as `IGNORED`. Casdoor sends webhooks in batches about every 30 seconds and does not retry a failed one, so changes made while this component is down are not bridged (a user re-enabled meanwhile cannot log in until the next change to them in Casdoor; any edit will do). `infra.iam.login.v1` is declared but not published yet. Consumed: `infra.authz.user_role.changed.v1`, where `change_type: kicked` revokes every refresh token of that user; other changes leave refresh tokens alone, since the next refresh picks up the new roles.
- `assembly.yaml` — this project's metadata: the edge routes for token, refresh, logout and features; no permission keys, no menus; the schema and role; `data_scopes: none`.

## Shell declaration

Not a shell. It can be hosted in a Go shell (in the BrickEnterprise project, `be/go-infra`) or run on its own; the code is the same either way. Hosted in a shell, its port cannot be exposed on its own; Casdoor reaches the webhook through the member's service name, which the shell answers to (see `WEBHOOK_CALLBACK_URL`).
