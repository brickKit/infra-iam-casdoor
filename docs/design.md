[English](design.md) · [中文](design.zh.md)

# infra/iam-casdoor design

Conclusions only, for whoever changes this component's design. How to use it: `BRICKKIT.md`; how the code is laid out: `AGENTS.md`.

## Boundaries

This component is the adapter in front of Casdoor, and the only member of the IAM slot: replacing Casdoor with Keycloak means replacing this component, nothing else. It owns issuing, refreshing and revoking application tokens, the JWKS other components verify them against, the installed-components list for the frontend, the bridge from Casdoor's user webhooks to events, and the start-up reconciliation of the Casdoor objects it needs.

| Not here | Owner | Why |
|---|---|---|
| Users, passwords, login page, OIDC flow, MFA, social login | Casdoor | Code this project does not write is not wrapped as a component. The browser talks to Casdoor directly; this component takes over only after authentication |
| Role model, role permissions, user roles | `infra/authz` | Roles never live in Casdoor, so replacing the IAM implementation migrates no role data |
| Checking a token or a permission on a request | the SDK in every component | Verification is a local computation against the JWKS and the bundle; this component is not on the request path |
| The organisation tree | `infra/authz` for now, an organisation master-data component later | This component only copies the `dept_path` string into the token, verbatim: an empty string (no department, which consumers scope to the owner alone) stays empty and is never turned into `"/"` (the whole tree) |
| Notification preferences and addresses | `infra/notification` | It keeps its own copy from the user events |

Every login method (password, WeChat, QQ, Google, and any Casdoor adds later) is configured in Casdoor: whatever the method, Casdoor produces the same OIDC id_token, and this component only knows that token. A self-registered or social account has **no roles** in authz, so its application token carries an empty `roles[]` and every business route answers `403` until an administrator grants a role. No role may be granted automatically to new accounts: that would turn sign-up into privilege escalation.

There is no DingTalk login, so Casdoor does not know a user's DingTalk identity. Notifications reach DingTalk by phone number instead: this component puts the phone number into the user events, and `integration/im-dingtalk` maps it to a DingTalk user.

## Owned data

| Table | Partitioned | Notes |
|---|---|---|
| `refresh_tokens` | no | `jti` primary key, `sub`, `expires_at`, `revoked_at` (null = valid), `rotated_from` (the rotation chain). Bounded by the number of active users |
| `signing_keys` | no | key ID and algorithm of the current and previous signing keys, for diagnosis. The private key is never stored: it comes from configuration |
| `webhook_deliveries` | monthly, by `received_at` | one row per Casdoor delivery: dedup key, action, the raw payload as `TEXT`, status `RECEIVED` / `PROCESSED` / `IGNORED` / `ERROR` |
| `user_event_versions` | no | one row per user that has had an event: the last event version and the owner and name last read from Casdoor for that ID. No profile data. Bounded by the number of users |
| `bootstrap_state` | no | one row per reconciliation step (`casdoor_org`, `casdoor_app`, `casdoor_webhook`) and what it produced (the application's client ID) |
| `event_outbox`, `event_inbox` | weekly, by `created_at` | the standard outbox and the consumer's inbox |

Terminal states: a refresh token that is revoked or expired; a webhook delivery as soon as it is written. There is no user table and no role table: users are read from Casdoor when asked (`BatchGetUsers`), roles from authz at every issue. A users shadow table would weld the IAM slot to this implementation; a cached copy of roles would reintroduce the stale-token loop described under Contract surface. `user_event_versions` is not one: it holds how far each user's events have got and the name Casdoor last gave for the ID, never what the user looks like.

`payload` is `TEXT`, not JSONB: JSONB validates on insert, so a delivery that is not valid JSON would fail the insert and be lost, while the point is to keep what Casdoor sent for diagnosis.

## Contract surface

gRPC `infra.iam.v1.IamService`, the IAM family's contract (the package name carries no implementation, so an `infra/iam-keycloak` can implement the same proto and callers keep their imports):

| rpc | Kind | Notes |
|---|---|---|
| `BatchGetUsers` | read | the batched read: subs → display name, email, phone, IM accounts. Read from Casdoor on every call (Casdoor has no batch lookup by ID; the batch saves the caller's round trips). Unknown subs are left out; Casdoor failing or the admin session not ready → `UNAVAILABLE`, never "left out" |
| `GetTenantFeatures` | read | the installed components, as on REST |

REST, at fixed paths shared by the IAM family; no route needs a permission key, because this component is the door between "no identity" and "an identity":

| Path | Access | Notes |
|---|---|---|
| `POST /api/iam/token` | public | Casdoor id_token → application token + refresh token |
| `POST /api/iam/token/refresh` | public | the refresh token authenticates itself; rotates it |
| `POST /api/iam/logout` | signed in | revokes one refresh token of the caller; idempotent; another user's token is left alone |
| `GET /.well-known/jwks.json` | public | for the SDK in other components; not routed through the gateway |
| `GET /api/tenant/features` | public | read by the frontend before login |
| `POST /api/iam/webhooks/casdoor` | public route, shared secret | Casdoor has no webhook signature but sends custom headers, so `X-Shared-Secret` is compared (in constant time) with `WEBHOOK_SHARED_SECRET`; not routed through the gateway |

**How Casdoor reaches the webhook.** Casdoor is a base resource, not a component, so it is not on the project's network by default. It is attached to it, and `WEBHOOK_CALLBACK_URL` is this component's versioned service name. A host port (`expose: true` plus `host.docker.internal`) was rejected: it works only standalone, because a shell member's port cannot be exposed on its own, while the service name is also a network alias of the shell. The price is that the URL carries the version and changes with every release, like `IAM_JWKS_URL`.

**What a delivery looks like** (captured on a real Casdoor): the body is Casdoor's `Record`. `action` is the action name (`update-user`, `login`, …); `object` is the request body *encoded as a JSON string*, so it holds whatever the caller sent: for an `update-user` that sends the whole user object, that object with the password already masked as `***`; for `login`, the login form with no user ID; `user` is the account that acted (`admin` when an administrator edits someone), not the user acted on. So `object`, in either form, is read only to learn who changed: its `id`, or its `owner` and `name` when the caller sent only those (an `add-user` / `delete-user` through the admin API with a minimal body). What the event says is read back from Casdoor (see Events). Changes made through the admin API do trigger deliveries.

**Two tokens.** Authentication stays between the browser and Casdoor; the application token must carry `roles[]`, `dept_path` and `org_id`, which only authz knows. So: (1) the browser gets an id_token from Casdoor; (2) the frontend exchanges it here: this component verifies it against Casdoor's JWKS (RS256 only, issuer checked), calls authz `ResolveClaims` and signs the application token with its own key; (3) business components verify the application token against this component's JWKS; (4) refreshing comes here too and calls `ResolveClaims` again, so roles are always current. After step 1 Casdoor is out of the picture.

Letting Casdoor sign tokens with roles mirrored into it was rejected for three independent reasons: authz could no longer revoke a session without calling the IAM (the edge would point the wrong way); the mirror would be asynchronous, so after a role change the refresh would still return the old roles, the component would answer `401 token_stale`, and the frontend would refresh again forever with every log line looking normal; and the role data would be welded back into Casdoor.

**Being the issuer means:** the signing key comes from configuration (a generated one would change at every restart and differ between replicas); its key ID is the RFC 7638 thumbprint, so it is stable; during a rotation the JWKS serves the previous public key too, and refresh tokens signed with it still verify; refresh tokens rotate on every use (no sliding expiry), and a reused one revokes every refresh token of that user, because a well-behaved client never presents a rotated token. Refresh tokens are JWTs signed with the same key, told apart from application tokens by `typ: refresh`.

**Refresh order.** Verify the refresh token, fetch the claims and sign, and only then rotate. Rotating first would let one authz hiccup use up the caller's token: the retry would hit reuse detection and log the user out everywhere.

**Fail closed on authz.** No fallback to earlier claims: a security component must not issue tokens it cannot vouch for, the deployment is one machine where "authz down while everything else runs" is rare, and a cache would reopen the window in which a token carries roles that `stale_since` already invalidated. While authz is down, users with a token keep working until it expires (`APP_TOKEN_TTL_SECONDS`, 600 s by default); login and refresh answer `503`.

**Installed components.** `ENABLED_COMPONENTS` is the project's `brickkit.yaml` (`file://brickkit.yaml`): the lock file `brickkit add` / `remove` / `upgrade` maintain is the one source of what is installed, so adding a component needs no regeneration step. Only `components[].id` and `kind` are decoded; shells are skipped; an ID present at several versions counts once; the result is sorted. The rest of the file (sources with tokens, installer settings) is never decoded and never appears in an error message. "Installed" is not "running": a component turned off in the deploy file is still listed.

## Events

Published through the outbox, in the same transaction that records the webhook delivery:

| Subject | Grade | When | Payload |
|---|---|---|---|
| `infra.iam.user.created.v1` | core | Casdoor reports a new user | `sub`, `display_name`, `email`, `phone`, `im_accounts` |
| `infra.iam.user.updated.v1` | core | a user changes | the same plus `version` |
| `infra.iam.user.disabled.v1` | core | a user is disabled **or deleted** | `sub` |
| `infra.iam.login.v1` | peripheral | declared for login auditing | `sub`, `ip`, `occurred_at`; not published yet |

The user events are core, not peripheral: `infra/notification` keeps "whom to notify, where" from them, and a lost one means a notification that silently never arrives. Deletion is sent as `disabled`: downstream needs "stop sending to them", not "erase their history".

**How a user event is built.** A delivery tells who changed, not what the user looks like now. Casdoor sends the records of one batch in no reliable order (two `update-user` records created in the same second arrived newest first), and a record's `createdTime` has whole seconds only. Publishing the delivery's body would leave downstream with whichever change happened to be processed last. So each delivery reads the user back from Casdoor's admin API and publishes that state, all in the transaction that records the delivery:

1. Take the user's next version from `user_event_versions`. The row stays locked until commit, so deliveries for one user are handled one at a time.
2. Read the user from Casdoor by ID. A delivery with only owner and name is first resolved by owner and name; when Casdoor no longer has that user, by the name last recorded for an ID.
3. Gone, forbidden (`isForbidden`) or soft-deleted (`isDeleted`) → `disabled`; present and the action created the user → `created`; anything else → `updated`. The payload is the state just read, `im_accounts` included (DingTalk, as in `BatchGetUsers`).

In whatever order deliveries arrive, a later read always gets a higher version, so the event downstream keeps is the latest state Casdoor was seen in. If Casdoor cannot be read (the admin session is not up yet, or Casdoor errors), the webhook answers `503` and the delivery is not recorded, so it is not mistaken for a duplicate later. Duplicates and actions that are not user changes (`login`) never call Casdoor.

**Why this version.** `version = max(processing time in nanoseconds, last version + 1)`, per user, in this component's database. The row lock is what ties the read to the version: a bare timestamp, taken without a lock, lets two concurrent deliveries read Casdoor in one order and stamp versions in the other. The floor keeps versions in the range of the timestamp versions consumers may already hold. The `+ 1` keeps them strictly growing when clocks of replicas differ or step back. A version from the record's `createdTime` was rejected: whole seconds cannot order two changes inside one second.

Consumed: `infra.authz.user_role.changed.v1`. `change_type: kicked` revokes every refresh token of that user (with the inbox record, in one transaction), which is how "kick out" logs a user out at the next refresh. Other changes (granted, revoked, expired) leave refresh tokens alone: the next refresh carries the new roles, and revoking on every role change would log people out at every reorganisation.

Casdoor webhook deliveries are deduplicated by a hash of the body (whether Casdoor sends a stable delivery ID is not confirmed). The dedup check runs under a transaction-scoped advisory lock on the key: the table's unique index must include the partition key `received_at`, which differs on every redelivery, so a constraint cannot dedup, and a plain check-then-insert lets two concurrent copies both publish.

## Dependencies

| Dependency | Used for | Why synchronous |
|---|---|---|
| `infra/authz` (required) | `ResolveClaims` at every issue and refresh | the token must carry the roles of this moment |

Expected but absent:

| Not a dependency | Why |
|---|---|
| Casdoor | a resource outside the project, reached at `CASDOOR_BASE_URL`; the component waits for it in the background instead of failing at start |
| `infra/notification` | it consumes the user events; this component does not need to know whether a notification went out |
| any component depending on this one | must stay so: components verify tokens through `IAM_JWKS_URL` and learn about users from events. A dependency edge would put this implementation's name into their environment variables, and replacing the IAM would break them |

## Place in the synchronous call graph

One outgoing edge, `infra/iam-casdoor → infra/authz`, and authz has none, so every path from here has length 1 and there can be no cycle. Incoming edges: none, by design (see Dependencies); the frontend and the SDK reach it over configured URLs. It is outside the three hubs (master data, `erp/inventory`, `erp/finance`) and touches neither CRM nor ERP.

## Partitioning and archiving

| Data | Hot | Archive condition | Where |
|---|---|---|---|
| `refresh_tokens` | not expired, not revoked | 30 days after expiry or revocation, delete | not archived |
| `signing_keys` | current and previous | older entries after 90 days, delete | not archived |
| `bootstrap_state` | always | never | — |
| `webhook_deliveries` | last 30 days | whole monthly partitions older than 30 days | `infra_iam_casdoor_archive` |
| `event_outbox`, `event_inbox` | published within 30 days | older | removed |

The component creates future partitions itself, at start and every 24 hours: weekly ones for the outbox and inbox four weeks ahead, monthly ones for `webhook_deliveries` three months ahead. A write into a period with no partition fails, so this loop is what keeps events and webhooks flowing. `refresh_tokens` is never partitioned: it is small and every refresh looks a row up by `jti`. The deletions and the archiving in the table are not implemented yet (see Open questions).

## Data scopes

None (`data_scopes: none`). The tables are this component's own operational data (issued tokens, key metadata, deliveries, reconciliation state); no end-user screen lists them, so there is nothing to scope.

## Reference implementations

| Project | Version | Module consulted | What was borrowed | License | Usage |
|---|---|---|---|---|---|
| Casdoor | not pinned | OIDC endpoints and JWKS, id_token fields, webhook settings, `User.Properties` | webhooks have no signature but take custom headers (hence the shared secret); custom claims (`JWT-Custom`) exist, so mirroring roles into Casdoor was possible and was rejected on architecture alone | Apache-2.0 | Borrowed reasoning |
| OAuth 2.0 Token Exchange (RFC 8693) | — | the request and response of exchanging one token for another | exchanging an id_token for an application token has a standard; field names follow it where they overlap | standard text | Borrowed reasoning |
| Keycloak | not pinned | protocol mappers | the family contract is the intersection both implementations can serve | Apache-2.0 | Borrowed practice |
| Dex | not pinned | connectors | counter-example: multiplexing several upstream IdPs at run time is not needed; the IAM slot is chosen at assembly | Apache-2.0 | Borrowed reasoning |
| Grafana | — | OIDC integration, "which claim holds the role" | confirms that roles in an IdP-signed token are the common shape (documentation only) | AGPL-3 | Borrowed practice |

**Deliberately avoided**: a users shadow table in the adapter (the IAM slot could no longer be replaced without a data migration); Casdoor's own RBAC (role data welded to one implementation); permission keys inside the JWT (an administrator's key set overflows the 8 KB header limit, and every request after login fails with `431`). Implementing an OIDC provider (Ory Hydra, Zitadel) was not considered: Casdoor is the provider.

No new slot family: Casdoor versus Keycloak is the IAM slot itself, of which this component is the default member.

## Open questions

| Question | Current answer |
|---|---|
| Does Casdoor send a stable delivery ID? | No: the record's `id` is `0` in every delivery seen, so dedup uses a body hash (the body includes the record's `name` and `createdTime`, so two different changes are not byte-identical) |
| Deliveries lost while this component is down | Seen on a real Casdoor: it sends webhooks in batches about every 30 seconds, records a failed send as its own `send-webhook` record and does not retry the original. Changes made while this component is down or being redeployed are never bridged, nor is a delivery answered `503` because Casdoor could not be read back. Reconciling users at start (comparing Casdoor with what downstream last heard) would need a copy of the users, which this component deliberately does not keep; undecided |
| A minimal-body `delete-user` for a user this component never had an event for | The delivery has only owner and name, Casdoor no longer has the user and no ID was ever recorded for that name, so it is stored as `IGNORED`. The same happens when a minimal-body `add-user` and `delete-user` of one user land in one batch. Such a user never reached downstream, so nothing is left stale. Deliveries that carry the ID are not affected |
| `infra.iam.login.v1` is declared but never published | No consumer exists yet (the audit component is planned); publish it from the token exchange when one does |
| Expired and revoked refresh tokens, old key metadata and old webhook deliveries are never deleted or archived | The tables grow slowly (bounded by users and by Casdoor activity); a cleanup loop beside the partition loop is the planned answer |
| The Casdoor id_token's audience is not checked | Any application of the same Casdoor instance can produce an id_token this component accepts; acceptable while that Casdoor serves only this project. Checking `aud` against the application's client ID would close it |
| Is the family contract right? | Only a second implementation (`infra/iam-keycloak`) can tell; before adding an rpc, ask whether Keycloak can serve it |
