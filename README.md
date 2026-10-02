[English](README.md) · [中文](README.zh.md)

# infra/iam-casdoor

A thin adapter in front of Casdoor; issues and refreshes application tokens, serves /api/tenant/features and bridges Casdoor webhooks.

## Use it in a project

```bash
brickkit add infra/iam-casdoor@2.0.0
brickkit up
```

Prepare first: see "Before you deploy" in BRICKKIT.md (a PostgreSQL schema and login role, NATS, a running Casdoor with an administrator account, an RSA signing key, a webhook shared secret, and `infra/authz`).

## Documentation

| To find out | Read |
|---|---|
| What it does and does not do, how to configure it, what to prepare | [BRICKKIT.md](BRICKKIT.md) |
| Its gRPC, REST and event contracts | [contracts/](contracts/) |
| Why it is designed this way: two tokens, fail-closed claims, sessions that end, webhook dedup and the delivery queue, user events read back from Casdoor, open questions | [docs/design.md](docs/design.md) |
| What it depends on (`infra/authz`) and its configuration keys | [component.yaml](component.yaml) |
| How to develop it: code map, tests, pitfalls | [AGENTS.md](AGENTS.md) |

## Development

Go 1.25, Gin, `database/sql` with pgx, golang-migrate through be-sdk-go. Tests need a real PostgreSQL (`TEST_PG_DSN`); the Casdoor tests need a running Casdoor (`TEST_CASDOOR_BASE_URL`); the commands and what success looks like are in AGENTS.md, section "Build and test". Inside the BrickEnterprise project, `make verify ID=infra/iam-casdoor FOCUS=1` at the project root runs it for real, in a container and as a local process, and tears down afterwards.
