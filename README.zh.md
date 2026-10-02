[English](README.md) · [中文](README.zh.md)

# infra/iam-casdoor

Casdoor 前面的一层薄适配：签发与刷新应用 token，提供 /api/tenant/features，桥接 Casdoor 的 webhook。

## 在项目里使用

```bash
brickkit add infra/iam-casdoor@2.0.0
brickkit up
```

先看 BRICKKIT.zh.md 的"部署前准备"（PostgreSQL 的 schema 与登录角色、NATS、一个在跑且有管理员账号的 Casdoor、一把 RSA 签名密钥、webhook 共享密钥，以及 `infra/authz`）。

## 文档

| 想知道 | 读 |
|---|---|
| 它做什么、不做什么、怎么配置、要准备什么 | [BRICKKIT.zh.md](BRICKKIT.zh.md) |
| gRPC、REST 与事件契约 | [contracts/](contracts/) |
| 为什么这样设计：两个 token、claims 失败关闭、webhook 去重、用户事件回读 Casdoor、未决问题 | [docs/design.zh.md](docs/design.zh.md) |
| 依赖什么（`infra/authz`）、有哪些配置键 | [component.yaml](component.yaml) |
| 怎么开发：代码地图、测试、易错点 | [AGENTS.zh.md](AGENTS.zh.md) |

## 开发

Go 1.25、Gin、`database/sql` + pgx、经 be-sdk-go 的 golang-migrate。测试要真实的 PostgreSQL（`TEST_PG_DSN`）；Casdoor 测试要一个在跑的 Casdoor（`TEST_CASDOOR_BASE_URL`）；确切命令与成功的样子见 AGENTS.zh.md 的"构建与测试"。在 BrickEnterprise 项目里，项目根目录的 `make verify ID=infra/iam-casdoor FOCUS=1` 以容器与本机进程两种方式真机跑一遍，结束后收尾。
