# infra-iam-casdoor

组件 `infra/iam-casdoor`（身份适配，Casdoor）的仓库。旧版本（2.x）在分支 `legacy/v2`，标签保留；本主分支按终局设计从零开始（D59），版本从 `3.0.0` 起（A110）。

## 在项目里使用

在装配项目里 `brickkit add infra/iam-casdoor@<版本>`，再按 `BRICKKIT.md` 的“部署前准备”配置 Casdoor、签名密钥与数据库。

## 文档

| 问题 | 看哪里 |
| --- | --- |
| 它做什么、怎样部署与配置 | `BRICKKIT.md` |
| 怎样改它 | `AGENTS.md` |
| 设计依据 | 装配项目 be-assembly-standard 的边界卡 `docs/zh/07-components/infra.md`，安全 02、03、11，协议 20 |
| 族契约 | `contract-infra-iam` 仓库 |

## 开发

见 `AGENTS.md` 的“构建与测试”。
