# itest/：集成测试与测试索引

身份成员对着真实的 Casdoor、PostgreSQL 与消息系统的端到端测试：开发换取、按签发者绑定、浏览器登录、边缘经 mTLS 的换取与已结束会话、改密码（一次性用户，测完删掉）、空闲超时与登出、与 Casdoor 的比较、账号操作（授权成员是 sectest 的替身，`AccountCheck` 设它的回答）、证据的重放、整套恢复的 6.6（最后一步：推进恢复代次、以恢复阶段重启成员，结束全部会话）。构建标签 `integration`；按模块分文件。

## 怎样跑

- `go test -count=1 -tags integration ./itest/`，约 30 秒。
- 先运行 `scripts/dev_setup.py`；环境变量（`IAM_IT_PG_PASSWORD`、`IAM_IT_BUS_URL`、`IAM_IT_CLIENT_SECRET`、`IAM_IT_DEV_CLIENT_SECRET`、`IAM_IT_TEST_PASSWORD`、`IAM_IT_CASDOOR_ADMIN_PASSWORD`、`IAM_IT_KEY_FILE` 等，见 `endtoend_integration_test.go` 的 `need`）缺一个就失败，不会跳过；装配项目里 `make up` 起了 `be-casdoor`；系统面的端口 9200 要空着。
- **只有一个测试** `TestEndToEndAgainstCasdoor`：按下表的顺序跑各步（`iamRun` 的方法），后面的步用前面的会话与账号，所以一步不能单独跑；最后核对日志里没有密码与会话 Cookie。

## 文件

按运行顺序：

| 文件 | 步 | 测的流程 | 被测的模块 |
| --- | --- | --- | --- |
| `login_integration_test.go` | `tokens` | 开发换取的令牌通过核验、按签发者绑定 | `login` |
| `sessions_integration_test.go` | `edgeSessions`、`passwordChange` | 浏览器登录后边缘经 mTLS 换取、已结束的会话；改密码（一次性用户） | `sessions`、`login` |
| `accounts_integration_test.go` | `accountReads` | 账号状态流的批量读取与快照（只许 `infra/authz`） | `accounts` |
| `sessions_integration_test.go` | `idleAndLogout` | 空闲超时与登出 | `sessions`、`login` |
| `reconcile_integration_test.go` | `comparison` | 与 Casdoor 比较：控制台停用、回退、密码与第二因素的变更 | `reconcile`、`core` |
| `accounts_integration_test.go` | `accountOperations` | 停用、冻结、启用（授权成员的回答）、强制登出、重置第二因素 | `accounts` |
| `replay_integration_test.go` | `replay` | 证据的重放：状态与强制登出重新施加，凭据收紧对照 Casdoor 核对 | `replay`、`core` |
| `recovery_integration_test.go` | `recovery` | 整套恢复的 6.6：推进恢复代次、以恢复阶段重启成员，结束全部会话 | `sessions`、`core` |

共用的：

| 文件 | 内容 |
| --- | --- |
| `endtoend_integration_test.go` | `TestEndToEndAgainstCasdoor`（各步的顺序）；环境与 Casdoor 的辅助（`need`、`send`、`casdoorSubject`、`casdoorAdmin`、`browserLogin`、`throwawayUser`）；`iamRun` 与 `startIAM`、`restart`、`serve`、`verify`、`exchange`、`ended`、`endedSince` 等 |

## 加测试

新流程加一步（`iamRun` 的方法）放进它模块的文件，在 `TestEndToEndAgainstCasdoor` 里按依赖排进顺序，在上表加一行；测试不为了通过而改。
