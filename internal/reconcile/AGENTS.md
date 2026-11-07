# reconcile：与 Casdoor 比较

与 Casdoor 的全量比较（安全 03）：定期作业（`IAM_PULL_INTERVAL`）与授权成员每次补取的“回声之前”（`PullRef.Before`）；每个账号在行锁内比较、记证据（`core.Store.Compare`）：控制台停用照常生效，本组件停用的账号在 Casdoor 被启用时判为回退，在 Casdoor 里改密码或第二因素是安全变更。

## 负责与不负责

- 负责：`DefaultPullInterval`、`JobPull`、`PullRef`、`bound`、`Reconcile`、`Pull`。
- 不负责：一个账号怎样比较、记什么（`core.Store.Compare`）。

## 文件

| 文件 | 内容 |
| --- | --- |
| `reconcile.go` | 上面全部 |

## 依赖与被依赖

- 依赖：`core`、`provider`。
- 被依赖：`accounts`；入口（作业、`Definition` 的事件流）。

## 规则在哪

`docs/design.md` 实现状态 3.0.21；安全 03；组件协议 P9.16。

## 测试

`itest/reconcile_integration_test.go`（`comparison`）。
