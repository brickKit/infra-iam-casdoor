# keys：签名密钥（共用）

访问令牌的签名密钥：当前与下一把（轮换），kid 是 RFC 7638 指纹，JWKS 同时发布两把。

## 负责与不负责

- 负责：`KeyRing`（读密钥、`Keys`）、`signingKey`、`parseKey`、`thumbprint`、`Jwk`、`B64`、`B64decode`。
- 不负责：令牌的声明（`login.Issue`）。

## 文件

| 文件 | 内容 |
| --- | --- |
| `keys.go` | 上面全部 |

## 依赖与被依赖

- 依赖：无。
- 被依赖：`provider`（`B64`）、`core`（`Base.Keys`）、`login`；入口建 `KeyRing`。

## 规则在哪

组件协议 P8.1（三种算法、`kid`）。

## 测试

`internal/login/tokens_test.go`（`TestKeyRotation`、`TestTokensPassTheSDKsVerification`）。
