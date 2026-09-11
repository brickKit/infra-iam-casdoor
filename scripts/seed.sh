#!/usr/bin/env bash
# 灌本地开发用的种子身份：一个万能测试用户 + 一个开着 ROPC 授权的测试
# 应用（同 mdm-customer/mdm-product 的既有判据，总纲 SOP-W-7：种子数据
# 归各组件自己持有）。
#
# ⚠️ 这里直接打 Casdoor 自己的管理 API（不是本组件的 gRPC/REST），不是
# 例外——Casdoor 是本组件包装的带外容器，"建一个测试身份"这件事物理上
# 就得打它的管理面；本组件的 slot:iam 角色决定了这属于它的职责范围，
# 不是随便找个组件塞进去的。
#
# 用法：make -C components/infra/iam-casdoor seed（或直接跑这个脚本）——
# 幂等，单独跑就能拿到一个可登录的测试身份，不依赖装配层编排。
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$(cd "$DIR/../../.." && pwd)"

C_GRN=$'\033[32m'; C_RED=$'\033[31m'; C_OFF=$'\033[0m'
ok()  { echo "${C_GRN}✓${C_OFF} $*"; }
die() { echo "${C_RED}✗${C_OFF} $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "缺少命令：$1"; }
need curl; need python3

# Casdoor 是带外容器，管理 API 走宿主机映射端口（同装配仓库
# infra/seed-data/seed.sh 的既有约定，不是这里新起的）。
CASDOOR_URL="${CASDOOR_URL:-http://localhost:8000}"
SEED_USER="dev.superuser"
SEED_PASSWORD="DevSeed123!"
SEED_APP="local-dev-seed-app"
COOKIE_JAR="$(mktemp)"
trap 'rm -f "$COOKIE_JAR"' EXIT

curl -sf -o /dev/null "$CASDOOR_URL/api/health" || die "Casdoor（$CASDOOR_URL）连不上，先 brickkit up"

curl -c "$COOKIE_JAR" -s -o /dev/null -X POST "$CASDOOR_URL/api/login" \
  -H "Content-Type: application/json" \
  -d '{"application":"app-built-in","organization":"built-in","username":"admin","password":"123","autoSignin":true,"type":"login"}'

# add-user 对已存在的用户会报错但不影响后续——用 get-user 先判断存在与否，
# 幂等地跳过创建（不能靠 add-user 的返回码，Casdoor 对"已存在"和"真的
# 失败"用同一种 HTTP 200 + status:error 形状回，靠 msg 文本分辨不可靠）。
EXISTING_USER="$(curl -b "$COOKIE_JAR" -s "$CASDOOR_URL/api/get-user?id=brickkit/$SEED_USER" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("yes" if d.get("data") else "no")')"
if [ "$EXISTING_USER" = "no" ]; then
  curl -b "$COOKIE_JAR" -s -X POST "$CASDOOR_URL/api/add-user" \
    -H "Content-Type: application/json" \
    -d "{\"owner\":\"brickkit\",\"name\":\"$SEED_USER\",\"password\":\"$SEED_PASSWORD\",\"email\":\"$SEED_USER@example.com\",\"displayName\":\"「本地测试」超级测试用户\",\"type\":\"normal-user\",\"isAdmin\":false,\"countryCode\":\"CN\"}" \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("status")=="ok", d' \
    || die "创建 Casdoor 用户失败"
  ok "已创建 Casdoor 用户 $SEED_USER"
else
  ok "Casdoor 用户 $SEED_USER 已存在，跳过创建"
fi

EXISTING_APP="$(curl -b "$COOKIE_JAR" -s "$CASDOOR_URL/api/get-application?id=admin/$SEED_APP" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("yes" if d.get("data") else "no")')"
if [ "$EXISTING_APP" = "no" ]; then
  curl -b "$COOKIE_JAR" -s -X POST "$CASDOOR_URL/api/add-application" \
    -H "Content-Type: application/json" \
    -d "{\"owner\":\"admin\",\"name\":\"$SEED_APP\",\"displayName\":\"$SEED_APP\",\"organization\":\"brickkit\",\"cert\":\"cert-built-in\",\"enablePassword\":true,\"enableSignUp\":false,\"redirectUris\":[\"http://localhost:3000/callback\"],\"grantTypes\":[\"authorization_code\",\"password\",\"refresh_token\"],\"tokenFormat\":\"JWT\",\"expireInHours\":24,\"refreshExpireInHours\":168}" \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("status")=="ok", d' \
    || die "创建 Casdoor ROPC 测试应用失败"
  ok "已创建 Casdoor ROPC 测试应用 $SEED_APP（⚠️ 只应该存在于本地环境，见 infra/seed-data/README.md）"
else
  ok "Casdoor ROPC 测试应用 $SEED_APP 已存在，跳过创建"
fi

USER_JSON="$(curl -b "$COOKIE_JAR" -s "$CASDOOR_URL/api/get-user?id=brickkit/$SEED_USER")"
SEED_SUB="$(echo "$USER_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["id"])')"
[ -n "$SEED_SUB" ] || die "拿不到 $SEED_USER 的 sub"
ok "$SEED_USER 的 sub = $SEED_SUB"
