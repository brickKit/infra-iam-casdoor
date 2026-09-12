#!/usr/bin/env bash
# 灌本地开发用的种子身份：一组测试用户（覆盖不同角色/部门画像，不是只
# 有一个全权限超级用户——总纲 SOP-W-7"数据要能真正体现数据权限维度"
# 这条判据）+ 一个开着 ROPC 授权的测试应用（供全部测试用户共用）。
#
# ⚠️ 这里直接打 Casdoor 自己的管理 API（不是本组件的 gRPC/REST），不是
# 例外——Casdoor 是本组件包装的带外容器，"建一个测试身份"这件事物理上
# 就得打它的管理面；本组件的 slot:iam 角色决定了这属于它的职责范围，
# 不是随便找个组件塞进去的。
#
# 用法：make -C components/infra/iam-casdoor seed（或直接跑这个脚本）——
# 幂等，单独跑就能拿到一组可登录的测试身份，不依赖装配层编排。
#
# 这组测试用户是"轻量契约"（同总纲 SOP-W-7 的种子数据契约精神）：
# 用户名固定，任何组件的 seed.sh 都可以直接向 Casdoor 查这些用户名拿
# 到 sub，不需要发明交接协议。角色/部门归属由 infra-authz 自己的
# seed.sh 负责（本脚本只管"这个人存在，能登录"）。
#
#   dev.superuser        「本地测试」超级测试用户   全权限，无部门归属
#   dev.sales.east        「本地测试」销售-华东     dev_sales_rep 角色，华东分部
#   dev.warehouse.south   「本地测试」仓管-华南     dev_warehouse_manager 角色，华南分部
#   dev.finance.viewer    「本地测试」财务只读       dev_finance_viewer 角色，无部门归属
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
SEED_PASSWORD="DevSeed123!"
SEED_APP="local-dev-seed-app"
COOKIE_JAR="$(mktemp)"
trap 'rm -f "$COOKIE_JAR"' EXIT

curl -sf -o /dev/null "$CASDOOR_URL/api/health" || die "Casdoor（$CASDOOR_URL）连不上，先 brickkit up"

curl -c "$COOKIE_JAR" -s -o /dev/null -X POST "$CASDOOR_URL/api/login" \
  -H "Content-Type: application/json" \
  -d '{"application":"app-built-in","organization":"built-in","username":"admin","password":"123","autoSignin":true,"type":"login"}'

# ensure_user <username> <displayName>：幂等建一个 Casdoor 用户。
# add-user 对已存在的用户会报错但不影响后续——用 get-user 先判断存在
# 与否，幂等地跳过创建（不能靠 add-user 的返回码，Casdoor 对"已存在"
# 和"真的失败"用同一种 HTTP 200 + status:error 形状回，靠 msg 文本
# 分辨不可靠）。
ensure_user() {
  local username="$1" display_name="$2"
  local existing
  existing="$(curl -b "$COOKIE_JAR" -s "$CASDOOR_URL/api/get-user?id=brickkit/$username" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("yes" if d.get("data") else "no")')"
  if [ "$existing" = "no" ]; then
    curl -b "$COOKIE_JAR" -s -X POST "$CASDOOR_URL/api/add-user" \
      -H "Content-Type: application/json" \
      -d "{\"owner\":\"brickkit\",\"name\":\"$username\",\"password\":\"$SEED_PASSWORD\",\"email\":\"$username@example.com\",\"displayName\":\"$display_name\",\"type\":\"normal-user\",\"isAdmin\":false,\"countryCode\":\"CN\"}" \
      | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("status")=="ok", d' \
      || die "创建 Casdoor 用户 $username 失败"
    ok "已创建 Casdoor 用户 $username"
  else
    ok "Casdoor 用户 $username 已存在，跳过创建"
  fi
}

ensure_user "dev.superuser"      "「本地测试」超级测试用户"
ensure_user "dev.sales.east"     "「本地测试」销售-华东"
ensure_user "dev.warehouse.south" "「本地测试」仓管-华南"
ensure_user "dev.finance.viewer" "「本地测试」财务只读"

# ⚠️ 实测踩坑：应用被真实登录过一次之后，Casdoor 会往 get-application
# 响应的 signinItems.customCss 里塞一个带字面换行符（不是转义 \n）的
# 默认主题 CSS——严格模式的 JSON 解析会报 "Invalid control character"。
# 用 strict=False 放宽，我们只关心 data 存不存在，不关心这个 UI 主题
# 字段本身对不对。
EXISTING_APP="$(curl -b "$COOKIE_JAR" -s "$CASDOOR_URL/api/get-application?id=admin/$SEED_APP" | python3 -c 'import json,sys; d=json.load(sys.stdin, strict=False); print("yes" if d.get("data") else "no")')"
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

sub_of() {
  curl -b "$COOKIE_JAR" -s "$CASDOOR_URL/api/get-user?id=brickkit/$1" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["id"])'
}
for u in dev.superuser dev.sales.east dev.warehouse.south dev.finance.viewer; do
  sub="$(sub_of "$u")"
  [ -n "$sub" ] || die "拿不到 $u 的 sub"
  ok "$u 的 sub = $sub"
done
