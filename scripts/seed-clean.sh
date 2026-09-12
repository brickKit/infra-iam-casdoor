#!/usr/bin/env bash
# 撤销 seed.sh 灌的测试身份——删全部测试用户 + 测试应用。
set -euo pipefail

C_GRN=$'\033[32m'; C_RED=$'\033[31m'; C_OFF=$'\033[0m'
ok()  { echo "${C_GRN}✓${C_OFF} $*"; }
die() { echo "${C_RED}✗${C_OFF} $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "缺少命令：$1"; }
need curl; need python3

CASDOOR_URL="${CASDOOR_URL:-http://localhost:8000}"
SEED_APP="local-dev-seed-app"
COOKIE_JAR="$(mktemp)"
trap 'rm -f "$COOKIE_JAR"' EXIT

curl -sf -o /dev/null "$CASDOOR_URL/api/health" || die "Casdoor（$CASDOOR_URL）连不上，先 brickkit up"

curl -c "$COOKIE_JAR" -s -o /dev/null -X POST "$CASDOOR_URL/api/login" \
  -H "Content-Type: application/json" \
  -d '{"application":"app-built-in","organization":"built-in","username":"admin","password":"123","autoSignin":true,"type":"login"}'

# ⚠️ 实测踩坑：delete-application 只给 {owner,name} 时返回
# status:ok + data:"Unaffected"——看起来成功，应用其实原封不动没删掉
# （直接 curl 验证过：删完立刻 get-application 还在）。跟 delete-user
# 不一样（那个给 {owner,name} 就真删），delete-application 必须先
# get-application 拿完整对象再整个传回去做 body，Casdoor 内部拿它去
# 匹配的字段比 owner/name 多。应用不存在时 get-application 的 data
# 是 null，直接跳过。
# ⚠️ 同 scripts/seed.sh 的既有注释：应用真实登录过一次之后，
# get-application 响应里会带字面换行符的 customCss，strict=False 放宽。
APP_JSON="$(curl -b "$COOKIE_JAR" -s "$CASDOOR_URL/api/get-application?id=admin/$SEED_APP")"
if echo "$APP_JSON" | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin, strict=False).get("data") else 1)'; then
  echo "$APP_JSON" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin, strict=False)["data"]))' \
    | curl -b "$COOKIE_JAR" -s -X POST "$CASDOOR_URL/api/delete-application" \
      -H "Content-Type: application/json" -d @- >/dev/null
  ok "已删除 Casdoor 测试应用 $SEED_APP"
else
  ok "Casdoor 测试应用 $SEED_APP 不存在，跳过"
fi

for u in dev.superuser dev.sales.east dev.warehouse.south dev.finance.viewer; do
  curl -b "$COOKIE_JAR" -s -X POST "$CASDOOR_URL/api/delete-user" \
    -H "Content-Type: application/json" \
    -d "{\"owner\":\"brickkit\",\"name\":\"$u\"}" >/dev/null
  ok "已删除 Casdoor 用户 $u（不存在也不报错）"
done
