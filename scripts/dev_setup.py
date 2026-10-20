#!/usr/bin/env python3
"""Prepares Casdoor for a development or test deployment of infra/iam-casdoor (BRICKKIT.md, "deployment
preparation"): the login application, the development client with the password grant (A101: never in a production
deployment), and test users. Idempotent: what exists is updated to the wanted state. Prints names only, never a
secret. Standard library only.

The test users are the seed data's accounts (be-assembly-standard's seed and test data conventions): TEST_USERS below,
one per role and scope the other components' seeds grant to, plus any named in IAM_TEST_USERS. Their user names are a
light contract: the other seeds find them by name, so a name is only ever added, never removed or given another
meaning. `--users-only` (make seed) creates the users alone, without touching the applications.

Environment: CASDOOR_URL (e.g. http://localhost:8000), CASDOOR_ADMIN_PASSWORD (the built-in admin), CASDOOR_ORG
(default brickkit), IAM_TEST_PASSWORD (the test users' password); without --users-only also IAM_CLIENT_ID,
IAM_CLIENT_SECRET, IAM_CALLBACK_URL, IAM_DEV_CLIENT_ID, IAM_DEV_CLIENT_SECRET; IAM_TEST_USERS (comma-separated extra
user names, optional).

    python3 -I scripts/dev_setup.py [--users-only]
"""
import http.cookiejar
import json
import os
import sys
import urllib.request

E = os.environ
PREFIX = "「本地测试」"
# the seed accounts: user name -> display name (what they stand for is in be-assembly-standard's seed data inventory)
TEST_USERS = {
    "test.alice": "授权管理员",
    "test.bob": "负载用户（全部操作）",
    "test.mdm.admin": "主数据管理员",
    "test.mdm.viewer": "主数据只读",
    "test.rates": "汇率维护员",
    "test.sales.cn": "销售 CN01 华东区",
    "test.sales.es": "销售 ES01",
    "test.sales.multi": "销售 CN01 华东区与华南区",
    "test.unit.admin.cn": "中国区授权管理员",
    "test.revoked": "授予已撤销",
    "test.expired": "授予已过期",
    "test.nobody": "没有任何授予",
}
BASE = E["CASDOOR_URL"].rstrip("/")
ORG = E.get("CASDOOR_ORG", "brickkit")
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def call(path, body=None):
    req = urllib.request.Request(BASE + path, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with opener.open(req, timeout=10) as r:
        out = json.loads(r.read())
    if out.get("status") not in (None, "ok"):
        sys.exit(f"{path}: {out.get('msg')}")
    return out


def upsert(kind, owner, name, wanted):
    """get-<kind>, then add-<kind> or update-<kind> with the wanted fields over what exists."""
    got = call(f"/api/get-{kind}?id={owner}/{name}").get("data")
    if got:
        call(f"/api/update-{kind}?id={owner}/{name}", {**got, **wanted})
        print(f"{kind} {owner}/{name}: updated")
    else:
        call(f"/api/add-{kind}", {"owner": owner, "name": name, "createdTime": "2026-10-19T00:00:00Z", **wanted})
        print(f"{kind} {owner}/{name}: added")


def application(name, client_id, secret, grants, redirects):
    return name, {"displayName": name, "organization": ORG, "clientId": client_id, "clientSecret": secret,
                  "grantTypes": grants, "redirectUris": redirects, "tokenFormat": "JWT", "cert": "cert-built-in",
                  "expireInHours": 1, "refreshExpireInHours": 1, "enablePassword": True,
                  "signinMethods": [{"name": "Password", "displayName": "Password", "rule": "All"}],
                  "signupItems": [], "providers": []}


def main():
    call("/api/login", {"application": "app-built-in", "organization": "built-in", "username": "admin",
                        "password": E["CASDOOR_ADMIN_PASSWORD"], "type": "login"})
    users = {**TEST_USERS, **{u: u for u in filter(None, E.get("IAM_TEST_USERS", "").split(",")) if u not in TEST_USERS}}
    if "--users-only" not in sys.argv[1:]:
        applications()
    for user, display in users.items():
        upsert("user", ORG, user, {"displayName": PREFIX + display, "type": "normal-user",
                                   "password": E["IAM_TEST_PASSWORD"], "isForbidden": False, "signupApplication": "be-iam"})


def applications():
    upsert("application", "admin", *application("be-iam", E["IAM_CLIENT_ID"], E["IAM_CLIENT_SECRET"],
                                                ["authorization_code"], [E["IAM_CALLBACK_URL"]]))
    upsert("application", "admin", *application("be-iam-dev", E["IAM_DEV_CLIENT_ID"], E["IAM_DEV_CLIENT_SECRET"],
                                                ["password"], []))


if __name__ == "__main__":
    main()
