#!/usr/bin/env python3
"""Prepares Casdoor for a development or test deployment of infra/iam-casdoor (BRICKKIT.md, "deployment
preparation"): the login application, the development client with the password grant (A101: never in a production
deployment), and test users. Idempotent: what exists is updated to the wanted state. Prints names only, never a
secret. Standard library only.

Environment: CASDOOR_URL (e.g. http://localhost:8000), CASDOOR_ADMIN_PASSWORD (the built-in admin), CASDOOR_ORG
(default brickkit), IAM_CLIENT_ID, IAM_CLIENT_SECRET, IAM_CALLBACK_URL, IAM_DEV_CLIENT_ID, IAM_DEV_CLIENT_SECRET,
IAM_TEST_USERS (comma-separated user names), IAM_TEST_PASSWORD (their password).

    python3 -I scripts/dev_setup.py
"""
import http.cookiejar
import json
import os
import sys
import urllib.request

E = os.environ
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
    upsert("application", "admin", *application("be-iam", E["IAM_CLIENT_ID"], E["IAM_CLIENT_SECRET"],
                                                ["authorization_code"], [E["IAM_CALLBACK_URL"]]))
    upsert("application", "admin", *application("be-iam-dev", E["IAM_DEV_CLIENT_ID"], E["IAM_DEV_CLIENT_SECRET"],
                                                ["password"], []))
    for user in filter(None, E.get("IAM_TEST_USERS", "").split(",")):
        upsert("user", ORG, user, {"displayName": user, "type": "normal-user", "password": E["IAM_TEST_PASSWORD"],
                                   "isForbidden": False, "signupApplication": "be-iam"})


if __name__ == "__main__":
    main()
