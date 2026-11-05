package iam

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"

	"github.com/brickKit/be-sdk-go/v3/calls"
	"github.com/brickKit/be-sdk-go/v3/errs"
)

// The management side towards Casdoor (security 03, "身份成员由外部产品承载时"): the users of an organization as they
// are now, for the full comparison; forbidding or allowing a user (the comparison's rollback, the account operations);
// ending a user's Casdoor sessions (a forced logout) and removing the second factors (their reset).
// The login application's client credentials authorize both (Casdoor 4.1.0: an application's credentials manage
// the users of its organization), sent as Basic, never in the URL.

// productUser is what the comparison reads of a Casdoor user (object/user.go of Casdoor 4.1.0).
type productUser struct {
	ID                     string   `json:"id"`
	Owner                  string   `json:"owner"`
	Name                   string   `json:"name"`
	IsForbidden            bool     `json:"isForbidden"`
	IsDeleted              bool     `json:"isDeleted"`
	LastChangePasswordTime string   `json:"lastChangePasswordTime"`
	UpdatedTime            string   `json:"updatedTime"`
	PreferredMfaType       string   `json:"preferredMfaType"`
	MfaPhoneEnabled        bool     `json:"mfaPhoneEnabled"`
	MfaEmailEnabled        bool     `json:"mfaEmailEnabled"`
	TotpSecret             string   `json:"totpSecret"`
	RecoveryCodes          []string `json:"recoveryCodes"`
}

// hasFactors: the user has a second factor in the product.
func (u productUser) hasFactors() bool {
	return u.PreferredMfaType != "" || u.MfaPhoneEnabled || u.MfaEmailEnabled || u.TotpSecret != ""
}

// off: the product refuses the user's sign-in (forbidden or deleted).
func (u productUser) off() bool { return u.IsForbidden || u.IsDeleted }

// secondFactors is a digest of the second factors' state: a change in it (a factor removed, reset or added outside
// this member) is a security change. The secrets themselves are never kept.
func (u productUser) secondFactors() string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%t|%t|%s|%d", u.PreferredMfaType, u.MfaPhoneEnabled, u.MfaEmailEnabled,
		hashOf(u.TotpSecret), len(u.RecoveryCodes))))
	return hex.EncodeToString(h[:16])
}

func (c *casdoor) basic() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(c.clientID+":"+c.secret()))
}

type casdoorAnswer struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

func (a casdoorAnswer) err(what string) error {
	if a.Status == "ok" {
		return nil
	}
	return errs.New(errs.ReasonDependencyUnavailable, "casdoor refused "+what).With("dependency", "casdoor").
		Wrap(fmt.Errorf("casdoor: %s", a.Msg))
}

// users reads every user of an organization as Casdoor has it now.
func (c *casdoor) users(ctx context.Context, owner string) ([]productUser, error) {
	var ans casdoorAnswer
	if err := c.http.Do(ctx, calls.Request{Method: "GET", Path: "/api/get-users?owner=" + url.QueryEscape(owner),
		Credential: c.basic()}, &ans); err != nil {
		return nil, err
	}
	if err := ans.err("the user list of " + owner); err != nil {
		return nil, err
	}
	var out []productUser
	if err := json.Unmarshal(ans.Data, &out); err != nil {
		return nil, errs.From(fmt.Errorf("casdoor: the user list of %s: %w", owner, err))
	}
	return out, nil
}

// user reads one user (owner/name).
func (c *casdoor) user(ctx context.Context, username string) (map[string]any, error) {
	var ans casdoorAnswer
	if err := c.http.Do(ctx, calls.Request{Method: "GET", Path: "/api/get-user?id=" + url.QueryEscape(username),
		Credential: c.basic()}, &ans); err != nil {
		return nil, err
	}
	if err := ans.err("the user " + username); err != nil {
		return nil, err
	}
	var u map[string]any
	if err := json.Unmarshal(ans.Data, &u); err != nil || u == nil {
		return nil, errs.New(errs.ReasonDependencyUnavailable, "casdoor: no user "+username).With("dependency", "casdoor")
	}
	return u, nil
}

// productUser reads one user as the comparison sees it.
func (c *casdoor) productUser(ctx context.Context, username string) (productUser, error) {
	var out productUser
	u, err := c.user(ctx, username)
	if err != nil {
		return out, err
	}
	raw, _ := json.Marshal(u)
	return out, json.Unmarshal(raw, &out)
}

// endSessions ends every Casdoor session of a user, in any application (its single sign-on would otherwise let the
// browser in again without credentials): each session row and its sign-in sessions are deleted.
func (c *casdoor) endSessions(ctx context.Context, username string) error {
	owner, name, _ := cut(username)
	var ans casdoorAnswer
	if err := c.http.Do(ctx, calls.Request{Method: "GET", Path: "/api/get-sessions?owner=" + url.QueryEscape(owner),
		Credential: c.basic()}, &ans); err != nil {
		return err
	}
	if err := ans.err("the sessions of " + owner); err != nil {
		return err
	}
	var sessions []struct{ Owner, Name, Application string }
	if err := json.Unmarshal(ans.Data, &sessions); err != nil {
		return errs.From(fmt.Errorf("casdoor: the sessions of %s: %w", owner, err))
	}
	for _, s := range sessions {
		if s.Name != name {
			continue
		}
		var del casdoorAnswer
		if err := c.http.Do(ctx, calls.Request{Method: "POST", Path: "/api/delete-session", Idempotent: true,
			Body: map[string]string{"owner": s.Owner, "name": s.Name, "application": s.Application}, Credential: c.basic()}, &del); err != nil {
			return err
		}
		if err := del.err("ending a session of " + username); err != nil {
			return err
		}
	}
	return nil
}

// deleteFactors removes every second factor of a user (Casdoor's delete-mfa: a form, not JSON).
func (c *casdoor) deleteFactors(ctx context.Context, username string) error {
	owner, name, _ := cut(username)
	var ans casdoorAnswer
	if err := c.http.Do(ctx, calls.Request{Method: "POST", Path: "/api/delete-mfa", Idempotent: true,
		Form: url.Values{"owner": {owner}, "name": {name}}, Credential: c.basic()}, &ans); err != nil {
		return err
	}
	return ans.err("removing the second factors of " + username)
}

// setForbidden writes a user's isForbidden in Casdoor: the whole user read back and sent again (update-user replaces
// the user; an absent field would be cleared).
func (c *casdoor) setForbidden(ctx context.Context, username string, forbidden bool) error {
	u, err := c.user(ctx, username)
	if err != nil {
		return err
	}
	u["isForbidden"] = forbidden
	var ans casdoorAnswer
	if err := c.http.Do(ctx, calls.Request{Method: "POST", Path: "/api/update-user?id=" + url.QueryEscape(username),
		Body: u, Idempotent: true, Credential: c.basic()}, &ans); err != nil {
		return err
	}
	if err := ans.err("forbidding " + username + ": " + strconv.FormatBool(forbidden)); err != nil {
		return err
	}
	return nil
}
