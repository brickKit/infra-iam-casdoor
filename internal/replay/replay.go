package replay

import (
	"context"
	"fmt"
	"time"

	core "github.com/brickKit/infra-iam-casdoor/v3/internal/core"

	"github.com/brickKit/be-sdk-go/v3/evidence"
)

// The replay of this member's evidence in a full recovery's step 6 (assembly protocol 15, 6.3; be-protocol
// P12.19-P12.21): an account's status (a disablement, a freeze, a console disablement, a rollback, a re-enable) and a
// forced logout are applied again here as recorded, without the business preconditions (the authorization member's
// check, the requester's rights): they held when the change was made. Only the account must exist. Casdoor is not
// called in the transaction: the comparison with Casdoor (P_pull) forbids or allows it there again, as for any
// status this member holds. The credential tightenings (a password changed here, the second factors reset here, a
// credential change seen in Casdoor) cannot be made again: Casdoor is outside the recovery group (A141), so 6.7 checks
// them against Casdoor instead (be-protocol P12.20, checkCredential).

// clockSkew is the clock offset declared between this member and Casdoor (assembly protocol 15's parameters: 2 s).
const clockSkew = 2 * time.Second

// CheckCredential is 6.7 with Casdoor outside the recovery group: whether a credential tightening still holds in
// Casdoor. A password changed here holds when Casdoor's last password change is not earlier than the record; a reset
// of the second factors holds when Casdoor has none now or has changed since; a change seen in Casdoor holds when
// Casdoor is not older than what was seen. Casdoor's times have one-second precision, so the record's time is taken
// less the declared skew. Not so: Casdoor went back on its own, for review.
func CheckCredential(m *core.Base, ctx context.Context, rec evidence.Replayed) (bool, string, error) {
	username, err := m.Store.UsernameOf(ctx, rec.Object.ID)
	if err != nil {
		return false, "", err
	}
	if username == "" {
		return false, "no such account here", nil
	}
	u, err := m.Casdoor.ProductUser(ctx, username)
	if err != nil {
		return false, "", err
	}
	kind, _ := rec.Change["kind"].(string)
	since := rec.At.Add(-clockSkew)
	if rec.Category == "credential_tightening_in_product" {
		seen, _ := rec.Change["product_updated"].(string)
		if !notBefore(u.UpdatedTime, parseProductTime(seen)) {
			return false, fmt.Sprintf("Casdoor's user was updated at %q, before the change seen at %q", u.UpdatedTime, seen), nil
		}
		return true, "", nil
	}
	switch kind {
	case "password":
		if !notBefore(u.LastChangePasswordTime, since) {
			return false, fmt.Sprintf("Casdoor's last password change %q is before the record", u.LastChangePasswordTime), nil
		}
	case "second_factor":
		if u.HasFactors() && !notBefore(u.UpdatedTime, since) {
			return false, fmt.Sprintf("Casdoor has second factors, unchanged since %q, before the reset", u.UpdatedTime), nil
		}
	default:
		return false, fmt.Sprintf("a credential tightening of kind %q", kind), nil
	}
	return true, "", nil
}

// parseProductTime reads one of Casdoor's times (RFC 3339); a time that does not parse is the zero time.
func parseProductTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// notBefore: Casdoor's time is set and not before t (a time that does not parse is not).
func notBefore(product string, t time.Time) bool {
	p := parseProductTime(product)
	return !p.IsZero() && !p.Before(t)
}
