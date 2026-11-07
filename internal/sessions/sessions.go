package sessions

import (
	"context"
	"net/http"
	"time"

	core "github.com/brickKit/infra-iam-casdoor/v3/internal/core"
	login "github.com/brickKit/infra-iam-casdoor/v3/internal/login"
	provider "github.com/brickKit/infra-iam-casdoor/v3/internal/provider"

	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/events"
	"github.com/brickKit/be-sdk-go/v3/httpx"
	"github.com/brickKit/be-sdk-go/v3/sessionpb"
)

// Ended's page size (be-protocol P8.28).
const (
	endedDefault = 500
	endedMax     = 2000
)

// sessions is the edge's side of the member: SessionService (be.session.v1, P8.28), callable by infra/edge only.
// newSessions is the session service over the module.
func NewSessions(m *core.Base) *sessions { return &sessions{m: m} }

type sessions struct {
	sessionpb.UnimplementedSessionServiceServer
	m *core.Base
}

// Exchange is a live session's access token, at the account's current security version; SESSION_ENDED otherwise.
// The session row's lock makes the exchanges of one session go one at a time.
func (s *sessions) Exchange(ctx context.Context, in *sessionpb.ExchangeRequest) (*sessionpb.ExchangeResponse, error) {
	if in.GetSessionDigest() == "" {
		return nil, errs.New(errs.ReasonRequestInvalid, "session_digest is required")
	}
	if p := s.m.RT.RecoveryPhase(); p != "" && p != "read_only" { // no token while a full recovery runs, until the read-only opening (P1.23)
		return nil, errs.New(errs.ReasonMaintenance, "a full recovery is running")
	}
	a, until, ok, err := s.m.Store.Use(ctx, in.GetSessionDigest(), s.m.Idle, s.m.Absolute, in.GetRenewIdle())
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errs.New(errs.ReasonSessionEnded, "no live session")
	}
	tok, exp, err := login.Issue(s.m, a.Principal, a.SecurityVersion, time.Now(), until)
	if err != nil {
		return nil, err
	}
	return &sessionpb.ExchangeResponse{AccessToken: tok, ExpiresAtMs: exp.UnixMilli(), Principal: a.Principal,
		SessionUntilMs: until.UnixMilli()}, nil
}

// Ended is the sessions that ended after the edge's cursor, read from the ended stream by position.
func (s *sessions) Ended(ctx context.Context, in *sessionpb.EndedRequest) (*sessionpb.EndedResponse, error) {
	limit := int(in.GetLimit())
	switch {
	case limit == 0:
		limit = endedDefault
	case limit > endedMax:
		return nil, errs.New(errs.ReasonRequestInvalid, "limit is at most 2000")
	}
	var after *events.Cursor
	if c := in.GetAfter(); c != nil {
		e, err := events.ParseEpoch(c.GetEpoch())
		if err != nil {
			return nil, errs.New(errs.ReasonRequestInvalid, "the cursor's epoch is not <generation>.<timeline>")
		}
		after = &events.Cursor{Impl: c.GetImpl(), Epoch: e, Seq: int64(c.GetSeq())}
	}
	rows, next, reset, err := events.ReadAfter(ctx, s.m.RT.DB, s.m.Impl, core.StreamEnded, 0, after, limit)
	if err != nil {
		return nil, err
	}
	out := &sessionpb.EndedResponse{Reset_: reset, Next: &sessionpb.Cursor{Impl: next.Impl, Epoch: next.Epoch.String(),
		Seq: uint64(next.Seq)}}
	for _, r := range rows {
		out.SessionDigests = append(out.SessionDigests, r.RecordID)
	}
	return out, nil
}

// ChangePassword is the user's password change, made through this member so that it knows the session making it
// (protocol 20): Casdoor checks the old password, then the account's security version goes up, every other session
// of the account ends, and this session's next exchange gets a token of the new version. A change made in Casdoor's
// own pages is found by the pull of foundations item 3.
func ChangePassword(m *core.Base, c *httpx.Context) error {
	var in struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := c.BindJSON(&in); err != nil {
		return err
	}
	if in.OldPassword == "" || in.NewPassword == "" {
		return errs.New(errs.ReasonRequestInvalid, "old_password and new_password are required")
	}
	h := login.Session(m, c)
	if h == "" {
		return errs.New(errs.ReasonSessionEnded, "no live session")
	}
	a, _, ok, err := m.Store.Use(c.Ctx(), h, m.Idle, m.Absolute, true)
	if err != nil {
		return err
	}
	if !ok {
		return errs.New(errs.ReasonSessionEnded, "no live session")
	}
	// a credential tightening: its intent before Casdoor is asked, its conclusion with the change (item 4 T6b)
	p := m.Store.Intent(c.Ctx(), "credential_tightening", a.Principal, a.SecurityVersion,
		map[string]any{"kind": "password", "source": "adapter"})
	done := false
	defer func() { core.Settle(c.Ctx(), p, done) }()
	if err := m.Casdoor.SetPassword(c.Ctx(), a.Username, in.OldPassword, in.NewPassword); err != nil {
		if e := errs.From(err); e.Reason == errs.ReasonRequestInvalid {
			m.RT.Logger.Info("a password change was refused", "principal", a.Principal,
				"provider_error", e.Metadata["provider_error"])
		}
		return err
	}
	// Casdoor has the new password now; if this fails, the pull of item 3 finds the change by Casdoor's
	// LastChangePasswordTime and ends the sessions then
	if _, err := m.Store.SecurityChange(c.Ctx(), a.Principal, "password", h, core.Effective(p)); err != nil {
		return err
	}
	done = true
	ownPassword(m, c.Ctx(), a)
	return c.NoContent(http.StatusNoContent)
}

// ownPassword takes Casdoor's new password time as the comparison's baseline: the change made here is not one made in
// Casdoor itself, and the next comparison must not end the sessions again (the one that changed it kept). When Casdoor
// cannot be read now, the comparison counts it once more: one more re-login, never a missed change.
func ownPassword(m *core.Base, ctx context.Context, a core.AccountRow) {
	u, err := m.Casdoor.User(ctx, a.Username)
	if err == nil {
		at, _ := u["lastChangePasswordTime"].(string)
		err = m.Store.BaselinePassword(ctx, a.Principal, at)
	}
	if err != nil {
		m.RT.Logger.Warn("the password change's baseline was not recorded: the next comparison ends the sessions again",
			"principal", a.Principal, "error", err.Error())
	}
}

// EndSessionsBeforeRecovery ends this platform's sessions from before a full recovery, then this platform's client
// sessions in Casdoor of the same people (protocol 15, 6.6 when the identity product is outside the recovery group:
// the people's sessions in other applications stay). A product call that fails is logged for the operator; the
// platform's sessions are ended either way.
func EndSessionsBeforeRecovery(m *core.Base, ctx context.Context) error {
	people, err := m.Store.EndBeforeRecovery(ctx)
	if err != nil || len(people) == 0 {
		return err
	}
	failed := 0
	for _, u := range people {
		cctx, cancel := context.WithTimeout(ctx, provider.ProductCallLimit)
		err := m.Casdoor.EndSessions(cctx, u)
		cancel()
		if err != nil {
			failed++
			m.RT.Logger.Warn("a full recovery could not end a person's sessions in Casdoor", "username", u, "error", err.Error())
		}
	}
	m.RT.Logger.Warn("a full recovery ended the sessions from before it", "event", "sessions_ended_by_recovery",
		"people", len(people), "product_failures", failed)
	return nil
}
