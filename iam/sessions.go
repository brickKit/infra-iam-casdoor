package iam

import (
	"context"
	"net/http"
	"time"

	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/events"
	"github.com/brickKit/be-sdk-go/v3/grpcx"
	"github.com/brickKit/be-sdk-go/v3/httpx"
	"github.com/brickKit/be-sdk-go/v3/sessionpb"
)

// Ended's page size (be-protocol P8.28).
const (
	endedDefault = 500
	endedMax     = 2000
)

// sessions is the edge's side of the member: SessionService (be.session.v1, P8.28), callable by infra/edge only.
type sessions struct {
	sessionpb.UnimplementedSessionServiceServer
	m *Module
}

// Services registers the session methods on the system surface.
func (m *Module) Services(s *grpcx.Services) error {
	s.Register(&sessionpb.SessionService_ServiceDesc, &sessions{m: m}, map[string]grpcx.Method{
		"Exchange": {Operation: OpExchange, Callers: []string{Edge}},
		"Ended":    {Operation: OpEnded, Callers: []string{Edge}},
	})
	return nil
}

// Exchange is a live session's access token, at the account's current security version; SESSION_ENDED otherwise.
// The session row's lock makes the exchanges of one session go one at a time.
func (s *sessions) Exchange(ctx context.Context, in *sessionpb.ExchangeRequest) (*sessionpb.ExchangeResponse, error) {
	if in.GetSessionDigest() == "" {
		return nil, errs.New(errs.ReasonRequestInvalid, "session_digest is required")
	}
	a, until, ok, err := s.m.store.use(ctx, in.GetSessionDigest(), s.m.idle, s.m.absolute, in.GetRenewIdle())
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errs.New(errs.ReasonSessionEnded, "no live session")
	}
	tok, exp, err := s.m.issue(a.principal, a.securityVersion, time.Now(), until)
	if err != nil {
		return nil, err
	}
	return &sessionpb.ExchangeResponse{AccessToken: tok, ExpiresAtMs: exp.UnixMilli(), Principal: a.principal,
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
	rows, next, reset, err := events.ReadAfter(ctx, s.m.rt.DB, s.m.impl, StreamEnded, 0, after, limit)
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

// changePassword is the user's password change, made through this member so that it knows the session making it
// (protocol 20): Casdoor checks the old password, then the account's security version goes up, every other session
// of the account ends, and this session's next exchange gets a token of the new version. A change made in Casdoor's
// own pages is found by the pull of foundations item 3.
func (m *Module) changePassword(c *httpx.Context) error {
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
	h := m.session(c)
	if h == "" {
		return errs.New(errs.ReasonSessionEnded, "no live session")
	}
	a, _, ok, err := m.store.use(c.Ctx(), h, m.idle, m.absolute, true)
	if err != nil {
		return err
	}
	if !ok {
		return errs.New(errs.ReasonSessionEnded, "no live session")
	}
	if err := m.casdoor.setPassword(c.Ctx(), a.username, in.OldPassword, in.NewPassword); err != nil {
		if e := errs.From(err); e.Reason == errs.ReasonRequestInvalid {
			m.rt.Logger.Info("a password change was refused", "principal", a.principal,
				"provider_error", e.Metadata["provider_error"])
		}
		return err
	}
	// Casdoor has the new password now; if this fails, the pull of item 3 finds the change by Casdoor's
	// LastChangePasswordTime and ends the sessions then
	if _, err := m.store.securityChange(c.Ctx(), a.principal, "password", h); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}
