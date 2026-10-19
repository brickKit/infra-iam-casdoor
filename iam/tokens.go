package iam

import (
	"crypto/rand"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// issue signs an access token for a principal (protocol P8.1: typ at+jwt, a kid, EdDSA; iss, aud, sub, iat, nbf,
// exp; no role or department claims, authorization comes from the view only). The lifetime never runs past until
// when until is set (a session's end).
func (m *Module) issue(principal string, now time.Time, until time.Time) (string, time.Time, error) {
	key, _, err := m.keys.keys()
	if err != nil {
		return "", time.Time{}, err
	}
	exp := now.Add(m.ttl)
	if !until.IsZero() && until.Before(exp) {
		exp = until
	}
	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss": m.issuer, "aud": m.audience, "sub": principal, "iat": now.Unix(), "nbf": now.Unix(),
		"exp": exp.Unix(), "jti": b64(jti)})
	t.Header["typ"] = "at+jwt"
	t.Header["kid"] = key.kid
	s, err := t.SignedString(key.priv)
	return s, exp, err
}
