package iam

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
)

// signingKey is one Ed25519 key and its kid (the RFC 7638 thumbprint of its public JWK).
type signingKey struct {
	kid  string
	priv ed25519.PrivateKey
}

func parseKey(pemText string) (signingKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return signingKey{}, errors.New("not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return signingKey{}, fmt.Errorf("not a PKCS #8 private key: %w", err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return signingKey{}, fmt.Errorf("a %T, not an Ed25519 key", k)
	}
	return signingKey{kid: thumbprint(priv.Public().(ed25519.PublicKey)), priv: priv}, nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// thumbprint is RFC 7638 over the required members of an OKP key, in lexicographic order.
func thumbprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256([]byte(`{"crv":"Ed25519","kty":"OKP","x":"` + b64(pub) + `"}`))
	return b64(sum[:])
}

func (k signingKey) jwk() map[string]string {
	return map[string]string{"kty": "OKP", "crv": "Ed25519", "x": b64(k.priv.Public().(ed25519.PublicKey)),
		"kid": k.kid, "alg": "EdDSA", "use": "sig"}
}

// keyRing holds the current signing key and the standby one, parsed again only when their PEM changes (the SDK
// re-reads secret files on rotation). A standby key that does not parse is left out of the published set and
// reported through warn; a current key that does not parse fails every issue.
type keyRing struct {
	current, next func() string
	warn          func(error)

	mu              sync.Mutex
	curPEM, nextPEM string
	curKey          signingKey
	nextKey         *signingKey
}

// keys returns the current key and the published set.
func (r *keyRing) keys() (signingKey, []signingKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p := r.current(); p != r.curPEM {
		k, err := parseKey(p)
		if err != nil {
			return signingKey{}, nil, fmt.Errorf("IAM_SIGNING_KEY: %w", err)
		}
		r.curPEM, r.curKey = p, k
	}
	if p := r.next(); p != r.nextPEM {
		r.nextPEM, r.nextKey = p, nil
		if p != "" {
			if k, err := parseKey(p); err == nil {
				r.nextKey = &k
			} else {
				r.warn(fmt.Errorf("IAM_SIGNING_KEY_NEXT is not published: %w", err))
			}
		}
	}
	set := []signingKey{r.curKey}
	if r.nextKey != nil && r.nextKey.kid != r.curKey.kid {
		set = append(set, *r.nextKey)
	}
	return r.curKey, set, nil
}

func b64decode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
