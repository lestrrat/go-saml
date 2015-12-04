package saml

import (
	"github.com/lestrrat/go-libxml2/types"
	"github.com/lestrrat/go-xmlsec"
	"github.com/lestrrat/go-xmlsec/crypto"
	"github.com/lestrrat/go-xmlsec/dsig"
)

func NewGenericSign(m, t, d, c dsig.TransformID) (*GenericSign, error) {
	return &GenericSign{
		c14nmethod: c,
		digmethod:  d,
		sigmethod:  m,
		transform:  t,
	}, nil
}

func (s GenericSign) Sign(n types.Node, key *crypto.Key, id string) error {
	xmlsec.Init()
	defer xmlsec.Shutdown()

	sig, err := dsig.NewSignature(n, s.c14nmethod, s.sigmethod, id)
	if err != nil {
		return err
	}

	if err := sig.AddReference(dsig.Sha1, "", "", ""); err != nil {
		return err
	}

	if err := sig.AddTransform(dsig.Enveloped); err != nil {
		return err
	}

	return sig.Sign(key)
}