package saml

import (
	"github.com/lestrrat/go-libxml2"
	"github.com/lestrrat/go-xmlsec"
)

func NewGenericSign(m, t, d, c xmlsec.TransformID) (*GenericSign, error) {
	return &GenericSign{
		c14nmethod: c,
		digmethod:  d,
		sigmethod:  m,
		transform:  t,
	}, nil
}

func (s GenericSign) Sign(n libxml2.Node, key *xmlsec.Key, id string) error {
	xmlsec.Init()
	defer xmlsec.Shutdown()

	sig, err := xmlsec.NewSignature(n, s.c14nmethod, s.sigmethod, id)
	if err != nil {
		return err
	}

	if err := sig.AddReference(xmlsec.Sha1, "", "", ""); err != nil {
		return err
	}

	if err := sig.AddTransform(xmlsec.Enveloped); err != nil {
		return err
	}

	return sig.Sign(key)
}