package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/lestrrat/go-libxml2"
	"github.com/lestrrat/go-saml/binding"
	"github.com/lestrrat/go-saml/ns"
	"github.com/lestrrat/go-xmlsec"
	"github.com/stretchr/testify/assert"
)

func TestAssertion_XML(t *testing.T) {
	a := Assertion{
		Conditions: Conditions{
			NotBefore:    time.Now(),
			NotOnOrAfter: time.Now(),
		},
		Version:      "2.0",
		ID:           "b07b804c-7c29-ea16-7300-4f3d6f7928ac",
		IssueInstant: time.Now(),
		Issuer:       "https://idp.example.org/SAML2",
		Subject: Subject{
			NameID: NameID{
				Format: NameIDFormatTransient,
				Value:  "3f7b3dcf-1674-4ecd-92c8-1544f346baf8",
			},
			SubjectConfirmation: SubjectConfirmation{
				InResponseTo: "aaf23196-1773-2113-474a-fe114412ab72",
				Recipient:    "https://sp.example.com/SAML2/SSO/POST",
				NotOnOrAfter: time.Now(),
			},
		},
		AuthnStatement: AuthnStatement{
			AuthnInstant: time.Now(),
			SessionIndex: "b07b804c-7c29-ea16-7300-4f3d6f7928ac",
			AuthnContext: AuthnContext{
				AuthnContextClassRef: PasswordProtectedTransport,
			},
		},
	}
	a.Conditions.AddAudienceRestriction(
		AudienceRestriction{
			Audience: []string{"https://sp.example.com/SAML2"},
		},
	)
	a.AddAttribute(Attribute{
		Attrs: map[string]string{
			"xmlns:" + ns.X500.Prefix:     ns.X500.URI,
			ns.X500.AddPrefix("Encoding"): "LDAP",
			"NameFormat":                  ns.NameFormatURI,
		},
		Name:         "urn:oid:1.3.6.1.4.1.5923.1.1.1.1",
		FriendlyName: "eduPersonAffiliation",
		Values: []AttributeValue{
			AttributeValue{
				Type:  "xs:string",
				Value: "member",
			},
			AttributeValue{
				Type:  "xs:string",
				Value: "staff",
			},
		},
	})

	xmlstr, err := a.Serialize()
	if !assert.NoError(t, err, "Serialize() succeeds") {
		return
	}

	p := libxml2.NewParser(libxml2.XMLParseDTDLoad | libxml2.XMLParseDTDAttr | libxml2.XMLParseNoEnt)
	c14ndoc, err := p.ParseString(xmlstr)
	if !assert.NoError(t, err, "Parse C14N XML doc succeeds") {
		return
	}
	defer c14ndoc.Free()

	root, err := c14ndoc.DocumentElement()
	if !assert.NoError(t, err, "DocumentElement succeeds") {
		return
	}

	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if !assert.NoError(t, err, "GenerateKey succeeds") {
		return
	}

	s, err := NewGenericSign(xmlsec.RsaSha1, xmlsec.Enveloped, xmlsec.Sha1, xmlsec.ExclC14N)
	if !assert.NoError(t, err, "NewGenericSign succeeds") {
		return
	}
	s.Sign(root, privkey, "")
}

func TestAuthnRequest(t *testing.T) {
	ar := NewAuthnRequest()
	ar.ID = "809707f0030a5d00620c9d9df97f627afe9dcc24"
	ar.Version = "2.0"
	ar.IssueInstant = time.Now()
	ar.Issuer = "http://sp.example.com/metadata"
	ar.Destination = "http://idp.example.com/sso"
	ar.ProviderName = "FooProvider"
	ar.ProtocolBinding = binding.HTTPPost
	ar.AssertionConsumerServiceURL = "http://sp.example.com/acs"
	ar.NameIDPolicy = NewNameIDPolicy(NameIDFormatEmailAddress, true)
	ar.RequestedAuthnContext = NewRequestedAuthnContext(
		"exact",
		"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
	)

	xmlstr, err := ar.Serialize()
	if !assert.NoError(t, err, "Serialize() succeeds") {
		return
	}

	p := libxml2.NewParser(libxml2.XMLParseDTDLoad | libxml2.XMLParseDTDAttr | libxml2.XMLParseNoEnt)
	c14ndoc, err := p.ParseString(xmlstr)
	if !assert.NoError(t, err, "Parse C14N XML doc succeeds") {
		return
	}
	defer c14ndoc.Free()

	root, err := c14ndoc.DocumentElement()
	if !assert.NoError(t, err, "DocumentElement succeeds") {
		return
	}

	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if !assert.NoError(t, err, "GenerateKey succeeds") {
		return
	}

	s, err := NewGenericSign(xmlsec.RsaSha1, xmlsec.Enveloped, xmlsec.Sha1, xmlsec.ExclC14N)
	if !assert.NoError(t, err, "NewGenericSign succeeds") {
		return
	}
	s.Sign(root, privkey, "urn:oasis:names:tc:SAML:2.0:protocol:AuthnRequest")

	t.Logf("%s", c14ndoc.Dump(true))
}