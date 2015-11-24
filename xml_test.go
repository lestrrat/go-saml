package saml

import (
	"encoding/xml"
	"testing"
	"time"

	"github.com/lestrrat/go-saml/binding"
	"github.com/lestrrat/go-saml/ns"
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
			NameID: "3f7b3dcf-1674-4ecd-92c8-1544f346baf8",
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
				AuthnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
			},
		},
	}
	a.Conditions.AddAudienceRestriction(
		AudienceRestriction{
			Audience: []string{"https://sp.example.com/SAML2"},
		},
	)
	a.AddAttribute(Attribute{
		Attrs: []xml.Attr{
			ns.X500.XMLAttr(),
			xml.Attr{
				Name:  xml.Name{Local: "x500:Encoding"},
				Value: "LDAP",
			},
			xml.Attr{
				Name:  xml.Name{Local: "NameFormat"},
				Value: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			},
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

	t.Logf("%s", xmlstr)
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

	t.Logf("%s", xmlstr)
}