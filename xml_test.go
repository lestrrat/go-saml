package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/lestrrat/go-libxml2/dom"
	"github.com/lestrrat/go-libxml2/parser"
	"github.com/lestrrat/go-saml/binding"
	"github.com/lestrrat/go-saml/nameid"
	"github.com/lestrrat/go-saml/ns"
	"github.com/lestrrat/go-xmlsec"
	"github.com/lestrrat/go-xmlsec/crypto"
	"github.com/lestrrat/go-xmlsec/dsig"
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
				Format: nameid.Transient,
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
	a.Conditions.AddAudience("https://sp.example.com/SAML2")
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
				Type:  ns.XMLSchema.AddPrefix("string"),
				Value: "member",
			},
			AttributeValue{
				Type:  ns.XMLSchema.AddPrefix("string"),
				Value: "staff",
			},
		},
	})

	xmlstr, err := a.Serialize()
	if !assert.NoError(t, err, "Serialize() succeeds") {
		return
	}

	p := parser.New(parser.XMLParseDTDLoad | parser.XMLParseDTDAttr | parser.XMLParseNoEnt)
	c14ndoc, err := p.ParseString(xmlstr)
	if !assert.NoError(t, err, "Parse C14N XML doc succeeds") {
		return
	}
	defer c14ndoc.Free()
}

func TestAuthnRequest(t *testing.T) {
	xmlsec.Init()
	defer xmlsec.Shutdown()

	ar := NewAuthnRequest()
	ar.ID = "809707f0030a5d00620c9d9df97f627afe9dcc24"
	ar.Version = "2.0"
	ar.IssueInstant = time.Now()
	ar.Issuer = "http://sp.example.com/metadata"
	ar.Destination = "http://idp.example.com/sso"
	ar.ProviderName = "FooProvider"
	ar.ProtocolBinding = binding.HTTPPost
	ar.AssertionConsumerServiceURL = "http://sp.example.com/acs"
	ar.NameIDPolicy = NewNameIDPolicy(nameid.EmailAddress, true)
	ar.RequestedAuthnContext = NewRequestedAuthnContext(
		"exact",
		"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
	)

	xmlstr, err := ar.Serialize()
	if !assert.NoError(t, err, "Serialize() succeeds") {
		return
	}

	p := parser.New(parser.XMLParseDTDLoad | parser.XMLParseDTDAttr | parser.XMLParseNoEnt)
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

	signer, err := dsig.NewSignature(root, dsig.ExclC14N, dsig.RsaSha1, "urn:oasis:names:tc:SAML:2.0:protocol:AuthnRequest")
	if !assert.NoError(t, err, "dsig.NewSignature succeeds") {
		return
	}

	if !assert.NoError(t, signer.AddReference(dsig.Sha1, "", "", ""), "AddReference succeeds") {
		return
	}

	if !assert.NoError(t, signer.AddTransform(dsig.Enveloped), "AddTransform succeeds") {
		return
	}

	if !assert.NoError(t, signer.AddKeyValue(), "AddKeyValue succeeds") {
		return
	}

	key, err := crypto.LoadKeyFromRSAPrivateKey(privkey)
	if !assert.NoError(t, err, "Load key from RSA private key succeeds") {
		return
	}

	if !assert.NoError(t, signer.Sign(key), "Sign succeeds") {
		return
	}

	t.Logf("%s", c14ndoc.Dump(true))
}

func TestResponse(t *testing.T) {
	xmlsec.Init()
	defer xmlsec.Shutdown()
	res := NewResponse()
	res.Issuer = "http://idp.example.com/metadata"
	res.Destination = "http://sp.example.com/sso"

	// Run serialize once so we can check for empty assertion
	xmlstr, err := res.Serialize()
	if !assert.NoError(t, err, "Serialize() succeeds") {
		return
	}
	if !assert.NotContains(t, xmlstr, "<Assertion", "Should not contain assertion") {
		return
	}

	res.Assertion = NewAssertion()

	res.Assertion.Conditions.AddAudience("sp.example.com/sso")

	xmlstr, err = res.Serialize()
	if !assert.NoError(t, err, "Serialize() succeeds") {
		return
	}

	p := parser.New(parser.XMLParseDTDLoad | parser.XMLParseDTDAttr | parser.XMLParseNoEnt)
	doc, err := p.ParseString(xmlstr)
	if !assert.NoError(t, err, "Parse XML doc succeeds") {
		return
	}
	defer doc.Free()

	c14nxml, err := dom.C14NSerialize{Mode: dom.C14NExclusive1_0}.Serialize(doc)
	if !assert.NoError(t, err, "C14NSerialize.Serialize succeeds") {
		return
	}

	c14ndoc, err := p.ParseString(c14nxml)
	if !assert.NoError(t, err, "Parse C14N doc succeeds") {
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

	signer, err := dsig.NewSignature(root, dsig.ExclC14N, dsig.RsaSha1, "urn:oasis:names:tc:SAML:2.0:protocol:Response")
	if !assert.NoError(t, err, "dsig.NewSignature succeeds") {
		return
	}

	if !assert.NoError(t, signer.AddReference(dsig.Sha1, "", "", ""), "AddReference succeeds") {
		return
	}

	if !assert.NoError(t, signer.AddTransform(dsig.Enveloped), "AddTransform succeeds") {
		return
	}

	if !assert.NoError(t, signer.AddKeyValue(), "AddKeyValue succeeds") {
		return
	}

	key, err := crypto.LoadKeyFromRSAPrivateKey(privkey)
	if !assert.NoError(t, err, "Load key from RSA private key succeeds") {
		return
	}

	if !assert.NoError(t, signer.Sign(key), "Sign succeeds") {
		t.Logf("%s", c14ndoc.Dump(true))
		return
	}

	t.Logf("%s", c14ndoc.Dump(true))
}

func TestParseAuthnRequest(t *testing.T) {
	const xmlsrc = `<?xml version="1.0" encoding="utf-8"?>
<saml:AuthnRequest xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" AssertionConsumerServiceURL="http://sp.example.com/acs" Destination="http://idp.example.com/sso" ID="809707f0030a5d00620c9d9df97f627afe9dcc24" IssueInstant="2015-11-30T18:18:31" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ProviderName="FooProvider" Version="2.0">
  <saml:Issuer>http://sp.example.com/metadata</saml:Issuer>
  <saml:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/>
  <saml:RequestedAuthnContext Comparison="exact">
    <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
  </saml:RequestedAuthnContext>
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#" Id="urn:oasis:names:tc:SAML:2.0:protocol:AuthnRequest">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <Reference>
        <Transforms>
          <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
        </Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <DigestValue>GuGtxIMZFN7XWsKRJW8x6/+Xf9Y=</DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue>v3S/CRBOf/TTvkGF+0exmOVQLz1ITgbAJ0+OUx1LSvAbxFxl/jqP+FLMz+qN5baC
QKYit5KcJWBjqfNukfKGhvdV8wR02m56FJQtYU+Xb42i1tHvS4h4krJiCBekn19M
2l01QaLnZxBhNYPoXkcsVGEOJOZVokPEbXEdze5n5Svaajdlfww9NpIbP5G4gQ76
QAzvSaZ34JkNN2sNQgRN9G+KT689M4I2i7OATNyckqguR8I3qjrxtAvVaDKNITTI
9yt7pHcf1Y6JA9WO3NXLsHq+z0KetS4qnBQ1vFr7nKxKJDOcBuqIVzGWuTgo98/W
uruUEt5gXJrdbUpiUAGnHg==</SignatureValue>
  </Signature>
</saml:AuthnRequest>`
	req, err := ParseAuthnRequestString(xmlsrc)
	if !assert.NoError(t, err, "ParseAuthnRequestString succeeds") {
		return
	}

	xmlstr, err := req.Serialize()
	if !assert.NoError(t, err, "Serialize succeeds") {
		return
	}

	t.Logf("%s", xmlstr)

	encoded, err := req.Encode(nil)
	if !assert.NoError(t, err, "Encode succeeds") {
		return
	}

	t.Logf("%s", encoded)

	decoded, err := DecodeAuthnRequest(encoded, false)
	if !assert.NoError(t, err, "Decode succeeds") {
		return
	}

	xmlstr2, err := decoded.Serialize()
	if !assert.NoError(t, err, "Serialize succeeds") {
		return
	}
	t.Logf("%s", xmlstr2)
}
