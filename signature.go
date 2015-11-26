package saml

import (
	"bytes"
	"crypto/rsa"
	"text/template"

	"github.com/lestrrat/go-libxml2"
	"github.com/lestrrat/go-xmlsec"
)

const sigxmlTmplSrc = `<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="{{ .C14NMethod }}" />
      <SignatureMethod Algorithm="{{ .SignatureMethod }}" />
      <Reference URI="">
        <Transforms>
          <Transform Algorithm="{{ .Transform }}" />
        </Transforms>
        <DigestMethod Algorithm="{{ .DigestMethod }}" />
        <DigestValue></DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue/>
    <KeyInfo>
      <KeyName/>
    </KeyInfo>
  </Signature>`

var sigxmlTmpl *template.Template

func init() {
	sigxmlTmpl = template.Must(template.New("sigxml").Parse(sigxmlTmplSrc))
}

func NewGenericSign(m SignatureMethod, t Transform, d DigestMethod, c C14NMethod) (*GenericSign, error) {
	switch m {
	case RSA_SHA1, DSA_SHA1:
	default:
		return nil, ErrUnsupportedSignatureMethod
	}

	switch t {
	case EnvelopedSignature:
	default:
		return nil, ErrUnsupportedTransform
	}

	switch d {
	case SHA1:
	default:
		return nil, ErrUnsupportedDigestMethod
	}

	switch c {
	case C14N1_0:
	default:
		return nil, ErrUnsupportedC14NMethod
	}

	var buf bytes.Buffer
	err := sigxmlTmpl.Execute(&buf, struct {
		C14NMethod      C14NMethod
		DigestMethod    DigestMethod
		SignatureMethod SignatureMethod
		Transform       Transform
	}{
		C14NMethod: c,
		DigestMethod: d,
		SignatureMethod: m,
		Transform: t,
	})
	if err != nil {
		return nil, err
	}

	return &GenericSign{
		c14nmethod: c,
		digmethod:  d,
		sigmethod:  m,
		transform:  t,
		template:   buf.String(),
	}, nil
}

// InjectSignature injects an XML signature.
func (s GenericSign) Sign(n libxml2.Node, key interface{}) error {
	xmlsec.Init()
	defer xmlsec.Shutdown()

	ctx, err := xmlsec.NewDSigCtx()
	if err != nil {
		return err
	}
	defer ctx.Free()

	var seckey *xmlsec.Key
	switch s.sigmethod {
	case RSA_SHA1:
		seckey, err = xmlsec.LoadKeyFromRSAPrivateKey(key.(*rsa.PrivateKey))
		if err != nil {
			return err
		}
	default:
		return ErrUnsupportedKeyType
	}

	ctx.SetKey(seckey)

	newnode, err := n.ParseInContext(s.template, libxml2.XmlParseDTDLoad|libxml2.XmlParseDTDAttr|libxml2.XmlParseNoEnt)
	if err != nil {
		return err
	}

	n.AddChild(newnode)

	if err := ctx.SignNode(newnode); err != nil {
		return err
	}
	return nil
}