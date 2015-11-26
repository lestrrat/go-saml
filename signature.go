package saml

import (
	"crypto/rsa"

	"github.com/lestrrat/go-libxml2"
	"github.com/lestrrat/go-xmlsec"
)

func InjectSignature(n libxml2.Node, key *rsa.PrivateKey) error {
	const sigxml = `<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" />
      <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" />
      <Reference URI="">
        <Transforms>
          <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
        </Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
        <DigestValue></DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue/>
    <KeyInfo>
      <KeyName/>
    </KeyInfo>
  </Signature>`
	xmlsec.Init()
	defer xmlsec.Shutdown()

	ctx, err := xmlsec.NewDSigCtx()
	if err != nil {
		return err
	}
	defer ctx.Free()

	seckey, err := xmlsec.LoadKeyFromRSAPrivateKey(key)
	if err != nil {
		return err
	}
	ctx.SetKey(seckey)

	newnode, err := n.ParseInContext(sigxml, libxml2.XmlParseDTDLoad|libxml2.XmlParseDTDAttr|libxml2.XmlParseNoEnt)
	if err != nil {
		return err
	}

	n.AddChild(newnode)

	if err := ctx.SignNode(newnode); err != nil {
		return err
	}
	return nil
}