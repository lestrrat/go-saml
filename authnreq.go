package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"errors"
	"io"
	"strings"

	"github.com/lestrrat/go-libxml2/parser"
	"github.com/lestrrat/go-libxml2/types"
	"github.com/lestrrat/go-libxml2/xpath"
	"github.com/lestrrat/go-pdebug"
	"github.com/lestrrat/go-saml/binding"
	"github.com/lestrrat/go-saml/ns"
	"github.com/lestrrat/go-xmlsec/crypto"
	"github.com/lestrrat/go-xmlsec/dsig"
)

func NewAuthnRequest() *AuthnRequest {
	areq := &AuthnRequest{}
	areq.Request.Message.Initialize()
	return areq
}

// Encode takes the Authentication Request, generates the XML string,
// deflates it, and base64 encodes it. URL encoding is done in the HTTP
// protocol.
// If the key value is not nil, it will attempt to generate a signature
// using that specified key
func (ar AuthnRequest) Encode(key *crypto.Key) ([]byte, error) {
	if pdebug.Enabled {
		g := pdebug.IPrintf("START AuthnRequest.Encode")
		defer g.IRelease("END AuthnRequest.Encode")
	}

	return encode(ar, key, true)
}

// DecodeAuthnRequestString takes in a byte buffer, decodes it from base64,
// inflates it, and then parses the resulting XML.
// If verify is true, it looks for the signature in the payload and
// does signature validation using go-xmlsec.
func DecodeAuthnRequestString(s string, verify bool) (*AuthnRequest, error) {
	if pdebug.Enabled {
		g := pdebug.IPrintf("START saml.DecodeAuthnRequestString '%.30s...' (%d bytes)", s, len(s))
		defer g.IRelease("END saml.DecodeAuthnRequestString")
	}
	return decodeAuthnRequest(strings.NewReader(s), verify)
}

// DecodeAuthnRequest takes in a byte buffer, decodes it from base64,
// inflates it, and then parses the resulting XML.
// If verify is true, it looks for the signature in the payload and
// does signature validation using go-xmlsec.
func DecodeAuthnRequest(b []byte, verify bool) (*AuthnRequest, error) {
	if pdebug.Enabled {
		g := pdebug.IPrintf("START saml.DecodeAuthnRequest '%.30s...' (%d bytes)", b, len(b))
		defer g.IRelease("END saml.DecodeAuthnRequest")
	}
	return decodeAuthnRequest(bytes.NewReader(b), verify)
}

func decodeAuthnRequest(in io.Reader, verify bool) (*AuthnRequest, error) {
	r := flate.NewReader(base64.NewDecoder(b64enc, in))

	buf := bytes.Buffer{}
	if _, err := io.Copy(&buf, r); err != nil {
		if pdebug.Enabled {
			pdebug.Printf("Failed to copy from flate.Reader to bytes.Buffer: %s", err)
		}
		return nil, err
	}

	if err := r.Close(); err != nil {
		if pdebug.Enabled {
			pdebug.Printf("Failed to Close() flat.Reader: %s", err)
		}
		return nil, err
	}

	if buf.Len() <= 0 {
		if pdebug.Enabled {
			pdebug.Printf("buf.Len() is 0")
		}
		return nil, errors.New("empty request")
	}

	xmlbytes := buf.Bytes()
	if verify {
		verifier, err := dsig.NewSignatureVerify()
		if err != nil {
			return nil, err
		}

		if err := verifier.Verify(xmlbytes); err != nil {
			return nil, err
		}
	}

	if pdebug.Enabled {
		pdebug.Printf("base64 decode/uncompress/xml signature verification complete")
	}

	return ParseAuthnRequest(xmlbytes)
}

func (ar AuthnRequest) Serialize() (string, error) {
	return serialize(ar)
}

func ParseAuthnRequest(src []byte) (*AuthnRequest, error) {
	p := parser.New(parser.XMLParseDTDLoad | parser.XMLParseDTDAttr | parser.XMLParseNoEnt)
	doc, err := p.Parse(src)
	if err != nil {
		return nil, errors.New("failed to parse xml: " + err.Error())
	}

	return constructAuthnRequest(doc)
}

func ParseAuthnRequestString(src string) (*AuthnRequest, error) {
	p := parser.New(parser.XMLParseDTDLoad | parser.XMLParseDTDAttr | parser.XMLParseNoEnt)
	doc, err := p.ParseString(src)
	if err != nil {
		return nil, errors.New("failed to parse xml: " + err.Error())
	}

	return constructAuthnRequest(doc)
}

func constructAuthnRequest(doc types.Document) (*AuthnRequest, error) {
	root, err := doc.DocumentElement()
	if err != nil {
		return nil, errors.New("failed to fetch document element: " + err.Error())
	}

	ar := &AuthnRequest{}
	if err := ar.PopulateFromXML(root); err != nil {
		return nil, errors.New("failed to populate from xml: " + err.Error())
	}
	return ar, nil
}

func (ar *AuthnRequest) PopulateFromXML(n types.Node) error {
	if err := ar.Request.PopulateFromXML(n); err != nil {
		return err
	}

	xpc, err := xpath.NewContext(n)
	if err != nil {
		return errors.New("failed to create xpath context: " + err.Error())
	}

	if err := xpc.RegisterNS(ns.SAML.Prefix, ns.SAML.URI); err != nil {
		return errors.New("failed to register namespace for xpath context: " + err.Error())
	}

	ar.ProviderName = xpath.String(xpc.Find("@ProviderName"))
	// Check if we have a proper ProtocolBinding
	switch proto := binding.Protocol(xpath.String(xpc.Find("@ProtocolBinding"))); proto {
	case binding.HTTPPost, binding.HTTPRedirect:
		ar.ProtocolBinding = proto
	default:
		return errors.New("invalid protocol binding")
	}

	ar.AssertionConsumerServiceURL = xpath.String(xpc.Find("@AssertionConsumerServiceURL"))
	if node := xpath.NodeList(xpc.Find("NameIDPolicy")).First(); node != nil {
		nip := &NameIDPolicy{}
		if err := nip.PopulateFromXML(node.(types.Element)); err != nil {
			return err
		}
		ar.NameIDPolicy = nip
	}

	return nil
}

func (ar AuthnRequest) MakeXMLNode(d types.Document) (types.Node, error) {
	oarxml, err := ar.Request.MakeXMLNode(d)
	if err != nil {
		return nil, err
	}
	arxml := oarxml.(types.Element)

	arxml.MakeMortal()
	defer arxml.AutoFree()

	arxml.SetNodeName("AuthnRequest")
	arxml.SetNamespace(ns.SAML.URI, ns.SAML.Prefix, false)
	arxml.SetNamespace(ns.SAMLP.URI, ns.SAMLP.Prefix, true)

	arxml.SetAttribute("ProviderName", ar.ProviderName)
	arxml.SetAttribute("ProtocolBinding", ar.ProtocolBinding.String())
	arxml.SetAttribute("AssertionConsumerServiceURL", ar.AssertionConsumerServiceURL)

	if nip := ar.NameIDPolicy; nip != nil {
		nipxml, err := nip.MakeXMLNode(d)
		if err != nil {
			return nil, err
		}
		arxml.AddChild(nipxml)
	}

	if rac := ar.RequestedAuthnContext; rac != nil {
		racxml, err := rac.MakeXMLNode(d)
		if err != nil {
			return nil, err
		}
		arxml.AddChild(racxml)
	}
	arxml.MakePersistent()
	return arxml, nil
}
