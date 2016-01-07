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
	"github.com/lestrrat/go-saml/ns"
)

func NewAuthnRequest() *AuthnRequest {
	areq := &AuthnRequest{}
	areq.Request.Message.Initialize()
	return areq
}

// Encode takes the Authentication Request, generates the XML string,
// deflates it, and base64 encodes it. URL encoding is done in the HTTP
// protocol.
func (ar AuthnRequest) Encode() ([]byte, error) {
	xmlstr, err := ar.Serialize()
	if err != nil {
		return nil, err
	}

	buf := bytes.Buffer{}
	w, err := flate.NewWriter(&buf, 1)
	if err != nil {
		return nil, err
	}
	defer w.Close()
	io.WriteString(w, xmlstr)
	w.Flush()

	raw := buf.Bytes()
	ret := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	base64.StdEncoding.Encode(ret, raw)

	return ret, nil
}

// DecodeAuthnRequestString takes in a byte buffer, decodes it from base64,
// inflates it, and then parses the resulting XML
func DecodeAuthnRequestString(s string) (*AuthnRequest, error) {
	return decodeAuthnRequest(strings.NewReader(s))
}

// DecodeAuthnRequest takes in a byte buffer, decodes it from base64,
// inflates it, and then parses the resulting XML
func DecodeAuthnRequest(b []byte) (*AuthnRequest, error) {
	return decodeAuthnRequest(bytes.NewReader(b))
}

func decodeAuthnRequest(in io.Reader) (*AuthnRequest, error) {
	r := flate.NewReader(base64.NewDecoder(base64.StdEncoding, in))
	buf := bytes.Buffer{}
	if _, err := io.Copy(&buf, r); err != nil {
		return nil, err
	}
	if err := r.Close(); err != nil {
		return nil, err
	}

	if buf.Len() <= 0 {
		return nil, errors.New("empty request")
	}

	return ParseAuthnRequest(buf.Bytes())
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
	ar.ProtocolBinding = xpath.String(xpc.Find("@ProtocolBinding"))
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
	arxml.SetAttribute("ProtocolBinding", ar.ProtocolBinding)
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
