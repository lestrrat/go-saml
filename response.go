package saml

import (
	"github.com/lestrrat/go-libxml2/types"
	"github.com/lestrrat/go-pdebug"
	"github.com/lestrrat/go-saml/ns"
	"github.com/lestrrat/go-xmlsec/crypto"
)

func NewResponse() *Response {
	res := &Response{}
	res.Message.Initialize()
	return res
}

func (r Response) Serialize() (string, error) {
	return serialize(r)
}

func (res Response) MakeXMLNode(d types.Document) (types.Node, error) {
	oresxml, err := res.Message.MakeXMLNode(d)
	if err != nil {
		return nil, err
	}

	resxml := oresxml.(types.Element)
	resxml.MakeMortal()
	defer resxml.AutoFree()

	resxml.SetNodeName("Response")
	resxml.SetNamespace(ns.SAMLP.URI, ns.SAMLP.Prefix, true)
	resxml.SetNamespace(ns.SAML.URI, ns.SAML.Prefix, false)

	if v := res.InResponseTo; v != "" {
		resxml.SetAttribute("InResponseTo", v)
	}
	st, err := d.CreateElement("samlp:Status")
	if err != nil {
		return nil, err
	}
	stc, err := d.CreateElement("samlp:StatusCode")
	if err != nil {
		return nil, err
	}
	stc.SetAttribute("Value", res.Status.String())
	st.AddChild(stc)
	resxml.AddChild(st)

	if assertion := res.Assertion; assertion != nil {
		axml, err := assertion.MakeXMLNode(d)
		if err != nil {
			return nil, err
		}

		resxml.AddChild(axml)
	}

	resxml.MakePersistent()

	return resxml, nil
}

func (res Response) Encode(key *crypto.Key) ([]byte, error) {
	if pdebug.Enabled {
		g := pdebug.IPrintf("START Response.Encode")
		defer g.IRelease("END Response.Encode")
	}

	return encode(res, key, false)
}
