package ns

import "encoding/xml"

type Namespace struct {
	Prefix string
	URI    string
}

var (
	SAML              = New("saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	SAMLP             = New("samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	XMLDSignature     = New("ds", "http://www.w3.org/2000/09/xmldsig#")
	XMLSchema         = New("xs", "http://www.w3.org/2001/XMLSchema")
	XMLSchemaInstance = New("xsi", "http://www.w3.org/2001/XMLSchema-instance")
	X500              = New("x500", "urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500")
)

func New(prefix, uri string) Namespace {
	return Namespace{Prefix: prefix, URI: uri}
}

func (ns Namespace) XMLAttr() xml.Attr {
	return xml.Attr{
		Name:  xml.Name{Local: "xmlns:" + ns.Prefix},
		Value: ns.URI,
	}
}

func (ns Namespace) XMLName(name string) xml.Name {
	return ns.AddPrefix(xml.Name{Local: name})
}

func (ns Namespace) AddPrefix(n xml.Name) xml.Name {
	n.Local = ns.Prefix + ":" + n.Local
	return n
}
