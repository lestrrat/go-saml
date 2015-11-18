package ns

import "encoding/xml"

var (
	SAML              = New("saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	SAMLP             = New("samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	XMLDSignature     = New("ds", "http://www.w3.org/2000/09/xmldsig#")
	XMLSchema         = New("xs", "http://www.w3.org/2001/XMLSchema")
	XMLSchemaInstance = New("xsi", "http://www.w3.org/2001/XMLSchema-instance")
	X500              = New("x500", "urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500")
)

func New(prefix, uri string) xml.Attr {
	return xml.Attr{
		Name:  xml.Name{Local: "xmlns:" + prefix},
		Value: uri,
	}
}
