package ns

type Namespace struct {
	Prefix string
	URI    string
}

const NameFormatURI = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
var (
	SAML              = NewNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	SAMLP             = NewNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	XMLDSignature     = NewNamespace("ds", "http://www.w3.org/2000/09/xmldsig#")
	XMLEncryption     = NewNamespace("xenc", "http://www.w3.org/2001/04/xmlenc#")
	XMLSchema         = NewNamespace("xs", "http://www.w3.org/2001/XMLSchema")
	XMLSchemaInstance = NewNamespace("xsi", "http://www.w3.org/2001/XMLSchema-instance")
	X500              = NewNamespace("x500", "urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500")
)

func NewNamespace(prefix, uri string) *Namespace {
	return &Namespace{
		Prefix: prefix,
		URI:    uri,
	}
}

func (ns Namespace) AddPrefix(n string) string {
	return ns.Prefix + ":" + n
}
