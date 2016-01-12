package binding

type Protocol string

const (
	HTTPPost     Protocol = `urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST`
	HTTPRedirect Protocol = `urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect`
)

func (p Protocol) String() string {
	return string(p)
}
