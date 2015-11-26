package saml

import (
	"encoding/xml"
	"errors"
	"time"

	"github.com/lestrrat/go-libxml2"
)

// TimeFormat is the format defined in xs:dateTime
const TimeFormat = "2006-01-02T15:04:05"

const (
	NameIDFormatEmailAddress    = `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`
	NameIDFormatUnspecified     = `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`
	NameIDFormatX509SubjectName = `urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName`
)

var (
	ErrUnsupportedDigestMethod    = errors.New("unsupported digest method")
	ErrUnsupportedSignatureMethod = errors.New("unsupported signature method")
	ErrUnsupportedTransform       = errors.New("unsupported transform")
	ErrUnsupportedC14NMethod      = errors.New("unsupported c14n method")
	ErrUnsupportedKeyType         = errors.New("unsupported signature key type")
)

// Signer defines an interface of things that can generate XML
// signature for the given node. The node being passed should
// point to the XML element to which the signature should be
// injected into. key should be whatever appropriate key type
// that you will be using to sign
type Signer interface {
	Sign(libxml2.Node, interface{}) error
}

type C14NMethod string

const (
	C14N1_0 C14NMethod = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
)

type SignatureMethod string

const (
	RSA_SHA1 SignatureMethod = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	DSA_SHA1 SignatureMethod = "http://www.w3.org/2000/09/xmldsig#dsa-sha1"
)

type Transform string

const (
	EnvelopedSignature Transform = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
)

type DigestMethod string

const (
	SHA1 DigestMethod = "http://www.w3.org/2000/09/xmldsig#sha1"
)

type GenericSign struct {
	c14nmethod C14NMethod
	digmethod  DigestMethod
	sigmethod  SignatureMethod
	template   string
	transform  Transform
}

type AttributeValue struct {
	Type  string
	Value string
}

type Attribute struct {
	Attrs        []xml.Attr
	FriendlyName string
	Name         string
	Values       []AttributeValue
}

type AttributeStatement struct {
	Attributes []Attribute // Probably multiple attributes allowed?
}

type AuthnContext struct {
	AuthnContextClassRef string
}

type AuthnStatement struct {
	AuthnInstant time.Time
	SessionIndex string
	AuthnContext AuthnContext
}

type AudienceRestriction struct {
	Audience []string
}

type NameIDPolicy struct {
	AllowCreate     bool
	Format          string
	SPNameQualifier string
}

type RequestedAuthnContext struct {
	Comparison           string
	AuthnContextClassRef string
}

// Request represents the RequestAbstracttype from SAML specification
type Request struct {
	Consent     string `xml:",attr"`
	Destination string `xml:",attr"`
	// ID is an identifier for the request. It is of type xs:ID and
	// MUST follow the requirementsspecified in Section 1.3.4 for
	// identifier uniqueness. The values of the ID attribute in a
	// request and the InResponseTo attribute in the corresponding
	// response MUST match
	ID           string    `xml:",attr"`
	IssueInstant time.Time `xml:",attr"`
	Issuer       string
	Signature    Signature
	Version      string `xml:",attr"`

	// Extensions are not supported for now
}

type AuthnRequest struct {
	Request
	NameIDPolicy                   *NameIDPolicy
	ForceAuthn                     bool `xml:",attr"`
	IsPassive                      bool `xml:",attr"`
	ProtocolBinding                string
	AssertionConsumerServiceURL    string `xml:",attr"`
	AssertionConsumerServiceIndex  uint8  `xml:",attr"`
	AttributeConsumingServiceIndex uint8  `xml:",attr"`
	ProviderName                   string `xml:,attr"`
	RequestedAuthnContext          *RequestedAuthnContext
}

type Conditions struct {
	NotBefore           time.Time `xml:",attr"`
	NotOnOrAfter        time.Time `xml:",attr"`
	AudienceRestriction []AudienceRestriction
	Condition           []interface{}
}

// TODO: This is a way more complex type
type Signature string
type NameID string
type SubjectConfirmation struct {
	Method       string
	InResponseTo string    `xml:"InResponseTo"`
	Recipient    string    `xml:"Recipient"`
	NotOnOrAfter time.Time `xml:"NotOnOrAfter"`
}
type Subject struct {
	NameID
	SubjectConfirmation
}
type Assertion struct {
	AuthnStatement     AuthnStatement
	AttributeStatement AttributeStatement
	Conditions         Conditions
	ID                 string    `xml:",attr"`
	IssueInstant       time.Time `xml:",attr"`
	Issuer             string    `xml:"Issuer"`
	Signature          Signature
	Subject            Subject
	Version            string   `xml:",attr"`
	XMLName            xml.Name `xml:"saml:Assertion"`
}
