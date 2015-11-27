package saml

import (
	"time"

	"github.com/lestrrat/go-libxml2"
	"github.com/lestrrat/go-xmlsec"
)

// TimeFormat is the format defined in xs:dateTime
const TimeFormat = "2006-01-02T15:04:05"

type AuthenticationMethod string
type ConfirmationMethod string
type NameIDFormat string

const (
	Bearer                      ConfirmationMethod   = `urn:oasis:names:tc:SAML:2.0:cm:bearer`
	NameIDFormatEmailAddress    NameIDFormat         = `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`
	NameIDFormatTransient       NameIDFormat         = `urn:oasis:names:tc:SAML:2.0:nameid-format:transient`
	NameIDFormatUnspecified     NameIDFormat         = `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`
	NameIDFormatX509SubjectName NameIDFormat         = `urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName`
	PasswordProtectedTransport  AuthenticationMethod = `urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport`
)

// Signer defines an interface of things that can generate XML
// signature for the given node. The node being passed should
// point to the XML element to which the signature should be
// injected into. key should be whatever appropriate key type
// that you will be using to sign
type Signer interface {
	Sign(libxml2.Node, interface{}) error
}

type GenericSign struct {
	c14nmethod xmlsec.TransformID
	digmethod  xmlsec.TransformID
	sigmethod  xmlsec.TransformID
	transform  xmlsec.TransformID
}

type AttributeValue struct {
	Type  string
	Value string
}

type Attribute struct {
	Attrs        map[string]string
	FriendlyName string
	Name         string
	Values       []AttributeValue
}

type AttributeStatement struct {
	Attributes []Attribute // Probably multiple attributes allowed?
}

type AuthnContext struct {
	AuthnContextClassRef AuthenticationMethod
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
	Format          NameIDFormat
	SPNameQualifier string
}

type RequestedAuthnContext struct {
	Comparison           string
	AuthnContextClassRef string
}

// Request represents the RequestAbstracttype from SAML specification
type Request struct {
	Consent     string
	Destination string
	// ID is an identifier for the request. It is of type xs:ID and
	// MUST follow the requirementsspecified in Section 1.3.4 for
	// identifier uniqueness. The values of the ID attribute in a
	// request and the InResponseTo attribute in the corresponding
	// response MUST match
	ID           string
	IssueInstant time.Time
	Issuer       string
	Signature    Signature
	Version      string

	// Extensions are not supported for now
}

type AuthnRequest struct {
	Request
	NameIDPolicy                   *NameIDPolicy
	ForceAuthn                     bool
	IsPassive                      bool
	ProtocolBinding                string
	AssertionConsumerServiceURL    string
	AssertionConsumerServiceIndex  uint8
	AttributeConsumingServiceIndex uint8
	ProviderName                   string
	RequestedAuthnContext          *RequestedAuthnContext
}

type Conditions struct {
	NotBefore           time.Time
	NotOnOrAfter        time.Time
	AudienceRestriction []AudienceRestriction
	Condition           []interface{}
}

// TODO: This is a way more complex type
type Signature string
type NameID struct {
	Format NameIDFormat
	Value  string
}

type SubjectConfirmation struct {
	Method       ConfirmationMethod
	InResponseTo string
	Recipient    string
	NotOnOrAfter time.Time
}
type Subject struct {
	NameID
	SubjectConfirmation
}
type Assertion struct {
	AuthnStatement     AuthnStatement
	AttributeStatement AttributeStatement
	Conditions         Conditions
	ID                 string
	IssueInstant       time.Time
	Issuer             string
	Signature          Signature
	Subject            Subject
	Version            string
}
