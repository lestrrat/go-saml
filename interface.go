package saml

import (
	"time"

	"github.com/lestrrat/go-libxml2/types"
	"github.com/lestrrat/go-saml/nameid"
)

// MakeXMLNoder defines the interface for things that can marshal
// itself into libxml2 Nodes
type MakeXMLNoder interface {
	MakeXMLNode(types.Document) (types.Node, error)
}

// TimeFormat is the format defined in xs:dateTime
const TimeFormat = "2006-01-02T15:04:05"

type StatusCode string

// Error satisfies the "error" interface.
func (s StatusCode) Error() string {
	return s.String()
}

func (s StatusCode) String() string {
	return string(s)
}

// Top-level status codes
const (
	// StatusSuccess means the request succeeded. Additional information MAY
	// be returned in the <StatusMessage> and/or <StatusDetail> elements.
	StatusSuccess StatusCode = "urn:oasis:names:tc:SAML:2.0:status:Success"

	// ErrRequester means that the request could not be performed due to
	// an error on the part of the requester
	ErrRequester StatusCode = "urn:oasis:names:tc:SAML:2.0:status:Requester"

	// ErrResponder means the request could not be performed due to an error
	// on the part of the SAML responder or SAML authority.
	ErrResponder StatusCode = "urn:oasis:names:tc:SAML:2.0:status:Responder"

	// ErrVersionMismatch the SAML responder could not process the request
	// because the version of the request message was incorrect.
	ErrVersionMismatch StatusCode = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"
)

// Second-level status codes described in https://www.oasis-open.org/committees/download.php/56777/sstc-saml-core-errata-2.0-wd-07-diff.pdf.
// Quoth: "System entities are free to define more specific status codes by
// defining appropriate URI references.
const (
	// ErrAuthnFailed means the responding provider was unable to
	// successfully authenticate the principal.
	ErrAuthnFailed StatusCode = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"

	// ErrInvalidAttrNameOrValue means an unexpected or invalid content
	// was encountered within a <saml:Attribute> or <saml:AttributeValue>
	// element.
	ErrInvalidAttrNameOrValue StatusCode = "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue"

	// ErrInvalidNameIDPolicy means the responding provider cannot or
	// will not support the requested name identifier policy.
	ErrInvalidNameIDPolicy StatusCode = "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"

	// ErrNoAuthnContext means the specified authentication context
	// requirements cannot be met by the responder.
	ErrNoAuthnContext StatusCode = "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext"

	// ErrNoAvailableIDP is used by an intermediary to indicate that
	// none of the supported identity provider <Loc> elements in an
	// <IDPList> can be resolved or that none of the supported identity
	// providers are available.
	ErrNoAvailableIDP StatusCode = "urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP"

	// ErrNoPassive indicates the responding provider cannot authenticate
	// the principal passively, as has been requested.
	ErrNoPassive StatusCode = "urn:oasis:names:tc:SAML:2.0:status:NoPassive"

	// ErrNoSupportedIDP is used by an intermediary to indicate that none
	// of the identity providers in an <IDPList> are supported by the
	// intermediary.
	ErrNoSupportedIDP StatusCode = "urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP"

	// ErrPartialLogout is used by a session authority to indicate to
	// a session participant that it was not able to propagate logout
	// to all other session participants.
	ErrPartialLogout StatusCode = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout"

	// ErrProxyCountExceeded indicates that a responding provider cannot
	// authenticate the principal directly and is not permitted to proxy
	// the request further.
	ErrProxyCountExceeded StatusCode = "urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded"

	// ErrRequestDenied means the SAML responder or SAML authority is
	// able to process the request but has chosen not to respond. This
	// status code MAY be used when there is concern about the security
	// context of the request message or the sequence of request messages
	// received from a particular requester.
	ErrRequestDenied StatusCode = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"

	// ErrRequestUnsupported means the SAML responder or SAML authority
	// does not support the request.
	ErrRequestUnsupported StatusCode = "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported"

	// ErrRequestVersionDeprecated means the SAML responder cannot process
	// any requests with the protocol version specified in the request.
	ErrRequestVersionDeprecated StatusCode = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated"

	// ErrRequestVersionTooHigh means the SAML responder cannot process
	// the request because the protocol version specified in the request
	// message is a major upgrade from the highest protocol version supported
	// by the responder.
	ErrRequestVersionTooHigh StatusCode = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh"

	// ErrRequestVersionTooLow means the SAML responder cannot process
	// the request because the protocol version specified in the request
	// message is too low.
	ErrRequestVersionTooLow StatusCode = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow"

	// ErrResourceNotRecognized means the resource value provided in the
	// request message is invalid or unrecognized.
	ErrResourceNotRecognized StatusCode = "urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized"

	// ErrTooManyResponses means the response message would contain more
	// elements than the SAML responder is able to return.
	ErrTooManyResponses StatusCode = "urn:oasis:names:tc:SAML:2.0:status:TooManyResponses"

	// ErrUnknownAttrProfile means an entity that has no knowledge of a
	// particular attribute profile has been presented with an attribute
	// drawn from that profile.
	ErrUnknownAttrProfile StatusCode = "urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile"

	// ErrUnknownPrincipal means the responding provider does not recognize
	// the principal specified or implied by the request.
	ErrUnknownPrincipal StatusCode = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal"

	// ErrUnsupportedBinding means the SAML responder cannot properly fulfill
	// the request using the protocol binding specified in the request.
	ErrUnsupportedBinding StatusCode = "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding"
)

type AuthenticationMethod string
type ConfirmationMethod string

const (
	Bearer                     ConfirmationMethod   = `urn:oasis:names:tc:SAML:2.0:cm:bearer`
	PasswordProtectedTransport AuthenticationMethod = `urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport`
)

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
	Format          nameid.Format
	SPNameQualifier string
}

type RequestedAuthnContext struct {
	Comparison           string
	AuthnContextClassRef string
}

type Message struct {
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
	Version      string

	// Extensions are not supported for now
}

type Response struct {
	Message
	Status       StatusCode
	InResponseTo string
	Assertion    Assertion
}

// Request represents the RequestAbstracttype from SAML specification
type Request struct {
	Message
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

type NameID struct {
	Format nameid.Format
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
	Subject            Subject
	Version            string
}

type EntityID string
type Endpoint struct {
	Name             string
	ProtocolBinding  string
	Location         string
	ResponseLocation string
}
type IndexedEndpoint struct {
	Endpoint
	Index     int
	IsDefault bool
}

type AssertionConsumerService struct {
	ProtocolBinding string
	Location        string
	Index           int
}
