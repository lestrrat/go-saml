package md

import (
	"time"

	"github.com/lestrrat/go-saml"
	"github.com/lestrrat/go-saml/nameid"
)

type CommonDescriptor struct {
	CacheDuration int
	ID            string
	Name          string
	ValidUntil    time.Time
}

type RoleDescriptor struct {
	CommonDescriptor
	ErrorURL                    string
	ProtocolSupportEnumerations []string
}

type SSODescriptor struct {
	ArtifactResolutionService []saml.IndexedEndpoint
	SingleLogoutService       []saml.Endpoint
	ManageNameIDService       []saml.Endpoint
	NameIDFormat              nameid.Format
}

type IDPDescriptor struct {
	RoleDescriptor
	SSODescriptor

	ContactPerson *ContactPerson
	KeyDescriptor *KeyDescriptor

	// WantAuthnRequestsSigned is an optional attribute that indicates a
	// requirement for the <samlp:AuthnRequest> messages received by this
	// identity provider to be signed. If omitted, the value is assumed to
	// be false.
	WantAuthnRequestsSigned bool
	// SignleSingOnService holds one or more elements of type EndpointType
	// that describe endpoints that support the profiles of the Authentication
	// Request protocol defined in [SAMLProf]. All identity providers support
	// at least one such endpoint, by definition. The ResponseLocation attribute
	// MUST be omitted.
	SingleSignOnService []saml.Endpoint
	// NameIDMappingService holds zero or more elements of type EndpointType
	// that describe endpoints that support the Name Identifier Mapping profile
	// defined in [SAMLProf]. The ResponseLocation attribute MUST be omitted
	NameIDMappingService []saml.Endpoint
	// AssertionIDRequestService holds zero or more elements of type EndpointType
	// that describe endpoints that support the profile of the Assertion Request
	// protocol defined in [SAMLProf] or the special URI binding for assertion
	// requests defined in [SAMLBind].
	AssertionIDRequestService []saml.Endpoint
	// AttributeProfile holds zero or more elements of type anyURI that enumerate
	// the attribute profiles supported by this identity provider. See [SAMLProf]
	// for some possible values for this element.
	AttributeProfile []string
	// Attribute holds zero or more elements that identify the SAML attributes
	// supported by the identity provider.  Specific values MAY optionally be
	// included, indicating that only certain values permitted by the attribute's
	// definition are supported. In this context, "support" for an attribute
	// means that the identity provider has the capability to include it when
	// delivering assertions during single sign-on.
	Attribute []saml.Attribute
}

type EntityDescriptor interface {
	saml.MakeXMLNoder

	CacheDuration() int
	ID() string
	Name() string
	ProtocolSupportEnumerations() []string
	ValidUntil() time.Time
}

type SPDescriptor struct {
	CommonDescriptor

	Service saml.AssertionConsumerService
}

type Metadata struct {
	EntityDescriptors []EntityDescriptor
}

type ContactPerson struct {
	Type            string
	Company         string
	GivenName       string
	SurName         string
	EmailAddress    string
	TelephoneNumber string
}

type KeyDescriptor struct {
	Use string
	Key saml.MakeXMLNoder
}
