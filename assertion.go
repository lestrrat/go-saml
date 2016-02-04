package saml

import (
	"time"

	"github.com/lestrrat/go-saml/nameid"
	"github.com/satori/go.uuid"
)

func NewAssertion() *Assertion {
	a := &Assertion{}
	a.Version = "2.0"
	a.Conditions.SetNotBefore(time.Now())
	a.ID = uuid.NewV5(uuid.NamespaceDNS, UUIDURL).String()

	return a
}

func (am AuthenticationMethod) String() string {
	return string(am)
}

func (cm ConfirmationMethod) String() string {
	return string(cm)
}

func (a *Assertion) AddAttribute(att Attribute) error {
	a.AttributeStatement.Attributes = append(a.AttributeStatement.Attributes, att)
	return nil
}

func NewNameIDPolicy(f nameid.Format, allowCreate bool) *NameIDPolicy {
	return &NameIDPolicy{
		Format:      f,
		AllowCreate: allowCreate,
	}
}

func NewRequestedAuthnContext(cmp, classRef string) *RequestedAuthnContext {
	return &RequestedAuthnContext{
		Comparison:           cmp,
		AuthnContextClassRef: classRef,
	}
}
