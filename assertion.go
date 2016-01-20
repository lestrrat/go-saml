package saml

import "github.com/lestrrat/go-saml/nameid"

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

