package saml

func (am AuthenticationMethod) String() string {
	return string(am)
}

func (cm ConfirmationMethod) String() string {
	return string(cm)
}

func (n NameIDFormat) String() string {
	return string(n)
}

func (c *Conditions) AddAudienceRestriction(ar AudienceRestriction) error {
	c.AudienceRestriction = append(c.AudienceRestriction, ar)
	return nil
}

func (a *Assertion) AddAttribute(att Attribute) error {
	a.AttributeStatement.Attributes = append(a.AttributeStatement.Attributes, att)
	return nil
}

func NewNameIDPolicy(f NameIDFormat, allowCreate bool) *NameIDPolicy {
	return &NameIDPolicy {
		Format: f,
		AllowCreate: allowCreate,
	}
}

func NewRequestedAuthnContext(cmp, classRef string) *RequestedAuthnContext {
	return &RequestedAuthnContext{
		Comparison: cmp,
		AuthnContextClassRef: classRef,
	}
}

func NewAuthnRequest() *AuthnRequest {
	return &AuthnRequest{
		Request: Request{},
	}
}


