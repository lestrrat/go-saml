package saml

func (c *Conditions) AddAudienceRestriction(ar AudienceRestriction) error {
	c.AudienceRestriction = append(c.AudienceRestriction, ar)
	return nil
}

func (a *Assertion) AddAttribute(att Attribute) error {
	a.AttributeStatement.Attributes = append(a.AttributeStatement.Attributes, att)
	return nil
}

func NewNameIDPolicy(f string, allowCreate bool) *NameIDPolicy {
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


