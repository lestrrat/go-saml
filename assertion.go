package saml

func (c *Conditions) AddAudienceRestriction(ar AudienceRestriction) error {
	c.AudienceRestriction = append(c.AudienceRestriction, ar)
	return nil
}

func (a *Assertion) AddAttribute(att Attribute) error {
	a.AttributeStatement.Attributes = append(a.AttributeStatement.Attributes, att)
	return nil
}
