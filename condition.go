package saml

import "time"

func (c *Conditions) SetNotBefore(t time.Time) {
	c.NotBefore = t
	// XXX shobosso says issue_time + 660
	c.NotOnOrAfter = t.Add(11 * time.Minute)
}

func (c *Conditions) AddAudience(s string) {
	c.AudienceRestriction.Audience = append(c.AudienceRestriction.Audience, s)
}
