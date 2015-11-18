package saml

import (
	"encoding/xml"
	"time"
)

const TimeFormat = "2006-01-02T15:04:05"

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

type Conditions struct {
	NotBefore           time.Time `xml:",attr"`
	NotOnOrAfter        time.Time `xml:",attr"`
	AudienceRestriction []AudienceRestriction
	Condition           []interface{}
}

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
