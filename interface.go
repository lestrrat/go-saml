package saml

import (
	"encoding/xml"
	"time"
)

var TimeFormat = "2006-01-02T15:04:05"
var XMLSchemaNamespace = xml.Attr{
	Name:  xml.Name{Local: "xmlns:xs"},
	Value: "http://www.w3.org/2001/XMLSchema",
}
var XMLSchemaInstanceNamespace = xml.Attr{
	Name:  xml.Name{Local: "xmlns:xsi"},
	Value: "http://www.w3.org/2001/XMLSchema-instance",
}
var SAMLNamespace = xml.Attr{
	Name:  xml.Name{Local: "xmlns:saml"},
	Value: "urn:oasis:names:tc:SAML:2.0:assertion",
}
var XMLDSignatureNamespace = xml.Attr{
	Name:  xml.Name{Local: "xmlns:ds"},
	Value: "http://www.w3.org/2000/09/xmldsig#",
}
var X500Namespace = xml.Attr{
	Name:  xml.Name{Local: "xmlns:x500"},
	Value: "urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500",
}

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
	Audience string
}
type Conditions struct {
	NotBefore           time.Time `xml:",attr"`
	NotOnOrAfter        time.Time `xml:",attr"`
	AudienceRestriction AudienceRestriction
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
