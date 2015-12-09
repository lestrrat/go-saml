package saml

import (
	"time"

	"github.com/lestrrat/go-libxml2/types"
	"github.com/lestrrat/go-saml/ns"
	"github.com/satori/go.uuid"
)

var UUIDURL = "github.com/lestrrat/go-saml"

func (msg *Message) Initialize() *Message {
	msg.ID = uuid.NewV5(uuid.NamespaceDNS, UUIDURL).String()
	msg.Version = "2.0"
	msg.IssueInstant = time.Now()
	return msg
}

func (m Message) MakeXMLNode(d types.Document) (types.Node, error) {
	mxml, err := d.CreateElement("Message")
	if err != nil {
		return nil, err
	}
	mxml.MakeMortal()
	defer mxml.AutoFree()

	mxml.SetAttribute("ID", m.ID)
	mxml.SetAttribute("Version", m.Version)
	mxml.SetAttribute("IssueInstant", m.IssueInstant.Format(TimeFormat))
	if v := m.Destination; v != "" {
		mxml.SetAttribute("Destination", v)
	}
	if v := m.Consent; v != "" {
		mxml.SetAttribute("Consent", v)
	}

	// XXX Comeback later.
	iss, err := d.CreateElementNS(ns.SAML.URI, ns.SAML.AddPrefix("Issuer"))
	if err != nil {
		return nil, err
	}
	iss.AppendText(m.Issuer)
	mxml.AddChild(iss)

	mxml.MakePersistent()

	return mxml, nil
}
