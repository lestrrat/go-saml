package saml

import (
	"strconv"
	"strings"

	"github.com/lestrrat/go-libxml2"
	"github.com/lestrrat/go-saml/ns"
)

type MakeXMLNoder interface {
	MakeXMLNode(*libxml2.Document) (libxml2.Node, error)
}

func serialize(n MakeXMLNoder) (string, error) {
	d := libxml2.CreateDocument()
	defer d.Free()
	root, err := n.MakeXMLNode(d)
	if err != nil {
		return "", err
	}
	// note: no need to gc the root separately, as it's done by
	// d.Free()
	if err := d.SetDocumentElement(root); err != nil {
		return "", err
	}
	return libxml2.C14NSerialize{}.Serialize(d)
}

func (a Assertion) Serialize() (string, error) {
	return serialize(a)
}

func (a Assertion) MakeXMLNode(d *libxml2.Document) (libxml2.Node, error) {
	axml, err := d.CreateElementNS(ns.SAML.URI, ns.SAML.AddPrefix("Assertion"))
	if err != nil {
		return nil, err
	}

	axml.SetNamespace(ns.XMLSchema.URI, ns.XMLSchema.Prefix, false)
	axml.SetNamespace(ns.XMLSchemaInstance.URI, ns.XMLSchemaInstance.Prefix, false)
	axml.SetAttribute("ID", a.ID)
	axml.SetAttribute("Version", a.Version)
	axml.SetAttribute("IssueInstant", a.IssueInstant.Format(TimeFormat))

	iss, err := d.CreateElementNS(ns.SAML.URI, ns.SAML.AddPrefix("Issuer"))
	if err != nil {
		return nil, err
	}
	iss.AppendText(a.Issuer)
	axml.AddChild(iss)

	for _, noder := range []MakeXMLNoder{a.Signature, a.Subject, a.Conditions, a.AuthnStatement, a.AttributeStatement} {
		n, err := noder.MakeXMLNode(d)
		if err != nil {
			return nil, err
		}
		axml.AddChild(n)
	}

	return axml, nil
}

func (s Subject) MakeXMLNode(d *libxml2.Document) (libxml2.Node, error) {
	sub, err := d.CreateElement(ns.SAML.AddPrefix("Subject"))
	if err != nil {
		return nil, err
	}
	sub.MakeMortal()
	defer sub.AutoFree()

	for _, noder := range []MakeXMLNoder{s.NameID, s.SubjectConfirmation} {
		n, err := noder.MakeXMLNode(d)
		if err != nil {
			return nil, err
		}
		sub.AddChild(n)
	}

	sub.MakePersistent()
	return sub, nil
}

func (n NameID) MakeXMLNode(d *libxml2.Document) (libxml2.Node, error) {
	nameid, err := d.CreateElement(ns.SAML.AddPrefix("NameID"))
	if err != nil {
		return nil, err
	}
	nameid.SetAttribute("Format", n.Format.String())
	nameid.AppendText(n.Value)
	return nameid, nil
}

func (sc SubjectConfirmation) MakeXMLNode(d *libxml2.Document) (libxml2.Node, error) {
	scxml, err := d.CreateElement(ns.SAML.AddPrefix("SubjectConfirmation"))
	if err != nil {
		return nil, err
	}
	scxml.MakeMortal()
	defer scxml.AutoFree()

	method := sc.Method
	if sc.Method == "" {
		method = Bearer
	}

	scxml.SetAttribute("Method", method.String())

	scd, err := d.CreateElement(ns.SAML.AddPrefix("SubjectConfirmationData"))
	if err != nil {
		return nil, err
	}
	scd.SetAttribute("InResponseTo", sc.InResponseTo)
	scd.SetAttribute("Recipient", sc.Recipient)
	scd.SetAttribute("NotOnOrAfter", sc.NotOnOrAfter.Format(TimeFormat))

	scxml.AddChild(scd)
	scxml.MakePersistent()
	return scxml, nil
}

func (c Conditions) MakeXMLNode(d *libxml2.Document) (libxml2.Node, error) {
	cxml, err := d.CreateElement(ns.SAML.AddPrefix("Conditions"))
	if err != nil {
		return nil, err
	}
	cxml.MakeMortal()
	defer cxml.AutoFree()

	cxml.SetAttribute("NotBefore", c.NotBefore.Format(TimeFormat))
	cxml.SetAttribute("NotOnOrAfter", c.NotOnOrAfter.Format(TimeFormat))

	for _, ar := range c.AudienceRestriction {
		arxml, err := ar.MakeXMLNode(d)
		if err != nil {
			return nil, err
		}
		cxml.AddChild(arxml)
	}

	cxml.MakePersistent()
	return cxml, err
}

func (ar AudienceRestriction) MakeXMLNode(d *libxml2.Document) (libxml2.Node, error) {
	axml, err := d.CreateElement(ns.SAML.AddPrefix("AudienceRestriction"))
	if err != nil {
		return nil, err
	}
	axml.MakeMortal()
	defer axml.AutoFree()

	for _, a := range ar.Audience {
		audxml, err := d.CreateElement(ns.SAML.AddPrefix("Audience"))
		if err != nil {
			return nil, err
		}
		axml.AddChild(audxml)
		audxml.AppendText(string(a))
	}
	axml.MakePersistent()
	return axml, nil
}

func (as AuthnStatement) MakeXMLNode(d *libxml2.Document) (libxml2.Node, error) {
	asxml, err := d.CreateElement(ns.SAML.AddPrefix("AuthnStatement"))
	if err != nil {
		return nil, err
	}
	asxml.MakeMortal()
	defer asxml.AutoFree()

	asxml.SetAttribute("AuthnInstant", as.AuthnInstant.Format(TimeFormat))
	asxml.SetAttribute("SessionIndex", as.SessionIndex)
	acxml, err := as.AuthnContext.MakeXMLNode(d)
	if err != nil {
		return nil, err
	}
	asxml.AddChild(acxml)
	asxml.MakePersistent()
	return asxml, nil
}

func (ac AuthnContext) MakeXMLNode(d *libxml2.Document) (libxml2.Node, error) {
	acxml, err := d.CreateElement(ns.SAML.AddPrefix("AuthnContext"))
	if err != nil {
		return nil, err
	}
	acxml.MakeMortal()
	defer acxml.AutoFree()

	accxml, err := d.CreateElement(ns.SAML.AddPrefix("AuthnClassRef"))
	if err != nil {
		return nil, err
	}
	acxml.AddChild(accxml)
	accxml.AppendText(ac.AuthnContextClassRef.String())

	acxml.MakePersistent()
	return acxml, nil
}

func (as AttributeStatement) MakeXMLNode(d *libxml2.Document) (libxml2.Node, error) {
	asxml, err := d.CreateElement(ns.SAML.AddPrefix("AttributeStatement"))
	if err != nil {
		return nil, err
	}
	asxml.MakeMortal()
	defer asxml.AutoFree()

	for _, attr := range as.Attributes {
		attrxml, err := attr.MakeXMLNode(d)
		if err != nil {
			return nil, err
		}
		asxml.AddChild(attrxml)
	}

	asxml.MakePersistent()
	return asxml, nil
}

func (av AttributeValue) MakeNodeXML(d *libxml2.Document) (libxml2.Node, error) {
	avxml, err := d.CreateElement(ns.SAML.AddPrefix("AttributeValue"))
	if err != nil {
		return nil, err
	}
	avxml.MakeMortal()
	defer avxml.AutoFree()

	avxml.SetAttribute(ns.XMLSchemaInstance.AddPrefix("type"), av.Type)
	avxml.AppendText(av.Value)
	avxml.MakePersistent()
	return avxml, nil
}

func (a Attribute) MakeXMLNode(d *libxml2.Document) (libxml2.Node, error) {
	axml, err := d.CreateElement(ns.SAML.AddPrefix("Attribute"))
	if err != nil {
		return nil, err
	}
	axml.MakeMortal()
	defer axml.AutoFree()

	axml.SetAttribute("Name", a.Name)
	for k, v := range a.Attrs {
		if i := strings.IndexByte(k, ':'); i > 0 {
			if k[:i] == "xmlns" {
				if err := axml.SetNamespace(v, k[i+1:], false); err != nil {
					return nil, err
				}
			} else {
				if _, err := axml.LookupNamespaceURI(k[:i]); err != nil {
					return nil, err
				}
				axml.SetAttribute(k, v)
			}
		}
	}

	if v := a.FriendlyName; v != "" {
		axml.SetAttribute("FriendlyName", v)
	}

	for _, v := range a.Values {
		vxml, err := v.MakeNodeXML(d)
		if err != nil {
			return nil, err
		}
		axml.AddChild(vxml)
	}
	axml.MakePersistent()
	return axml, nil
}

func (s Signature) MakeXMLNode(d *libxml2.Document) (libxml2.Node, error) {
	sigxml, err := d.CreateElementNS("http://www.w3.org/2000/09/xmldsig#", "ds:Signature")
	if err != nil {
		return nil, err
	}
	sigxml.MakeMortal()
	defer sigxml.AutoFree()

	// XXX Later
	sigxml.MakePersistent()
	return sigxml, nil
}

func (rac RequestedAuthnContext) MakeXMLNode(d *libxml2.Document) (libxml2.Node, error) {
	racxml, err := d.CreateElement(ns.SAML.AddPrefix("RequestedAuthnContext"))
	if err != nil {
		return nil, err
	}
	racxml.MakeMortal()
	defer racxml.AutoFree()

	racxml.SetAttribute("Comparison", rac.Comparison)

	accxml, err := d.CreateElement(ns.SAML.AddPrefix("AuthnContextClassRef"))
	if err != nil {
		return nil, err
	}
	racxml.AddChild(accxml)
	accxml.AppendText(rac.AuthnContextClassRef)

	racxml.MakePersistent()
	return racxml, nil
}

func (nip NameIDPolicy) MakeXMLNode(d *libxml2.Document) (libxml2.Node, error) {
	nipxml, err := d.CreateElement(ns.SAML.AddPrefix("NameIDPolicy"))
	if err != nil {
		return nil, err
	}
	nipxml.MakeMortal()
	defer nipxml.AutoFree()

	nipxml.SetAttribute("AllowCreate", strconv.FormatBool(nip.AllowCreate))

	if v := nip.Format; v != "" {
		nipxml.SetAttribute("Format", v.String())
	}
	if v := nip.SPNameQualifier; v != "" {
		nipxml.SetAttribute("SPNameQualifier", v)
	}
	nipxml.MakePersistent()
	return nipxml, nil
}

func (ar AuthnRequest) Serialize() (string, error) {
	return serialize(ar)
}

func (ar AuthnRequest) MakeXMLNode(d *libxml2.Document) (libxml2.Node, error) {
	arxml, err := d.CreateElementNS(ns.SAML.URI, ns.SAML.AddPrefix("AuthnRequest"))
	if err != nil {
		return nil, err
	}
	arxml.MakeMortal()
	defer arxml.AutoFree()

	arxml.SetNamespace(ns.SAMLP.URI, ns.SAMLP.Prefix, false)
	arxml.SetAttribute("ID", ar.ID)
	arxml.SetAttribute("ProviderName", ar.ProviderName)
	arxml.SetAttribute("Version", ar.Version)
	arxml.SetAttribute("IssueInstant", ar.IssueInstant.Format(TimeFormat))
	arxml.SetAttribute("Destination", ar.Destination)
	arxml.SetAttribute("ProtocolBinding", ar.ProtocolBinding)
	arxml.SetAttribute("AssertionConsumerServiceURL", ar.AssertionConsumerServiceURL)

	// XXX Comeback later.
	iss, err := d.CreateElementNS(ns.SAML.URI, ns.SAML.AddPrefix("Issuer"))
	if err != nil {
		return nil, err
	}
	iss.AppendText(ar.Issuer)
	arxml.AddChild(iss)

	if nip := ar.NameIDPolicy; nip != nil {
		nipxml, err := nip.MakeXMLNode(d)
		if err != nil {
			return nil, err
		}
		arxml.AddChild(nipxml)
	}

	if rac := ar.RequestedAuthnContext; rac != nil {
		racxml, err := rac.MakeXMLNode(d)
		if err != nil {
			return nil, err
		}
		arxml.AddChild(racxml)
	}
	arxml.MakePersistent()
	return arxml, nil
}
