package saml

import (
	"encoding/xml"
	"strconv"

	"github.com/lestrrat/go-libxml2"
)

const SAMLNS = `urn:oasis:names:tc:SAML:2.0:assertion`

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
	d.SetDocumentElement(root)
	return d.Dump(true), nil
}

func (a Assertion) Serialize() (string, error) {
	return serialize(a)
}

func (a Assertion) MakeXMLNode(d *libxml2.Document) (libxml2.Node, error) {
	axml, err := d.CreateElementNS(SAMLNS, "saml:Assertion")
	if err != nil {
		return nil, err
	}

	axml.SetNamespace("xs", "http://www.w3.org/2001/XMLSchema", false)
	axml.SetNamespace("xsi", "http://www.w3.org/2001/XMLSchema-instance", false)
	axml.SetAttribute("ID", a.ID)
	axml.SetAttribute("Version", a.Version)
	axml.SetAttribute("IssueInstant", a.IssueInstant.Format(TimeFormat))

	iss, err := d.CreateElementNS(SAMLNS, "saml:Issuer")
	if err != nil {
		return nil, err
	}
	iss.AppendText(a.Issuer)
	axml.AppendChild(iss)

	for _, noder := range []MakeXMLNoder{a.Signature, a.Subject, a.Conditions, a.AuthnStatement, a.AttributeStatement} {
		n, err := noder.MakeXMLNode(d)
		if err != nil {
			return nil, nil
		}
		axml.AppendChild(n)
	}

	return axml, nil
}

func (s Subject) MakeXMLNode(d *libxml2.Document) (libxml2.Node, error) {
	sub, err := d.CreateElement("saml:Subject")
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
		sub.AppendChild(n)
	}

	sub.MakePersistent()
	return sub, nil
}

func (n NameID) MakeXMLNode(d *libxml2.Document) (libxml2.Node, error) {
	nameid, err := d.CreateElement("saml:NameID")
	if err != nil {
		return nil, err
	}
	nameid.SetAttribute("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:transient")
	nameid.AppendText(string(n))
	return nameid, nil
}

func (sc SubjectConfirmation) MakeXMLNode(d *libxml2.Document) (libxml2.Node, error) {
	scxml, err := d.CreateElement("saml:SubjectConfirmation")
	if err != nil {
		return nil, err
	}
	scxml.MakeMortal()
	defer scxml.AutoFree()

	method := sc.Method
	if sc.Method == "" {
		method = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
	}

	scxml.SetAttribute("Method", method)

	scd, err := d.CreateElement("saml:SubjectConfirmationData")
	if err != nil {
		return nil, err
	}
	scd.SetAttribute("InResponseTo", sc.InResponseTo)
	scd.SetAttribute("Recipient", sc.Recipient)
	scd.SetAttribute("NotOnOrAfter", sc.NotOnOrAfter.Format(TimeFormat))

	scxml.AppendChild(scd)
	scxml.MakePersistent()
	return scxml, nil
}

func (c Conditions) MakeXMLNode(d *libxml2.Document) (libxml2.Node, error) {
	cxml, err := d.CreateElement("saml:Conditions")
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
		cxml.AppendChild(arxml)
	}

	cxml.MakePersistent()
	return cxml, err
}

func (ar AudienceRestriction) MakeXMLNode(d *libxml2.Document) (libxml2.Node, error) {
	axml, err := d.CreateElement("saml:AudienceRestriction")
	if err != nil {
		return nil, err
	}
	axml.MakeMortal()
	defer axml.AutoFree()

	for _, a := range ar.Audience {
		audxml, err := d.CreateElement("saml:Audience")
		if err != nil {
			return nil, err
		}
		axml.AppendChild(audxml)
		audxml.AppendText(string(a))
	}
	axml.MakePersistent()
	return axml, nil
}

func (as AuthnStatement) MakeXMLNode(d *libxml2.Document) (libxml2.Node, error) {
	asxml, err := d.CreateElement("saml:AuthnStatement")
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
	asxml.AppendChild(acxml)
	asxml.MakePersistent()
	return asxml, nil
}

func (ac AuthnContext) MakeXMLNode(d *libxml2.Document) (libxml2.Node, error) {
	acxml, err := d.CreateElement("saml:AuthnContext")
	if err != nil {
		return nil, err
	}
	acxml.MakeMortal()
	defer acxml.AutoFree()

	accxml, err := d.CreateElement("saml:AuthnClassRef")
	if err != nil {
		return nil, err
	}
	acxml.AppendChild(accxml)
	accxml.AppendText(ac.AuthnContextClassRef)

	acxml.MakePersistent()
	return acxml, nil
}

func attr(name, value string) xml.Attr {
	return attrFull(xml.Name{Local: name}, value)
}

func attrFull(name xml.Name, value string) xml.Attr {
	return xml.Attr{
		Name:  name,
		Value: value,
	}
}

func (as AttributeStatement) MakeXMLNode(d *libxml2.Document) (libxml2.Node, error) {
	asxml, err := d.CreateElement("saml:AttributeStatement")
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
		asxml.AppendChild(attrxml)
	}

	asxml.MakePersistent()
	return asxml, nil
}

func (av AttributeValue) MakeNodeXML(d *libxml2.Document) (libxml2.Node, error) {
	avxml, err := d.CreateElement("saml:AttributeValue")
	if err != nil {
		return nil, err
	}
	avxml.MakeMortal()
	defer avxml.AutoFree()

	avxml.SetAttribute("xsi:type", av.Type)
	avxml.AppendText(av.Value)
	avxml.MakePersistent()
	return avxml, nil
}

func (a Attribute) MakeXMLNode(d *libxml2.Document) (libxml2.Node, error) {
	axml, err := d.CreateElement("saml:Attribute")
	if err != nil {
		return nil, err
	}
	axml.MakeMortal()
	defer axml.AutoFree()

	axml.SetAttribute("Name", a.Name)
	for _, attr := range a.Attrs {
		if nsuri := attr.Name.Space; nsuri != "" {
			prefix, err := axml.LookupNamespacePrefix(nsuri)
			if err != nil {
				return nil, err
			}

			axml.SetAttribute(prefix+":"+attr.Name.Local, attr.Value)
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
		axml.AppendChild(vxml)
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
	racxml, err := d.CreateElement("saml:RequestedAuthnContext")
	if err != nil {
		return nil, err
	}
	racxml.MakeMortal()
	defer racxml.AutoFree()

	racxml.SetAttribute("Comparison", rac.Comparison)

	accxml, err := d.CreateElement("saml:AuthnContextClassRef")
	if err != nil {
		return nil, err
	}
	racxml.AppendChild(accxml)
	accxml.AppendText(rac.AuthnContextClassRef)

	racxml.MakePersistent()
	return racxml, nil
}

func (nip NameIDPolicy) MakeXMLNode(d *libxml2.Document) (libxml2.Node, error) {
	nipxml, err := d.CreateElement("saml:NameIDPolicy")
	if err != nil {
		return nil, err
	}
	nipxml.MakeMortal()
	defer nipxml.AutoFree()

	nipxml.SetAttribute("AllowCreate", strconv.FormatBool(nip.AllowCreate))

	if v := nip.Format; v != "" {
		nipxml.SetAttribute("Format", v)
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
	arxml, err := d.CreateElement("saml:AuthnRequest")
	if err != nil {
		return nil, err
	}
	arxml.MakeMortal()
	defer arxml.AutoFree()

	arxml.SetNamespace("saml", SAMLNS)
	arxml.SetNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol", false)
	arxml.SetAttribute("ID", ar.ID)
	arxml.SetAttribute("ProviderName", ar.ProviderName)
	arxml.SetAttribute("Version", ar.Version)
	arxml.SetAttribute("IssueInstant", ar.IssueInstant.Format(TimeFormat))
	arxml.SetAttribute("Destination", ar.Destination)
	arxml.SetAttribute("ProtocolBinding", ar.ProtocolBinding)
	arxml.SetAttribute("AssertionConsumerServiceURL", ar.AssertionConsumerServiceURL)

	// XXX Comeback later.
	iss, err := d.CreateElementNS(SAMLNS, "saml:Issuer")
	if err != nil {
		return nil, err
	}
	iss.AppendText(ar.Issuer)
	arxml.AppendChild(iss)

	if nip := ar.NameIDPolicy; nip != nil {
		nipxml, err := nip.MakeXMLNode(d)
		if err != nil {
			return nil, err
		}
		arxml.AppendChild(nipxml)
	}

	if rac := ar.RequestedAuthnContext; rac != nil {
		racxml, err := rac.MakeXMLNode(d)
		if err != nil {
			return nil, err
		}
		arxml.AppendChild(racxml)
	}
	arxml.MakePersistent()
	return arxml, nil
}
