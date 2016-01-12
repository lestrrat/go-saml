package saml

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lestrrat/go-libxml2/dom"
	"github.com/lestrrat/go-libxml2/types"
	"github.com/lestrrat/go-libxml2/xpath"
	"github.com/lestrrat/go-saml/nameid"
	"github.com/lestrrat/go-saml/ns"
)

func serialize(n MakeXMLNoder) (string, error) {
	d := dom.CreateDocument()
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
	return dom.C14NSerialize{}.Serialize(d)
}

func (a Assertion) Serialize() (string, error) {
	return serialize(a)
}

func (a Assertion) MakeXMLNode(d types.Document) (types.Node, error) {
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

	for _, noder := range []MakeXMLNoder{a.Subject, a.Conditions, a.AuthnStatement, a.AttributeStatement} {
		n, err := noder.MakeXMLNode(d)
		if err != nil {
			return nil, err
		}
		axml.AddChild(n)
	}

	return axml, nil
}

func (s Subject) MakeXMLNode(d types.Document) (types.Node, error) {
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

func (n NameID) MakeXMLNode(d types.Document) (types.Node, error) {
	nameid, err := d.CreateElement(ns.SAML.AddPrefix("NameID"))
	if err != nil {
		return nil, err
	}
	nameid.SetAttribute("Format", n.Format.String())
	nameid.AppendText(n.Value)
	return nameid, nil
}

func (sc SubjectConfirmation) MakeXMLNode(d types.Document) (types.Node, error) {
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

func (c Conditions) MakeXMLNode(d types.Document) (types.Node, error) {
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

func (ar AudienceRestriction) MakeXMLNode(d types.Document) (types.Node, error) {
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

func (as AuthnStatement) MakeXMLNode(d types.Document) (types.Node, error) {
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

func (ac AuthnContext) MakeXMLNode(d types.Document) (types.Node, error) {
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

func (as AttributeStatement) MakeXMLNode(d types.Document) (types.Node, error) {
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

func (av AttributeValue) MakeXMLNode(d types.Document) (types.Node, error) {
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

func (a Attribute) MakeXMLNode(d types.Document) (types.Node, error) {
	axml, err := d.CreateElement(ns.SAML.AddPrefix("Attribute"))
	if err != nil {
		return nil, err
	}
	axml.MakeMortal()
	defer axml.AutoFree()

	axml.SetAttribute("Name", a.Name)

	// Process xmlns first
	for k, v := range a.Attrs {
		if !strings.HasPrefix(k, "xmlns") {
			continue
		}

		prefix := ""
		if i := strings.IndexByte(k, ':'); i > 0 {
			prefix = k[i+1:]
		}
		if err := axml.SetNamespace(v, prefix, false); err != nil {
			return nil, err
		}
	}

	for k, v := range a.Attrs {
		if strings.HasPrefix(k, "xmlns") {
			continue
		}

		if i := strings.IndexByte(k, ':'); i > 0 {
			if _, err := axml.LookupNamespaceURI(k[:i]); err != nil {
				return nil, err
			}
			axml.SetAttribute(k, v)
		}
	}

	if v := a.FriendlyName; v != "" {
		axml.SetAttribute("FriendlyName", v)
	}

	for _, v := range a.Values {
		vxml, err := v.MakeXMLNode(d)
		if err != nil {
			return nil, err
		}
		axml.AddChild(vxml)
	}
	axml.MakePersistent()
	return axml, nil
}

func (rac RequestedAuthnContext) MakeXMLNode(d types.Document) (types.Node, error) {
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

func (nip *NameIDPolicy) PopulateFromXML(n types.Element) error {
	xpc, err := makeXPathContext(n)
	if err != nil {
		return err
	}

	nip.AllowCreate = xpath.Bool(xpc.Find("@AllowCreate"))
	nip.Format = nameid.Format(xpath.String(xpc.Find("@Format")))
	nip.SPNameQualifier = xpath.String(xpc.Find("@SPNameQualifier"))
	return nil
}

func (nip NameIDPolicy) MakeXMLNode(d types.Document) (types.Node, error) {
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

// makeXPC wraps a node and creates an XPathContext that has all of the
// required namespaces registered to handle SAML node parsing
func makeXPathContext(n types.Node) (*xpath.Context, error) {
	xpc, err := xpath.NewContext(n)
	if err != nil {
		return nil, errors.New("failed to create xpath context: " + err.Error())
	}

	if err := xpc.RegisterNS(ns.SAML.Prefix, ns.SAML.URI); err != nil {
		return nil, errors.New("failed to register namespace for xpath context: " + err.Error())
	}
	return xpc, nil
}

func (r *Request) PopulateFromXML(n types.Node) error {
	xpc, err := makeXPathContext(n)
	if err != nil {
		return err
	}

	r.ID = xpath.String(xpc.Find("@ID"))
	r.Version = xpath.String(xpc.Find("@Version"))
	s := xpath.String(xpc.Find("@IssueInstant"))
	if s == "" {
		t, err := time.Parse(TimeFormat, s)
		if err == nil {
			r.IssueInstant = t
		}
	}

	r.Issuer = xpath.String(xpc.Find(ns.SAML.AddPrefix("Issuer")))
	return nil
}

func (e Endpoint) MakeXMLNode(doc types.Document) (types.Node, error) {
	root, err := doc.CreateElement(fmt.Sprintf("md:%s", e.Name))
	if err != nil {
		return nil, err
	}

	if v := e.ProtocolBinding.String(); v != "" {
		root.SetAttribute("Binding", v)
	}
	if v := e.Location; v != "" {
		root.SetAttribute("Location", v)
	}
	if v := e.ResponseLocation; v != "" {
		root.SetAttribute("ResponseLocation", v)
	}

	return root, nil
}

func (s AssertionConsumerService) MakeXMLNode(doc types.Document) (types.Node, error) {
	root, err := doc.CreateElement("md:AssertionConsumerService")
	if err != nil {
		return nil, err
	}
	defer root.AutoFree()
	root.MakeMortal()

	root.SetAttribute("Binding", s.ProtocolBinding)
	root.SetAttribute("Location", s.Location)
	root.SetAttribute("index", strconv.Itoa(s.Index))

	root.MakePersistent()
	return root, nil
}
