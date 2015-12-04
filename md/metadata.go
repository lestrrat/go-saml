package md

import (
	"bytes"
	"errors"
	"time"

	"github.com/lestrrat/go-libxml2/dom"
	"github.com/lestrrat/go-libxml2/types"
	"github.com/lestrrat/go-saml"
	"github.com/lestrrat/go-saml/ns"
)

func (m Metadata) Serialize() (string, error) {
	doc := dom.CreateDocument()
	defer doc.Free()

	root, err := m.MakeXMLNode(doc)
	if err != nil {
		return "", err
	}

	doc.SetDocumentElement(root)
	return doc.Dump(true), nil
}

func (m Metadata) MakeXMLNode(doc types.Document) (types.Node, error) {
	if len(m.EntityDescriptors) == 1 {
		return m.EntityDescriptors[0].MakeXMLNode(doc)
	}
	return nil, errors.New("unimplemented")
}

func (desc IDPDescriptor) SingleLogoutServices() []saml.Endpoint {
	return desc.SSODescriptor.SingleLogoutService
}

func (desc IDPDescriptor) MakeXMLNode(doc types.Document) (types.Node, error) {
	root, err := doc.CreateElementNS(ns.Metadata.URI, ns.Metadata.AddPrefix("EntityDescriptor"))
	if err != nil {
		return nil, err
	}
	defer root.AutoFree()
	root.MakeMortal()

	root.SetNamespace(ns.XMLDSignature.URI, ns.XMLDSignature.Prefix, false)
	root.SetAttribute("entityID", desc.ID())

	idpdesc, err := doc.CreateElement("md:IDPSSODescriptor")
	if err != nil {
		return nil, err
	}
	root.AddChild(idpdesc)

	if len(desc.RoleDescriptor.ProtocolSupportEnumerations) == 0 {
		desc.RoleDescriptor.ProtocolSupportEnumerations = []string{ns.SAMLP.URI}
	}

	protobuf := bytes.Buffer{}
	for i, proto := range desc.RoleDescriptor.ProtocolSupportEnumerations {
		protobuf.WriteString(proto)
		if i != len(desc.RoleDescriptor.ProtocolSupportEnumerations)-1 {
			protobuf.WriteString(" ")
		}
	}
	idpdesc.SetAttribute("protocolSupportEnumeration", protobuf.String())

	if k := desc.KeyDescriptor; k != nil {
		kdesc, err := k.MakeXMLNode(doc)
		if err != nil {
			return nil, err
		}
		idpdesc.AddChild(kdesc)
	}

	if v := desc.ErrorURL; v != "" {
		idpdesc.SetAttribute("errorURL", v)
	}

	for _, sls := range desc.SingleLogoutServices() {
		sls.Name = "SingleLogoutService"
		slsdesc, err := sls.MakeXMLNode(doc)
		if err != nil {
			return nil, err
		}
		idpdesc.AddChild(slsdesc)
	}
	{
		nif, err := desc.NameIDFormat.MakeXMLNode(doc)
		if err != nil {
			return nil, err
		}
		idpdesc.AddChild(nif)
	}
	for _, ssos := range desc.SingleSignOnService {
		ssos.Name = "SingleSignOnService"
		ssosdesc, err := ssos.MakeXMLNode(doc)
		if err != nil {
			return nil, err
		}
		idpdesc.AddChild(ssosdesc)
	}

	if cp := desc.ContactPerson; cp != nil {
		cpnode, err := cp.MakeXMLNode(doc)
		if err != nil {
			return nil, err
		}
		root.AddChild(cpnode)
	}
	root.MakePersistent()

	return root, nil
}

func (id IDPDescriptor) ID() string {
	return id.CommonDescriptor.ID
}

func (id IDPDescriptor) Name() string {
	return id.CommonDescriptor.Name
}

func (id IDPDescriptor) CacheDuration() int {
	return id.CommonDescriptor.CacheDuration
}

func (id IDPDescriptor) ValidUntil() time.Time {
	return id.CommonDescriptor.ValidUntil
}

func (id IDPDescriptor) ProtocolSupportEnumerations() []string {
	return id.RoleDescriptor.ProtocolSupportEnumerations
}

func (cp ContactPerson) MakeXMLNode(doc types.Document) (types.Node, error) {
	root, err := doc.CreateElement("md:ContactPerson")
	if err != nil {
		return nil, err
	}
	defer root.AutoFree()
	root.MakeMortal()

	root.SetAttribute("contactType", cp.Type)

	if v := cp.Company; v != "" {
		c, err := doc.CreateElement("md:Company")
		if err != nil {
			return nil, err
		}
		c.AppendText(v)
		root.AddChild(c)
	}

	if v := cp.GivenName; v != "" {
		gn, err := doc.CreateElement("md:GivenName")
		if err != nil {
			return nil, err
		}
		gn.AppendText(v)
		root.AddChild(gn)
	}

	if v := cp.SurName; v != "" {
		sn, err := doc.CreateElement("md:SurName")
		if err != nil {
			return nil, err
		}
		sn.AppendText(v)
		root.AddChild(sn)
	}

	if v := cp.EmailAddress; v != "" {
		ea, err := doc.CreateElement("md:EmailAddress")
		if err != nil {
			return nil, err
		}
		ea.AppendText(v)
		root.AddChild(ea)
	}

	if v := cp.TelephoneNumber; v != "" {
		tn, err := doc.CreateElement("md:TelephoneNumber")
		if err != nil {
			return nil, err
		}
		tn.AppendText(v)
		root.AddChild(tn)
	}

	root.MakePersistent()

	return root, nil
}

func (kd KeyDescriptor) MakeXMLNode(doc types.Document) (types.Node, error) {
	kdnode, err := doc.CreateElement("md:KeyDescriptor")
	if err != nil {
		return nil, err
	}
	defer kdnode.AutoFree()
	kdnode.MakeMortal()

	keynode, err := kd.Key.MakeXMLNode(doc)
	if err != nil {
		return nil, err
	}
	kdnode.AddChild(keynode)

	kdnode.MakePersistent()

	return kdnode, nil
}
