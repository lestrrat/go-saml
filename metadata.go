package saml

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/lestrrat/go-libxml2/dom"
	"github.com/lestrrat/go-libxml2/types"
	"github.com/lestrrat/go-saml/nameid"
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

func (nif NameIDFormat) MakeXMLNode(doc types.Document) (types.Node, error) {
	root, err := doc.CreateElement("md:NameIDFormat")
	if err != nil {
		return nil, err
	}

	root.AppendText(nameid.Transient)
	return root, nil
}

func (e Endpoint) MakeXMLNode(doc types.Document) (types.Node, error) {
	root, err := doc.CreateElement(fmt.Sprintf("md:%s", e.Name))
	if err != nil {
		return nil, err
	}

	if v := e.ProtocolBinding; v != "" {
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

func (desc IDPDescriptor) SingleLogoutServices() []Endpoint {
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
	idpdesc.SetAttribute("protocolSupportEnumeration", "urn:oasis:names:tc:SAML:2.0:protocol")

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

	root.MakePersistent()

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
