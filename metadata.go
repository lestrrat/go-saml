package saml

import (
	"errors"
	"strconv"

	"github.com/lestrrat/go-libxml2/dom"
	"github.com/lestrrat/go-libxml2/types"
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

func (ent EntityDescriptor) MakeXMLNode(doc types.Document) (types.Node, error) {
	root, err := doc.CreateElementNS(ns.Metadata.URI, ns.Metadata.AddPrefix("EntityDescriptor"))
	if err != nil {
		return nil, err
	}
	defer root.AutoFree()
	root.MakeMortal()

	root.SetNamespace(ns.XMLDSignature.URI, ns.XMLDSignature.Prefix, false)
	root.SetAttribute("entityID", ent.ID)

	ssodesc, err := ent.SPSSODescriptor.MakeXMLNode(doc)
	if err != nil {
		return nil, err
	}
	root.AddChild(ssodesc)

	root.MakePersistent()

	return root, nil
}

func (s SSODescriptor) MakeXMLNode(doc types.Document) (types.Node, error) {
	typ := s.Type
	if typ == "" {
		typ = "SP"
	}

	root, err := doc.CreateElement("md:" + typ + "SSODescriptor")
	if err != nil {
		return nil, err
	}
	defer root.AutoFree()
	root.MakeMortal()

	root.SetAttribute("protocolSupportEnumeration", "urn:oasis:names:tc:SAML:2.0:protocol")
	service, err := s.Service.MakeXMLNode(doc)
	if err != nil {
		return nil, err
	}
	root.AddChild(service)

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
