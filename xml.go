package saml

import (
	"encoding/xml"
	"errors"

	"github.com/lestrrat/go-saml/ns"
)

func (av AttributeValue) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = xml.Name{Local: "saml:AttributeValue"}
	start.Attr = append(
		start.Attr,
		xml.Attr{
			Name:  xml.Name{Local: "xsi:type"},
			Value: av.Type,
		},
	)
	e.EncodeToken(start)
	e.EncodeToken(xml.CharData(av.Value))
	e.EncodeToken(xml.EndElement{Name: start.Name})
	return nil
}

func (a Attribute) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = xml.Name{Local: "saml:Attribute"}
	if a.Name == "" {
		return errors.New("missing .Name")
	}
	start.Attr = append(start.Attr, a.Attrs...)

	start.Attr = append(
		start.Attr,
		xml.Attr{
			Name:  xml.Name{Local: "Name"},
			Value: a.Name,
		},
	)

	if a.FriendlyName != "" {
		start.Attr = append(
			start.Attr,
			xml.Attr{
				Name:  xml.Name{Local: "FriendlyName"},
				Value: a.FriendlyName,
			},
		)
	}
	e.EncodeToken(start)
	for _, v := range a.Values {
		e.Encode(v)
	}
	e.EncodeToken(xml.EndElement{Name: start.Name})
	return nil
}

func (as AuthnStatement) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = xml.Name{Local: "saml:AuthnStatement"}
	start.Attr = append(
		start.Attr,
		xml.Attr{
			Name:  xml.Name{Local: "AuthnInstant"},
			Value: as.AuthnInstant.Format(TimeFormat),
		},
		xml.Attr{
			Name:  xml.Name{Local: "SessionIndex"},
			Value: as.SessionIndex,
		},
	)
	e.EncodeToken(start)
	e.Encode(as.AuthnContext)
	e.EncodeToken(xml.EndElement{Name: start.Name})
	return nil
}

func (c Conditions) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = xml.Name{Local: "saml:Conditions"}
	start.Attr = append(
		start.Attr,
		xml.Attr{
			Name:  xml.Name{Local: "NotBefore"},
			Value: c.NotBefore.Format(TimeFormat),
		},
		xml.Attr{
			Name:  xml.Name{Local: "NotOnOrAfter"},
			Value: c.NotOnOrAfter.Format(TimeFormat),
		},
	)
	e.EncodeToken(start)
	e.Encode(c.AudienceRestriction)
	e.EncodeToken(xml.EndElement{Name: start.Name})
	return nil
}

func (sc SubjectConfirmation) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	if sc.Method == "" {
		sc.Method = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
	}
	start.Name = xml.Name{Local: "saml:SubjectConfirmation"}
	start.Attr = append(start.Attr, xml.Attr{
		Name:  xml.Name{Local: "Method"},
		Value: sc.Method,
	})
	e.EncodeToken(start)
	e.EncodeToken(xml.StartElement{
		Name: xml.Name{Local: "saml:SubjectConfirmationData"},
		Attr: []xml.Attr{
			xml.Attr{Name: xml.Name{Local: "InResponseTo"}, Value: sc.InResponseTo},
			xml.Attr{Name: xml.Name{Local: "Recipient"}, Value: sc.Recipient},
			xml.Attr{Name: xml.Name{Local: "NotOnOrAfter"}, Value: sc.NotOnOrAfter.Format(TimeFormat)},
		},
	})
	e.EncodeToken(xml.EndElement{Name: xml.Name{Local: "saml:SubjectConfirmationData"}})
	e.EncodeToken(xml.EndElement{Name: start.Name})
	return nil
}

func (n NameID) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Attr = append(start.Attr, xml.Attr{
		Name:  xml.Name{Local: "Format"},
		Value: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
	})
	e.EncodeToken(start)
	e.EncodeToken(xml.CharData(n))
	e.EncodeToken(xml.EndElement{Name: start.Name})
	return nil
}

func (s Subject) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = xml.Name{Local: "saml:Subject"}
	e.EncodeToken(start)
	e.EncodeElement(s.NameID, xml.StartElement{Name: xml.Name{Local: "saml:NameID"}})
	e.EncodeElement(s.SubjectConfirmation, xml.StartElement{Name: xml.Name{Local: "saml:SubjectConfirmation"}})
	e.EncodeToken(xml.EndElement{Name: start.Name})
	return nil
}

func (s Signature) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = xml.Name{Local: "ds:Signature"}
	start.Attr = append(start.Attr, ns.XMLDSignature)
	e.EncodeToken(start)
	e.EncodeToken(xml.EndElement{Name: start.Name})
	return nil
}

func (a Assertion) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = xml.Name{Local: "saml:Assertion"}
	start.Attr = append(
		start.Attr,
		ns.SAML,
		ns.XMLSchema,
		ns.XMLSchemaInstance,
		xml.Attr{
			Name:  xml.Name{Local: "ID"},
			Value: a.ID,
		},
		xml.Attr{
			Name:  xml.Name{Local: "Version"},
			Value: a.Version,
		},
		xml.Attr{
			Name:  xml.Name{Local: "IssueInstant"},
			Value: a.IssueInstant.Format(TimeFormat),
		},
	)
	e.EncodeToken(start)
	e.EncodeElement(a.Issuer, xml.StartElement{Name: xml.Name{Local: "saml:Issuer"}})
	e.EncodeElement(a.Signature, xml.StartElement{Name: xml.Name{Local: "ds:Signature"}})
	e.EncodeElement(a.Subject, xml.StartElement{Name: xml.Name{Local: "saml:Subject"}})
	e.EncodeElement(a.Conditions, xml.StartElement{Name: xml.Name{Local: "saml:Conditions"}})
	e.EncodeElement(a.AuthnStatement, xml.StartElement{Name: xml.Name{Local: "saml:AuthnStatement"}})
	e.EncodeElement(a.AttributeStatement, xml.StartElement{Name: xml.Name{Local: "saml:AttributeStatement"}})
	e.EncodeToken(xml.EndElement{Name: start.Name})

	return nil
}
