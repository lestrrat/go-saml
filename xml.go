package saml

import (
	"encoding/xml"
	"errors"

	"github.com/lestrrat/go-saml/ns"
)

func (av AttributeValue) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = ns.SAML.XMLName("AttributeValue")
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
	start.Name = ns.SAML.XMLName("Attribute")
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
	start.Name = ns.SAML.XMLName("AuthnStatement")
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

func (ar AudienceRestriction) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = ns.SAML.XMLName("AudienceRestriction")
	e.EncodeToken(start)
	for _, a := range ar.Audience {
		e.EncodeToken(xml.StartElement{Name: ns.SAML.XMLName("Audience")})
		e.EncodeToken(xml.CharData(a))
		e.EncodeToken(xml.EndElement{Name: ns.SAML.XMLName("Audience")})
	}
	e.EncodeToken(xml.EndElement{Name: start.Name})
	return nil
}

func (c Conditions) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = ns.SAML.XMLName("Conditions")
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
	for _, ar := range c.AudienceRestriction {
		e.Encode(ar)
	}
	e.EncodeToken(xml.EndElement{Name: start.Name})
	return nil
}

func (sc SubjectConfirmation) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	if sc.Method == "" {
		sc.Method = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
	}
	start.Name = ns.SAML.XMLName("SubjectConfirmation")
	start.Attr = append(start.Attr, xml.Attr{
		Name:  xml.Name{Local: "Method"},
		Value: sc.Method,
	})
	e.EncodeToken(start)
	e.EncodeToken(xml.StartElement{
		Name: ns.SAML.XMLName("SubjectConfirmationData"),
		Attr: []xml.Attr{
			xml.Attr{Name: xml.Name{Local: "InResponseTo"}, Value: sc.InResponseTo},
			xml.Attr{Name: xml.Name{Local: "Recipient"}, Value: sc.Recipient},
			xml.Attr{Name: xml.Name{Local: "NotOnOrAfter"}, Value: sc.NotOnOrAfter.Format(TimeFormat)},
		},
	})
	e.EncodeToken(xml.EndElement{Name: ns.SAML.XMLName("SubjectConfirmationData")})
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
	start.Name = ns.SAML.XMLName("Subject")
	e.EncodeToken(start)
	e.EncodeElement(s.NameID, xml.StartElement{Name: ns.SAML.XMLName("NameID")})
	e.EncodeElement(s.SubjectConfirmation, xml.StartElement{Name: ns.SAML.XMLName("SubjectConfirmation")})
	e.EncodeToken(xml.EndElement{Name: start.Name})
	return nil
}

func (s Signature) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = xml.Name{Local: "ds:Signature"}
	start.Attr = append(start.Attr, ns.XMLDSignature.XMLAttr())
	e.EncodeToken(start)
	e.EncodeToken(xml.EndElement{Name: start.Name})
	return nil
}

func (a Assertion) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = ns.SAML.XMLName("Assertion")
	start.Attr = append(
		start.Attr,
		ns.SAML.XMLAttr(),
		ns.XMLSchema.XMLAttr(),
		ns.XMLSchemaInstance.XMLAttr(),
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
	e.EncodeElement(a.Issuer, xml.StartElement{Name: ns.SAML.XMLName("Issuer")})
	e.EncodeElement(a.Signature, xml.StartElement{Name: ns.SAML.XMLName("Signature")})
	e.EncodeElement(a.Subject, xml.StartElement{Name: ns.SAML.XMLName("Subject")})
	e.EncodeElement(a.Conditions, xml.StartElement{Name: ns.SAML.XMLName("Conditions")})
	e.EncodeElement(a.AuthnStatement, xml.StartElement{Name: ns.SAML.XMLName("AuthnStatement")})
	e.EncodeElement(a.AttributeStatement, xml.StartElement{Name: ns.SAML.XMLName("AttributeStatement")})
	e.EncodeToken(xml.EndElement{Name: start.Name})

	return nil
}
