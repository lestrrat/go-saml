package nameid

import (
	"github.com/lestrrat/go-libxml2/types"
)

func (n Format) String() string {
	return string(n)
}

func (nif Format) MakeXMLNode(doc types.Document) (types.Node, error) {
	root, err := doc.CreateElement("md:NameIDFormat")
	if err != nil {
		return nil, err
	}

	root.AppendText(Transient)
	return root, nil
}
