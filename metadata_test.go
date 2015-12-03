package saml_test

import (
	"testing"

	"github.com/lestrrat/go-saml"
	"github.com/lestrrat/go-saml/binding"
	"github.com/stretchr/testify/assert"
)

func TestMetadata(t *testing.T) {
	md := saml.Metadata{
		EntityDescriptors: []saml.EntityDescriptor{
			saml.EntityDescriptor{
				ID: "https://github.com/lestrrat/go-saml",
				SPSSODescriptor: saml.SSODescriptor{
					Service: saml.AssertionConsumerService{
						ProtocolBinding: binding.HTTPPost,
						Location: "https://github.com/lestrrat/go-saml",
					},
				},
			},
		},
	}

	xmlstr, err := md.Serialize()
	if !assert.NoError(t, err, "Serialize succeeds") {
		return
	}

	t.Logf("%s", xmlstr)
}
