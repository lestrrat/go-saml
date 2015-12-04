package metadata_test

import (
	"testing"

	"github.com/lestrrat/go-saml"
	"github.com/lestrrat/go-saml/binding"
	"github.com/lestrrat/go-saml/metadata"
	"github.com/lestrrat/go-saml/nameid"
	"github.com/stretchr/testify/assert"
)

func TestMetadata(t *testing.T) {
	md := metadata.Metadata{
		EntityDescriptors: []metadata.EntityDescriptor{
			metadata.IDPDescriptor{
				CommonDescriptor: metadata.CommonDescriptor{
					ID: "https://github.com/lestrrat/go-saml",
				},
				SSODescriptor: metadata.SSODescriptor{
					SingleLogoutService: []saml.Endpoint{
						saml.Endpoint{
							ProtocolBinding: binding.HTTPRedirect,
							Location:        `https://github.com/lestrrat/go-saml/dummy/idp/logout`,
						},
					},
					NameIDFormat: nameid.Transient,
				},
				SingleSignOnService: []saml.Endpoint{
					saml.Endpoint{
						ProtocolBinding: binding.HTTPRedirect,
						Location:        `https://github.com/lestrrat/go-saml/dummy/idp/sso`,
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
