package md_test

import (
	"crypto/dsa"
	"crypto/rand"
	"testing"

	"github.com/lestrrat/go-saml"
	"github.com/lestrrat/go-saml/binding"
	"github.com/lestrrat/go-saml/md"
	"github.com/lestrrat/go-saml/nameid"
	"github.com/lestrrat/go-xmlsec/key"
	"github.com/stretchr/testify/assert"
)

func TestMetadata(t *testing.T) {
	params := dsa.Parameters{}
	if !assert.NoError(t, dsa.GenerateParameters(&params, rand.Reader, dsa.L2048N256), "Parameter generation succeeds") {
		return
	}

	privkey := dsa.PrivateKey{
		PublicKey: dsa.PublicKey{
			Parameters: params,
		},
	}

	if !assert.NoError(t, dsa.GenerateKey(&privkey, rand.Reader), "GenerateKey succeeds") {
		return
	}

	md := md.Metadata{
		EntityDescriptors: []md.EntityDescriptor{
			md.IDPDescriptor{
				ContactPerson: &md.ContactPerson{
					Type:            "technical",
					GivenName:       "Daisuke",
					SurName:         "Maki",
					EmailAddress:    "lestrrat@foo.bar.baz",
					TelephoneNumber: "000-1234-5678",
				},
				KeyDescriptor: &md.KeyDescriptor{
					Key: key.NewDSA(&privkey.PublicKey),
				},
				RoleDescriptor: md.RoleDescriptor{
					CommonDescriptor: md.CommonDescriptor{
						ID: "https://github.com/lestrrat/go-saml",
					},
				},
				SSODescriptor: md.SSODescriptor{
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
