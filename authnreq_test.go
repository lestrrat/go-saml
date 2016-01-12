package saml

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthnRequestDecode(t *testing.T) {
	const encoded = `fVLJTsMwEL0j8Q+W79mK2KwmVQEhKrFENHDg5iQTx8Wxg8dp4e9xUxBwoDfr+fkt45nO3jtF1mBRGp3SJIwpAV2ZWmqR0qfiOjijs+zwYIq8Uz2bD67Vj/A2ADriX2pk40VKB6uZ4SiRad4BMlex5fzulk3CmPXWOFMZRcniKqWm4bxswPuZUpVi1b42r7wRUgkhoF+Jtu51X5qWkufvWJNtrAXiAAuNjmvnoTg5CeIkiE+L+IhNzll8/EJJ/uV0IfWuwb5Y5Y6E7KYo8iB/WBajwFrWYO89O6XCGKEgrEy3tc85olx7uOEKgZI5IljnA14ajUMHdgl2LSt4erxNaetcjyyKNptN+CMT8UiEbb09h6s+4hXSbBwtG9vZXzPdn51/e9PsP/Vp9Es4+/rAba/FVW6UrD7IXCmzubTAnS/l7OA7XRvbcfe/dxImIyLroBmpbNDYQyUbCTUlUbZz/bspfn8+AQ==`

	req, err := DecodeAuthnRequestString(encoded, false)
	if !assert.NoError(t, err, "DecodeAuthnRequestString succeeds") {
		return
	}

	t.Logf("%#v", req)
}