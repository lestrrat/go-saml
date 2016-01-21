package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"io"
	"sync"

	"github.com/lestrrat/go-libxml2/parser"
	"github.com/lestrrat/go-pdebug"
	"github.com/lestrrat/go-xmlsec/crypto"
	"github.com/lestrrat/go-xmlsec/dsig"
)

var b64enc = base64.StdEncoding

var flateWriterPool = sync.Pool{
	New: allocFlateWriter,
}

// wasteful, but oh well
var emptyBuffer = &bytes.Buffer{}

func allocFlateWriter() interface{} {
	// flate.NewWriter (as of this writing) only returns an error
	// if the second argument is invalid. As we are using a standard
	// compression level here, there is no way this can err
	w, _ := flate.NewWriter(emptyBuffer, flate.DefaultCompression)
	return w
}
func getFlateWriter() *flate.Writer {
	return flateWriterPool.Get().(*flate.Writer)
}
func releaseFlateWriter(r *flate.Writer) {
	r.Reset(emptyBuffer) // release the previous io.Writer
	flateWriterPool.Put(r)
}

type serializer interface {
	Serialize() (string, error)
}

func encode(s serializer, key *crypto.Key, compress bool) ([]byte, error) {
	xmlstr, err := s.Serialize()
	if err != nil {
		return nil, err
	}
	if pdebug.Enabled {
		pdebug.Printf("Generated %d bytes of XML", len(xmlstr))
	}

	if key != nil {
		p := parser.New(parser.XMLParseDTDLoad | parser.XMLParseDTDAttr | parser.XMLParseNoEnt)
		doc, err := p.ParseString(xmlstr)
		if err != nil {
			return nil, err
		}

		root, err := doc.DocumentElement()
		if err != nil {
			return nil, err
		}

		// Create a new signature section.
		sig, err := dsig.NewSignature(root, dsig.ExclC14N, dsig.RsaSha1, "")
		if err := sig.AddReference(dsig.Sha1, "", "", ""); err != nil {
			return nil, err
		}

		if err := sig.AddTransform(dsig.Enveloped); err != nil {
			return nil, err
		}

		if err := sig.AddKeyValue(); err != nil {
			return nil, err
		}

		// If the key is setup using X509, add that node
		if key.HasX509() == nil {
			if err := sig.AddX509Data(); err != nil {
				return nil, err
			}
		}

		if pdebug.Enabled {
			pdebug.Printf("Signing using key %p", key)
		}
		if err := sig.Sign(key); err != nil {
			return nil, err
		}

		xmlstr = doc.Dump(false)
		if err != nil {
			return nil, err
		}
	}

	if !compress {
		return []byte(xmlstr), nil
	}

	buf := bytes.Buffer{}

	w := getFlateWriter()
	defer releaseFlateWriter(w)

	w.Reset(&buf)
	if _, err := io.WriteString(w, xmlstr); err != nil {
		return nil, err
	}

	if err := w.Close(); err != nil {
		return nil, err
	}
	if pdebug.Enabled {
		pdebug.Printf("Compressed to %d bytes", buf.Len())
	}

	ret := make([]byte, b64enc.EncodedLen(buf.Len()))
	b64enc.Encode(ret, buf.Bytes())
	if pdebug.Enabled {
		pdebug.Printf("Encoded into %d bytes of base64", len(ret))
	}

	return ret, nil
}
