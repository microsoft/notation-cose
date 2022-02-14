package cose

import (
	"github.com/fxamacker/cbor/v2"
	"github.com/notaryproject/notation-go-lib"
	"github.com/opencontainers/go-digest"
)

var cborEncMode cbor.EncMode

func init() {
	opts := cbor.CanonicalEncOptions()

	var err error
	cborEncMode, err = opts.EncMode()
	if err != nil {
		panic(err)
	}
}

// MediaTypeNotationPayload describes the media type of the payload of notation
// signature.
const MediaTypeNotationPayload = "application/vnd.cncf.notary.v2.cose.v1"

// Descriptor describes the content signed or to be signed, and used as the
// signing payload.
type Descriptor struct {
	// MediaType is the media type of the targeted content.
	MediaType string `cbor:"mediaType"`

	// Digest is the digest of the targeted content.
	Digest digest.Digest `cbor:"digest"`

	// Size specifies the size in bytes of the blob.
	Size int64 `cbor:"size"`

	// Annotations contains optional user defined attributes.
	Annotations map[string]string `cbor:"annotations,omitempty"`
}

func generatePayload(desc notation.Descriptor) ([]byte, error) {
	return cborEncMode.Marshal(Descriptor(desc))
}
