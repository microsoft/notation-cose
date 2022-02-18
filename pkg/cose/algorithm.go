package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"

	"github.com/veraison/go-cose"
)

// AlgorithmFromKey picks up a recommended algorithm for private and public
// keys.
// Reference: RFC 8152 8 Signature Algorithms.
func AlgorithmFromKey(key interface{}) (*cose.Algorithm, error) {
	if k, ok := key.(interface {
		Public() crypto.PublicKey
	}); ok {
		key = k.Public()
	}

	switch key := key.(type) {
	case *rsa.PublicKey:
		// use PS256 for all key sizes since PS256 is the only supported
		// algorithm by go-cose.
		return cose.PS256, nil
	case *ecdsa.PublicKey:
		switch key.Curve.Params().BitSize {
		case 256:
			return cose.ES256, nil
		case 384:
			return cose.ES384, nil
		case 521:
			return cose.ES512, nil
		default:
			return nil, errors.New("ecdsa key not supported")
		}
	}
	return nil, errors.New("key not supported")
}
