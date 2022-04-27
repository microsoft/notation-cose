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
func AlgorithmFromKey(key interface{}) (cose.Algorithm, error) {
	if k, ok := key.(interface {
		Public() crypto.PublicKey
	}); ok {
		key = k.Public()
	}

	switch key := key.(type) {
	case *rsa.PublicKey:
		switch key.Size() {
		case 256:
			return cose.AlgorithmPS256, nil
		case 384:
			return cose.AlgorithmPS384, nil
		case 512:
			return cose.AlgorithmPS512, nil
		default:
			return cose.AlgorithmPS256, nil
		}
	case *ecdsa.PublicKey:
		switch key.Curve.Params().BitSize {
		case 256:
			return cose.AlgorithmES256, nil
		case 384:
			return cose.AlgorithmES384, nil
		case 521:
			return cose.AlgorithmES512, nil
		default:
			return 0, errors.New("ecdsa key not supported")
		}
	}
	return 0, errors.New("key not supported")
}
