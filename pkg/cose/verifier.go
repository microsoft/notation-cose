package cose

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/notaryproject/notation-go-lib"
	"github.com/notaryproject/notation-go-lib/crypto/timestamp"
	"github.com/veraison/go-cose"
)

// maxTimestampAccuracy specifies the max acceptable accuracy for timestamp.
const maxTimestampAccuracy = time.Minute

// Verifier verifies artifacts against COSE signatures.
type Verifier struct {
	// ResolveAlgorithm resolves the signing algorithm used to verify the
	// signature according to the public key in the certificate chain.
	// If not present, `AlgorithmFromKey` will be used to pick up a recommended
	// algorithm.
	ResolveAlgorithm func(interface{}) (*cose.Algorithm, error)

	// EnforceExpiryValidation enforces the verifier to verify the timestamp
	// signature even if the certificate is valid.
	// Reference: https://github.com/notaryproject/notaryproject/discussions/98
	EnforceExpiryValidation bool

	// VerifyOptions is the verify option to verify the certificate of the
	// incoming signature.
	// The `Intermediates` in the verify options will be ignored and
	// re-contrusted using the certificates in the incoming signature.
	// An empty list of `KeyUsages` in the verify options implies
	// `ExtKeyUsageCodeSigning`.
	VerifyOptions x509.VerifyOptions

	// TSAVerifyOptions is the verify option to verify the fetched timestamp
	// signature.
	// The `Intermediates` in the verify options will be ignored and
	// re-contrusted using the certificates in the fetched timestamp signature.
	// An empty list of `KeyUsages` in the verify options implies
	// `ExtKeyUsageTimeStamping`.
	TSAVerifyOptions x509.VerifyOptions
}

// NewVerifier creates a verifier.
// Callers may be interested in options in the public field of the Verifier,
// especially VerifyOptions for setting up trusted certificates.
func NewVerifier() *Verifier {
	return &Verifier{}
}

// Verify verifies the signature and returns the verified descriptor and
// metadata of the signed artifact.
func (v *Verifier) Verify(ctx context.Context, signature []byte, opts notation.VerifyOptions) (notation.Descriptor, error) {
	// unpack envelope
	msg := &cose.Sign1Message{}
	if err := cbor.Unmarshal(signature, msg); err != nil {
		return notation.Descriptor{}, err
	}

	// verify signing identity
	headers := msg.Headers
	if headers == nil {
		return notation.Descriptor{}, errors.New("missing signature headers")
	}
	verifier, err := v.verifySigner(headers.Unprotected, msg.Signature)
	if err != nil {
		return notation.Descriptor{}, err
	}

	// verify COSE signature
	if err := v.verifyCOSE(verifier, msg); err != nil {
		return notation.Descriptor{}, err
	}

	var desc notation.Descriptor
	if err := cbor.Unmarshal(msg.Payload, desc); err != nil {
		return notation.Descriptor{}, err
	}
	return desc, nil
}

// verifySigner verifies the signing identity and returns the verifier for
//signature verification.
func (v *Verifier) verifySigner(header map[interface{}]interface{}, sig []byte) (*cose.Verifier, error) {
	certChain, _ := header["x5c"].([][]byte)
	if len(certChain) == 0 {
		return nil, errors.New("signer certificates not found")
	}
	timestamp, _ := header["timestamp"].([]byte)
	return v.verifySignerFromCertChain(certChain, timestamp, sig)
}

// verifySignerFromCertChain verifies the signing identity from the provided
// certificate chain and returns the verifier. The first certificate of the
// certificate chain contains the key, which used to sign the artifact.
func (v *Verifier) verifySignerFromCertChain(certChain [][]byte, timeStampToken, sig []byte) (*cose.Verifier, error) {
	// prepare for certificate verification
	certs := make([]*x509.Certificate, 0, len(certChain))
	for _, certBytes := range certChain {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	verifyOpts := v.VerifyOptions
	verifyOpts.Intermediates = intermediates
	if len(verifyOpts.KeyUsages) == 0 {
		verifyOpts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	}

	// verify the signing certificate
	checkTimestamp := v.EnforceExpiryValidation
	cert := certs[0]
	if _, err := cert.Verify(verifyOpts); err != nil {
		if certErr, ok := err.(x509.CertificateInvalidError); !ok || certErr.Reason != x509.Expired {
			return nil, err
		}

		// verification failed due to expired certificate
		checkTimestamp = true
	}
	if checkTimestamp {
		stampedTime, err := v.verifyTimestamp(timeStampToken, sig)
		if err != nil {
			return nil, err
		}
		verifyOpts.CurrentTime = stampedTime
		if _, err := cert.Verify(verifyOpts); err != nil {
			return nil, err
		}
	}

	// resolve signing method
	resolveAlgorithm := v.ResolveAlgorithm
	if resolveAlgorithm == nil {
		resolveAlgorithm = AlgorithmFromKey
	}
	alg, err := resolveAlgorithm(cert.PublicKey)
	if err != nil {
		return nil, err
	}

	return &cose.Verifier{
		PublicKey: cert.PublicKey,
		Alg:       alg,
	}, nil
}

// verifyTimestamp verifies the timestamp token and returns stamped time.
func (v *Verifier) verifyTimestamp(tokenBytes, sig []byte) (time.Time, error) {
	return verifyTimestamp(sig, tokenBytes, v.TSAVerifyOptions)
}

// verifyCOSE verifies the COSE signature against the specified verifier.
func (v *Verifier) verifyCOSE(verifier *cose.Verifier, msg *cose.Sign1Message) error {
	// verify signature
	header := msg.Headers.Protected
	if alg := header[1]; alg != verifier.Alg.Value {
		return fmt.Errorf("unexpected signing algorithm: %v: require %v %s", alg, verifier.Alg.Value, verifier.Alg.Name)
	}
	if err := msg.Verify(nil, *verifier); err != nil {
		return err
	}

	// ensure required attributes exist.
	if _, ok := header["iat"].(time.Time); !ok {
		return errors.New("missing iat")
	}
	return nil
}

// verifyTimestamp verifies the timestamp token and returns stamped time.
func verifyTimestamp(contentBytes, tokenBytes []byte, opts x509.VerifyOptions) (time.Time, error) {
	token, err := timestamp.ParseSignedToken(tokenBytes)
	if err != nil {
		return time.Time{}, err
	}
	if _, err := token.Verify(opts); err != nil {
		return time.Time{}, err
	}
	info, err := token.Info()
	if err != nil {
		return time.Time{}, err
	}
	if err := info.Verify(contentBytes); err != nil {
		return time.Time{}, err
	}
	stampedTime, accuracy := info.Timestamp()
	if accuracy > maxTimestampAccuracy {
		return time.Time{}, fmt.Errorf("max timestamp accuracy exceeded: %v", accuracy)
	}
	return stampedTime, nil
}
