package cose

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/notaryproject/notation-go-lib"
	"github.com/notaryproject/notation-go-lib/crypto/timestamp"
	artifactspec "github.com/oras-project/artifacts-spec/specs-go/v1"
	"github.com/veraison/go-cose"
)

// Signer signs artifacts and generates COSE signatures.
type Signer struct {
	// base is the base COSE signer
	base *cose.Signer

	// certChain contains the X.509 public key certificate or certificate chain
	// corresponding to the key used to generate the signature.
	certChain [][]byte
}

// NewSigner creates a signer with the recommended signing algorithm and a
// signing key bundled with a certificate chain.
func NewSigner(key crypto.PrivateKey, certChain []*x509.Certificate) (*Signer, error) {
	alg, err := AlgorithmFromKey(key)
	if err != nil {
		return nil, err
	}
	return NewSignerWithCertificateChain(alg, key, certChain)
}

// NewSignerWithCertificateChain creates a signer with the specified signing
// algorithm and a signing key bundled with a (partial) certificate chain.
func NewSignerWithCertificateChain(alg *cose.Algorithm, key crypto.PrivateKey, certChain []*x509.Certificate) (*Signer, error) {
	if alg == nil {
		return nil, errors.New("nil signing algorithm")
	}
	if key == nil {
		return nil, errors.New("nil signing key")
	}
	if len(certChain) == 0 {
		return nil, errors.New("missing signer certificate chain")
	}

	base, err := cose.NewSignerFromKey(alg, key)
	if err != nil {
		return nil, err
	}

	rawCerts := make([][]byte, 0, len(certChain))
	for _, cert := range certChain {
		rawCerts = append(rawCerts, cert.Raw)
	}
	return &Signer{
		base:      base,
		certChain: rawCerts,
	}, nil
}

// Sign signs the artifact described by its descriptor, and returns the
// signature.
func (s *Signer) Sign(ctx context.Context, desc notation.Descriptor, opts notation.SignOptions) ([]byte, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	// generate COSE signature
	msg := cose.NewSign1Message()
	payload, err := json.Marshal(desc)
	if err != nil {
		return nil, err
	}
	msg.Payload = payload
	msg.Headers.Protected = map[interface{}]interface{}{
		1:     s.base.GetAlg().Value,            // alg
		2:     []interface{}{3},                 // crit
		3:     artifactspec.MediaTypeDescriptor, // cty
		"iat": time.Now().Unix(),
	}
	if !opts.Expiry.IsZero() {
		msg.Headers.Protected["exp"] = opts.Expiry.Unix()
	}
	if err := msg.Sign(rand.Reader, nil, *s.base); err != nil {
		return nil, err
	}

	// generate unprotected header
	msg.Headers.Unprotected["x5c"] = s.certChain

	// timestamp signature
	if opts.TSA != nil {
		token, err := timestampSignature(ctx, msg.Signature, opts.TSA, opts.TSAVerifyOptions)
		if err != nil {
			return nil, fmt.Errorf("timestamp failed: %w", err)
		}
		msg.Headers.Unprotected["timestamp"] = token
	}

	// encode in CBOR
	return cbor.Marshal(msg)
}

// timestampSignature sends a request to the TSA for timestamping the signature.
func timestampSignature(ctx context.Context, sig []byte, tsa timestamp.Timestamper, opts x509.VerifyOptions) ([]byte, error) {
	// timestamp the signature
	req, err := timestamp.NewRequestFromBytes(sig)
	if err != nil {
		return nil, err
	}
	resp, err := tsa.Timestamp(ctx, req)
	if err != nil {
		return nil, err
	}
	if status := resp.Status; status.Status != 0 {
		return nil, fmt.Errorf("tsa: %d: %v", status.Status, status.StatusString)
	}
	tokenBytes := resp.TokenBytes()

	// verify the timestamp signature
	if _, err := verifyTimestamp(sig, tokenBytes, opts); err != nil {
		return nil, err
	}

	return tokenBytes, nil
}
