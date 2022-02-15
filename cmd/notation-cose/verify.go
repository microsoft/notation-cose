package main

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"

	"github.com/notaryproject/notation-go-lib"
	"github.com/notaryproject/notation-go-lib/crypto/cryptoutil"
	"github.com/shizhMSFT/notation-cose/pkg/cose"
	"github.com/shizhMSFT/notation-cose/pkg/protocol"
	"github.com/urfave/cli/v2"
)

var verifyCommand = &cli.Command{
	Name:      "verify",
	Usage:     "Verify OCI artifacts against COSE signatures",
	ArgsUsage: "<reference>",
	Action:    runVerify,
}

func runVerify(ctx *cli.Context) error {
	// initialize
	args := ctx.Args()
	if args.Len() != 1 {
		return errors.New("missing request")
	}

	// parse request
	var req protocol.VerifyRequest
	if err := json.Unmarshal([]byte(args.Get(0)), &req); err != nil {
		return err
	}

	// verify signature
	verifier, err := getVerifier(req.KMSProfile.ID)
	if err != nil {
		return err
	}
	desc, err := verifier.Verify(ctx.Context, req.Signature, req.VerifyOptions)
	if err != nil {
		return err
	}
	out, err := json.Marshal(desc)
	if err != nil {
		return err
	}

	// write response
	_, err = os.Stdout.Write(out)
	return err
}

func getVerifier(certPath string) (notation.Verifier, error) {
	bundledCerts, err := cryptoutil.ReadCertificateFile(certPath)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	for _, cert := range bundledCerts {
		roots.AddCert(cert)
	}
	verifier := cose.NewVerifier()
	verifier.VerifyOptions.Roots = roots
	return verifier, nil
}
