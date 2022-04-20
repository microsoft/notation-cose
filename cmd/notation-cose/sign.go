package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"os"
	"strings"

	"github.com/microsoft/notation-cose/pkg/cose"
	"github.com/microsoft/notation-cose/pkg/protocol"
	"github.com/notaryproject/notation-go-lib"
	"github.com/notaryproject/notation-go-lib/crypto/cryptoutil"
	"github.com/notaryproject/notation-go-lib/crypto/timestamp"
	"github.com/urfave/cli/v2"
)

var signCommand = &cli.Command{
	Name:      "sign",
	Usage:     "Sign artifacts in COSE",
	ArgsUsage: "<reference>",
	Action:    runSign,
}

func runSign(ctx *cli.Context) error {
	// initialize
	args := ctx.Args()
	if args.Len() != 1 {
		return errors.New("missing request")
	}

	// parse request
	var req protocol.SignRequest
	if err := json.Unmarshal([]byte(args.Get(0)), &req); err != nil {
		return err
	}

	// sign artifact
	signer, opts, err := getSignerWithOptions(req.KMSProfile.ID, req.SignOptions)
	if err != nil {
		return err
	}
	sig, err := signer.Sign(ctx.Context, req.Descriptor, opts)
	if err != nil {
		return err
	}

	// write response
	_, err = os.Stdout.Write(sig)
	return err
}

func getSignerWithOptions(keyInfo string, opts notation.SignOptions) (notation.Signer, notation.SignOptions, error) {
	// parse options
	items := strings.SplitN(keyInfo, ":", 3)
	if len(items) < 2 {
		return nil, opts, errors.New("missing signing key pair")
	}
	keyPath := items[0]
	certPath := items[1]
	var tsEndpoint string
	if len(items) > 2 {
		tsEndpoint = items[2]
	}

	// read key / cert pair
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, opts, err
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, opts, err
	}
	keyPair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, opts, err
	}

	// parse cert
	certs, err := cryptoutil.ParseCertificatePEM(certPEM)
	if err != nil {
		return nil, opts, err
	}

	// construct signer
	signer, err := cose.NewSigner(keyPair.PrivateKey, certs)
	if err != nil {
		return nil, opts, err
	}

	// hack: refine options
	// notation#feat-kv-extensibility uses an older version of notation-go-lib,
	// which does not support TSA in options.
	if tsEndpoint != "" {
		tsa, err := timestamp.NewHTTPTimestamper(nil, tsEndpoint)
		if err != nil {
			return nil, opts, err
		}
		opts.TSA = tsa
	}
	return signer, opts, nil
}
