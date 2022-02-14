package main

import (
	"encoding/json"
	"errors"

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

	// write response
	return nil
}
