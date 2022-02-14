package main

import (
	"encoding/json"
	"errors"

	"github.com/shizhMSFT/notation-cose/pkg/protocol"
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

	// write response
	return nil
}
