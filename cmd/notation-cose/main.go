package main

import (
	"os"

	"github.com/shizhMSFT/notation-cose/internal/version"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:    "notation-cose",
		Usage:   "COSE Plugin for Notation",
		Version: version.GetVersion(),
		Commands: []*cli.Command{
			signCommand,
			verifyCommand,
		},
	}
	if err := app.Run(os.Args); err != nil {
		os.Stderr.WriteString(err.Error())
	}
}
