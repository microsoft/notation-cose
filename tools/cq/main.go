package main

import (
	"os"

	"github.com/microsoft/notation-cose/internal/version"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:    "cq",
		Usage:   "Command-line CBOR processor",
		Version: version.GetVersion(),
		Action: func(c *cli.Context) error {
			return print(0, os.Stdin, 0, "")
		},
	}
	if err := app.Run(os.Args); err != nil {
		os.Stderr.WriteString(err.Error())
	}
}
