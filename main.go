package main

import (
	"fmt"
	"io"
	"os"

	"go.sandbox.ec/sandboxec/internal/cli"
)

var (
	runCLI             = cli.Run
	exitProc           = os.Exit
	stderr   io.Writer = os.Stderr
)

func main() {
	exitCode, err := runCLI(os.Args[1:])
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "sandboxec:", err)
		exitProc(1)
	}

	if exitCode != 0 {
		exitProc(exitCode)
	}
}
