package mcp

import (
	"context"
	"strings"
	"testing"

	"go.dw1.io/x/exp/sandboxec"
	"go.dw1.io/x/exp/sandboxec/access"
)

func TestRunExec_Success(t *testing.T) {
	out, err := run(context.Background(), input{
		Command: "/bin/echo",
		Args:    []string{"hello"},
	}, []sandboxec.Option{sandboxec.WithBestEffort(), sandboxec.WithFSRule("/", access.FS_READ_EXEC)})
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	if out.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0", out.ExitCode)
	}
	if strings.TrimSpace(out.Stdout) != "hello" {
		t.Fatalf("stdout = %q, want hello", out.Stdout)
	}
}

func TestRunExec_NonZeroExit(t *testing.T) {
	out, err := run(context.Background(), input{
		Command: "/bin/sh",
		Args:    []string{"-c", "echo boom 1>&2; exit 7"},
	}, []sandboxec.Option{sandboxec.WithBestEffort(), sandboxec.WithFSRule("/", access.FS_READ_EXEC)})
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	if out.ExitCode != 7 {
		t.Fatalf("exit code = %d, want 7", out.ExitCode)
	}
	if !strings.Contains(out.Stderr, "boom") {
		t.Fatalf("stderr = %q, want contains boom", out.Stderr)
	}
}

func TestRunExec_EmptyCommand(t *testing.T) {
	_, err := run(context.Background(), input{}, nil)
	if err == nil {
		t.Fatal("expected error for empty command")
	}
	if !strings.Contains(err.Error(), "command is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}
