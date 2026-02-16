package cli

import (
	"errors"
	"strings"
	"testing"

	"go.dw1.io/sandboxec/internal/mcp"
)

func TestRun_ModeValidation(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())

	_, err := Run([]string{"--mode", "invalid"})
	if err == nil {
		t.Fatal("expected invalid mode error")
	}
	if !strings.Contains(err.Error(), "invalid mode") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRun_ModeMCPWithoutCommand(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	prev := runMCPServer
	t.Cleanup(func() {
		runMCPServer = prev
	})

	called := false
	runMCPServer = func(cfg mcp.Config) error {
		called = true
		if len(cfg.Options) == 0 {
			t.Fatal("expected derived exec options for mcp")
		}
		return nil
	}

	exitCode, err := Run([]string{"--mode", "mcp", "--fs", "rx:/"})
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatal("expected mcp server to be started")
	}
}

func TestRun_ModeMCPUnsafeHostRuntimeOption(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	prev := runMCPServer
	t.Cleanup(func() {
		runMCPServer = prev
	})

	called := false
	runMCPServer = func(cfg mcp.Config) error {
		called = true
		if len(cfg.Options) == 0 {
			t.Fatal("expected unsafe-host-runtime to produce exec option")
		}
		return nil
	}

	exitCode, err := Run([]string{"--mode", "mcp", "--unsafe-host-runtime"})
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatal("expected mcp server to be started")
	}
}

func TestRun_ModeMCPRejectsCommandArgs(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())

	exitCode, err := Run([]string{"--mode", "mcp", "echo", "hello"})
	if exitCode != 1 {
		t.Fatalf("exitCode = %d, want 1", exitCode)
	}
	if err == nil {
		t.Fatal("expected mcp argument rejection error")
	}
	if !strings.Contains(err.Error(), "does not accept command arguments") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRun_ModeMCPPropagatesServerError(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	prev := runMCPServer
	t.Cleanup(func() {
		runMCPServer = prev
	})

	runMCPServer = func(_ mcp.Config) error {
		return errors.New("mcp boom")
	}

	exitCode, err := Run([]string{"--mode", "mcp"})
	if exitCode != 1 {
		t.Fatalf("exitCode = %d, want 1", exitCode)
	}
	if err == nil {
		t.Fatal("expected mcp server error")
	}
	if !strings.Contains(err.Error(), "mcp boom") {
		t.Fatalf("unexpected error: %v", err)
	}
}
