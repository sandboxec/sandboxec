package cli

import (
	"errors"
	"strings"
	"testing"

	"go.sandbox.ec/sandboxec/internal/mcp"
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

func TestNamedConfigURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantURL string
		wantErr bool
	}{
		{
			name:    "normal",
			input:   "agents/codex",
			wantURL: "https://github.com/sandboxec/profiles/raw/refs/heads/based/agents/codex.yaml",
		},
		{
			name:    "trim-leading-slash-and-extension",
			input:   "/agents/codex.yaml",
			wantURL: "https://github.com/sandboxec/profiles/raw/refs/heads/based/agents/codex.yaml",
		},
		{
			name:    "trim-yml-extension",
			input:   "agents/codex.yml",
			wantURL: "https://github.com/sandboxec/profiles/raw/refs/heads/based/agents/codex.yaml",
		},
		{
			name:    "empty-fails",
			input:   "   ",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := namedConfigURL(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.wantURL {
				t.Fatalf("url = %q, want %q", got, tt.wantURL)
			}
		})
	}
}

func TestRun_ConfigAndNamedConfigMutuallyExclusive(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())

	exitCode, err := Run([]string{"--config", "a.yaml", "--named-config", "agents/codex", "--mode", "mcp"})
	if exitCode != 1 {
		t.Fatalf("exitCode = %d, want 1", exitCode)
	}
	if err == nil {
		t.Fatal("expected conflict error")
	}
	if !strings.Contains(err.Error(), "cannot be used together") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildOptions_PlatformSettings(t *testing.T) {
	tests := []struct {
		name        string
		goos        string
		cfg         appConfig
		wantOpts    int
		wantWarning string
		wantErr     string
	}{
		{
			name:     "linux-applies-landlock-settings",
			goos:     "linux",
			cfg:      appConfig{ABI: 6, RestrictScoped: true},
			wantOpts: 3,
		},
		{
			name: "darwin-defaults",
			goos: "darwin",
		},
		{
			name:        "darwin-warns-on-abi",
			goos:        "darwin",
			cfg:         appConfig{ABI: 6},
			wantWarning: "abi 6 is ignored on darwin",
		},
		{
			name:    "darwin-rejects-restrict-scoped",
			goos:    "darwin",
			cfg:     appConfig{RestrictScoped: true},
			wantErr: "restrict-scoped is unsupported on darwin",
		},
		{
			name:        "warns-on-ignore-if-missing-false",
			goos:        "linux",
			cfg:         appConfig{FailIfMissing: true},
			wantOpts:    1,
			wantWarning: "ignore-if-missing: false is ignored",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, warnings, err := buildOptions(tt.cfg, tt.goos, nil, nil)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(opts) != tt.wantOpts {
				t.Fatalf("len(opts) = %d, want %d", len(opts), tt.wantOpts)
			}
			if tt.wantWarning == "" {
				if len(warnings) != 0 {
					t.Fatalf("unexpected warnings: %q", warnings)
				}
				return
			}
			if len(warnings) != 1 || !strings.Contains(warnings[0], tt.wantWarning) {
				t.Fatalf("warnings = %q, want one containing %q", warnings, tt.wantWarning)
			}
		})
	}
}
