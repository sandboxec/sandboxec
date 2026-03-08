package cli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLoadConfig_DefaultsWhenMissing(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, "xdg"))
	t.Setenv("HOME", filepath.Join(tmp, "home"))

	cfg, err := loadConfig("")
	if err != nil {
		t.Fatalf("loadConfig default failed: %v", err)
	}

	if cfg.Mode != "run" {
		t.Fatalf("unexpected default mode: %q", cfg.Mode)
	}
	if cfg.BestEffort || cfg.UnsafeHostRuntime {
		t.Fatalf("unexpected default scalar config: %+v", cfg)
	}
	if len(cfg.FSRules) != 0 || len(cfg.NetworkRules) != 0 {
		t.Fatalf("expected empty default rules, got fs=%v net=%v", cfg.FSRules, cfg.NetworkRules)
	}
}

func TestLoadConfig_ExplicitYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sandboxec.yaml")
	content := strings.Join([]string{
		"mode: mcp",
		"best-effort: true",
		"unsafe-host-runtime: true",
		"fs:",
		"  - rx:/bin",
		"  - rw:/tmp",
		"net:",
		"  - c:443",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig explicit yaml failed: %v", err)
	}

	if cfg.Mode != "mcp" {
		t.Fatalf("unexpected mode: %q", cfg.Mode)
	}
	if !cfg.BestEffort || !cfg.UnsafeHostRuntime {
		t.Fatalf("unexpected scalar config: %+v", cfg)
	}
	if !reflect.DeepEqual(cfg.FSRules, []string{"rx:/bin", "rw:/tmp"}) {
		t.Fatalf("fs rules mismatch: %v", cfg.FSRules)
	}
	if !reflect.DeepEqual(cfg.NetworkRules, []string{"c:443"}) {
		t.Fatalf("network rules mismatch: %v", cfg.NetworkRules)
	}
}

func TestLoadConfig_ExplicitNonYAMLFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sandboxec.json")
	if err := os.WriteFile(path, []byte(`{"abi":6}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := loadConfig(path)
	if err == nil {
		t.Fatal("expected non-yaml config to fail")
	}
	if !strings.Contains(err.Error(), "must be YAML") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadConfig_AutoSearchXDG(t *testing.T) {
	tmp := t.TempDir()
	xdg := filepath.Join(tmp, "xdg")
	home := filepath.Join(tmp, "home")
	t.Setenv("XDG_CONFIG_HOME", xdg)
	t.Setenv("HOME", home)

	dir := filepath.Join(xdg, "sandboxec")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	path := filepath.Join(dir, "sandboxec.yaml")
	content := "fs:\n  - r:/etc\nnet:\n  - c:53\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := loadConfig("")
	if err != nil {
		t.Fatalf("loadConfig auto search failed: %v", err)
	}
	if !reflect.DeepEqual(cfg.FSRules, []string{"r:/etc"}) {
		t.Fatalf("fs rules mismatch: %v", cfg.FSRules)
	}
	if !reflect.DeepEqual(cfg.NetworkRules, []string{"c:53"}) {
		t.Fatalf("network rules mismatch: %v", cfg.NetworkRules)
	}
}

func TestLoadConfig_RemoteYAML(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/profiles/agents/codex.yaml" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("mode: mcp\nfs:\n  - rx:/usr\nnet:\n  - c:443\n"))
	}))
	t.Cleanup(server.Close)

	cfg, err := loadConfig(server.URL + "/profiles/agents/codex.yaml")
	if err != nil {
		t.Fatalf("loadConfig remote yaml failed: %v", err)
	}

	if cfg.Mode != "mcp" {
		t.Fatalf("unexpected mode: %q", cfg.Mode)
	}
	if !reflect.DeepEqual(cfg.FSRules, []string{"rx:/usr"}) {
		t.Fatalf("fs rules mismatch: %v", cfg.FSRules)
	}
	if !reflect.DeepEqual(cfg.NetworkRules, []string{"c:443"}) {
		t.Fatalf("network rules mismatch: %v", cfg.NetworkRules)
	}
}
