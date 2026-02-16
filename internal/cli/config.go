package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

type appConfig struct {
	Mode              string
	ABI               int
	BestEffort        bool
	IgnoreIfMissing   bool
	RestrictScoped    bool
	UnsafeHostRuntime bool
	FSRules           []string
	NetworkRules      []string
}

func loadConfig(configPath string) (appConfig, error) {
	cfg := appConfig{}
	v := viper.New()
	v.SetDefault("mode", "run")
	v.SetDefault("abi", 0)
	v.SetDefault("best-effort", false)
	v.SetDefault("ignore-if-missing", false)
	v.SetDefault("restrict-scoped", false)
	v.SetDefault("unsafe-host-runtime", false)
	v.SetDefault("fs", []string{})
	v.SetDefault("net", []string{})

	if configPath != "" {
		ext := strings.ToLower(filepath.Ext(configPath))
		if ext != ".yaml" && ext != ".yml" {
			return cfg, fmt.Errorf("config file must be YAML (.yaml/.yml): %s", configPath)
		}
		v.SetConfigFile(configPath)
	} else {
		v.SetConfigName("sandboxec")
		v.SetConfigType("yaml")
		for _, p := range configSearchPaths() {
			v.AddConfigPath(p)
		}
	}

	if err := v.ReadInConfig(); err != nil {
		var notFoundError viper.ConfigFileNotFoundError
		if !errors.As(err, &notFoundError) {
			return cfg, fmt.Errorf("read config: %w", err)
		}
	}

	cfg.Mode = strings.ToLower(strings.TrimSpace(v.GetString("mode")))
	if cfg.Mode == "" {
		cfg.Mode = "run"
	}
	cfg.ABI = v.GetInt("abi")
	cfg.BestEffort = v.GetBool("best-effort")
	cfg.IgnoreIfMissing = v.GetBool("ignore-if-missing")
	cfg.RestrictScoped = v.GetBool("restrict-scoped")
	cfg.UnsafeHostRuntime = v.GetBool("unsafe-host-runtime")
	cfg.FSRules = append([]string(nil), v.GetStringSlice("fs")...)
	cfg.NetworkRules = append([]string(nil), v.GetStringSlice("net")...)

	return cfg, nil
}

func configSearchPaths() []string {
	paths := make([]string, 0, 5)
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		paths = append(paths, filepath.Join(xdg, "sandboxec"))
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		paths = append(paths, filepath.Join(home, ".config", "sandboxec"))
	}
	paths = append(paths, "/etc/sandboxec")
	return paths
}
