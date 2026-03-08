package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

type appConfig struct {
	Mode              string
	BestEffort        bool
	UnsafeHostRuntime bool
	FSRules           []string
	NetworkRules      []string
}

func loadConfig(configPath string) (appConfig, error) {
	cfg := appConfig{}
	v := viper.New()
	v.SetDefault("mode", "run")
	v.SetDefault("best-effort", false)
	v.SetDefault("unsafe-host-runtime", false)
	v.SetDefault("fs", []string{})
	v.SetDefault("net", []string{})
	loadedFromReader := false

	if configPath != "" {
		ext := configPathExt(configPath)
		if ext != ".yaml" && ext != ".yml" {
			return cfg, fmt.Errorf("config file must be YAML (.yaml/.yml): %s", configPath)
		}

		if isRemoteConfigPath(configPath) {
			if err := readRemoteYAMLConfig(v, configPath); err != nil {
				return cfg, err
			}
			loadedFromReader = true
		} else {
			v.SetConfigFile(configPath)
		}
	} else {
		v.SetConfigName("sandboxec")
		v.SetConfigType("yaml")
		for _, p := range configSearchPaths() {
			v.AddConfigPath(p)
		}
	}

	if !loadedFromReader {
		if err := v.ReadInConfig(); err != nil {
			var notFoundError viper.ConfigFileNotFoundError
			if !errors.As(err, &notFoundError) {
				return cfg, fmt.Errorf("read config: %w", err)
			}
		}
	}

	cfg.Mode = strings.ToLower(strings.TrimSpace(v.GetString("mode")))
	if cfg.Mode == "" {
		cfg.Mode = "run"
	}
	cfg.BestEffort = v.GetBool("best-effort")
	cfg.UnsafeHostRuntime = v.GetBool("unsafe-host-runtime")
	cfg.FSRules = append([]string(nil), v.GetStringSlice("fs")...)
	cfg.NetworkRules = append([]string(nil), v.GetStringSlice("net")...)

	return cfg, nil
}

func isRemoteConfigPath(configPath string) bool {
	u, err := url.Parse(configPath)
	if err != nil {
		return false
	}

	scheme := strings.ToLower(u.Scheme)

	return scheme == "http" || scheme == "https"
}

func configPathExt(configPath string) string {
	if !isRemoteConfigPath(configPath) {
		return strings.ToLower(filepath.Ext(configPath))
	}

	u, err := url.Parse(configPath)
	if err != nil {
		return ""
	}

	return strings.ToLower(filepath.Ext(u.Path))
}

func readRemoteYAMLConfig(v *viper.Viper, configURL string) error {
	resp, err := http.Get(configURL)
	if err != nil {
		return fmt.Errorf("read config: fetch %s: %w", configURL, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("read config: fetch %s: %s", configURL, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read config: fetch %s: %w", configURL, err)
	}

	v.SetConfigType("yaml")
	if err := v.ReadConfig(bytes.NewReader(body)); err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	return nil
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
