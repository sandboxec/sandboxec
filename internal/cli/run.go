package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"

	"github.com/spf13/pflag"
	"go.dw1.io/x/exp/sandboxec"
	"go.sandbox.ec/sandboxec/internal/mcp"
)

const namedConfigBaseURL = "https://github.com/sandboxec/profiles/raw/refs/heads/based/"

// Run executes the sandboxec CLI workflow.
// It returns a process exit code for wrapped commands and an error for CLI/runtime failures.
func Run(argv []string) (int, error) {
	var configPath string
	var namedConfig string
	mode := modeValue{value: "run"}
	var fsFlag fsRulesValue
	var networkFlag networkRulesValue

	flagSet := pflag.NewFlagSet("sandboxec", pflag.ContinueOnError)
	flagSet.SortFlags = false
	flagSet.SetOutput(os.Stderr)
	flagSet.Usage = func() {
		_, _ = fmt.Fprintf(flagSet.Output(), "%s - %s\n\n", AppName, AppDescription)
		_, _ = fmt.Fprintf(flagSet.Output(), "Author: %s\n\n", AppAuthor)
		_, _ = fmt.Fprint(flagSet.Output(), AppUsage)
		_, _ = fmt.Fprintln(flagSet.Output())
		_, _ = fmt.Fprintln(flagSet.Output(), "Options:")
		flagSet.PrintDefaults()
		_, _ = fmt.Fprintln(flagSet.Output())
		_, _ = fmt.Fprint(flagSet.Output(), AppRights)
		_, _ = fmt.Fprintln(flagSet.Output())
		_, _ = fmt.Fprint(flagSet.Output(), AppExamples)
	}

	flagSet.StringVarP(&configPath, "config", "c", "", "Path to YAML config file")
	flagSet.StringVarP(&namedConfig, "named-config", "C", "", "Named config profile (mapped to sandboxec/profiles repository)")
	flagSet.VarP(&fsFlag, "fs", "f", "Filesystem rule (repeatable)")
	flagSet.VarP(&networkFlag, "net", "n", "Network rule (repeatable)")
	flagSet.Int("abi", 0, "Landlock ABI version (1-7, 0 means default)")
	flagSet.Bool("best-effort", false, "Ignore unsupported sandbox feature availability")
	flagSet.Bool("restrict-scoped", false, "Enable scoped IPC restrictions (ABI v6+)")
	flagSet.Bool("unsafe-host-runtime", false, "Allow read_exec rights for host runtime paths")
	flagSet.VarP(&mode, "mode", "m", "Execution mode (run|mcp)")
	flagSet.BoolP("version", "V", false, "Show app version")
	flagSet.BoolP("help", "h", false, "Show help")
	if runtime.GOOS != "linux" {
		// Landlock-only flags still parse, so buildOptions can report them.
		_ = flagSet.MarkHidden("abi")
		_ = flagSet.MarkHidden("restrict-scoped")
	}

	if err := flagSet.Parse(argv); err != nil {
		return 1, err
	}

	help, _ := flagSet.GetBool("help")
	if help {
		flagSet.Usage()
		return 0, nil
	}

	version, _ := flagSet.GetBool("version")
	if version {
		_, _ = fmt.Fprintln(os.Stdout, appVersion())
		return 0, nil
	}

	if flagSet.Changed("config") && flagSet.Changed("named-config") {
		return 1, errors.New("--config and --named-config cannot be used together")
	}

	if flagSet.Changed("named-config") {
		resolvedConfigPath, resolveErr := namedConfigURL(namedConfig)
		if resolveErr != nil {
			return 1, resolveErr
		}
		configPath = resolvedConfigPath
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		return 1, err
	}

	if cfg.Mode == "" {
		cfg.Mode = "run"
	}
	if flagSet.Changed("mode") {
		cfg.Mode = mode.Value()
	}
	if cfg.Mode != "run" && cfg.Mode != "mcp" {
		return 1, fmt.Errorf("invalid mode %q (valid: run|mcp)", cfg.Mode)
	}

	if flagSet.Changed("abi") {
		cfg.ABI, _ = flagSet.GetInt("abi")
	}
	if flagSet.Changed("best-effort") {
		cfg.BestEffort, _ = flagSet.GetBool("best-effort")
	}
	if flagSet.Changed("restrict-scoped") {
		cfg.RestrictScoped, _ = flagSet.GetBool("restrict-scoped")
	}
	if flagSet.Changed("unsafe-host-runtime") {
		cfg.UnsafeHostRuntime, _ = flagSet.GetBool("unsafe-host-runtime")
	}

	var fsRules []fsRule
	if flagSet.Changed("fs") {
		fsRules = fsFlag.Slice()
	} else {
		for _, value := range cfg.FSRules {
			rule, parseErr := parseFSRule(value)
			if parseErr != nil {
				return 1, fmt.Errorf("invalid fs value %q in config: %w", value, parseErr)
			}
			fsRules = append(fsRules, rule)
		}
	}

	var networkRules []networkRule
	if flagSet.Changed("net") {
		networkRules = networkFlag.Slice()
	} else {
		for _, value := range cfg.NetworkRules {
			rule, parseErr := parseNetworkRule(value)
			if parseErr != nil {
				return 1, fmt.Errorf("invalid net value %q in config: %w", value, parseErr)
			}
			networkRules = append(networkRules, rule)
		}
	}

	cmdArgs := flagSet.Args()
	if cfg.Mode == "mcp" && len(cmdArgs) > 0 {
		return 1, errors.New("mode mcp does not accept command arguments")
	}
	if cfg.Mode == "run" && len(cmdArgs) == 0 {
		flagSet.Usage()
		return 1, errors.New("missing command")
	}

	opts, warnings, err := buildOptions(cfg, runtime.GOOS, fsRules, networkRules)
	if err != nil {
		return 1, err
	}
	for _, warning := range warnings {
		_, _ = fmt.Fprintln(os.Stderr, "sandboxec: warning:", warning)
	}

	if cfg.Mode == "mcp" {
		if err := runMCPServer(mcp.Config{
			Name:        AppName,
			Version:     AppVersion,
			Description: AppDescription,
			Options:     opts,
		}); err != nil {
			return 1, err
		}
		return 0, nil
	}

	sb := sandboxec.New(opts...)
	cmd := sb.Command(cmdArgs[0], cmdArgs[1:]...)
	if cmd.Err != nil {
		return 1, cmd.Err
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				return status.ExitStatus(), nil
			}
		}
		return 1, err
	}

	return 0, nil
}

var runMCPServer = func(cfg mcp.Config) error {
	return mcp.Serve(context.Background(), cfg)
}

// buildOptions maps cfg to sandbox options for goos. It reports every setting
// that cannot take effect there: as a warning when ignoring it keeps the
// sandbox as strict as requested, and as an error when it would not.
func buildOptions(cfg appConfig, goos string, fsRules []fsRule, networkRules []networkRule) ([]sandboxec.Option, []string, error) {
	isLinux := goos == "linux"
	if !isLinux && cfg.RestrictScoped {
		return nil, nil, fmt.Errorf("restrict-scoped is unsupported on %s: scoped IPC restrictions require Landlock on linux", goos)
	}

	var warnings []string
	if cfg.FailIfMissing {
		warnings = append(warnings, "ignore-if-missing: false is ignored: fs rules with missing paths never fail")
	}
	if !isLinux && cfg.ABI != 0 {
		warnings = append(warnings, fmt.Sprintf("abi %d is ignored on %s: Landlock ABIs apply only on linux", cfg.ABI, goos))
	}

	opts := make([]sandboxec.Option, 0, 5+len(fsRules)+len(networkRules))
	if isLinux {
		opts = append(opts, sandboxec.WithIgnoreIfMissing())
		if cfg.ABI != 0 {
			opts = append(opts, sandboxec.WithABI(cfg.ABI))
		}
		if cfg.RestrictScoped {
			opts = append(opts, sandboxec.WithRestrictScoped())
		}
	}
	if cfg.BestEffort {
		opts = append(opts, sandboxec.WithBestEffort())
	}
	if cfg.UnsafeHostRuntime {
		opts = append(opts, sandboxec.WithUnsafeHostRuntime())
	}
	for _, rule := range fsRules {
		opts = append(opts, sandboxec.WithFSRule(rule.Path, rule.Rights))
	}
	for _, rule := range networkRules {
		opts = append(opts, sandboxec.WithNetworkRule(rule.Port, rule.Rights))
	}
	return opts, warnings, nil
}

func appVersion() string {
	var sb strings.Builder

	sb.WriteString(AppName)
	sb.WriteString(" ")
	sb.WriteString(AppVersion)
	if AppBuildCommit != "" {
		sb.WriteString(" (")
		sb.WriteString(AppBuildCommit)
		sb.WriteString(")")
	}
	if AppBuildDate != "" {
		sb.WriteString(" built on ")
		sb.WriteString(AppBuildDate)
	}
	sb.WriteString("\n")
	sb.WriteString(AppDescription)
	sb.WriteString("\n\n")
	sb.WriteString("Author: ")
	sb.WriteString(AppAuthor)

	return sb.String()
}

func namedConfigURL(value string) (string, error) {
	name := strings.TrimSpace(value)
	name = strings.TrimPrefix(name, "/")
	name = strings.TrimSuffix(name, ".yaml")
	name = strings.TrimSuffix(name, ".yml")

	if name == "" {
		return "", errors.New("named config value cannot be empty")
	}

	return namedConfigBaseURL + name + ".yaml", nil
}
