package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/spf13/pflag"
	"go.dw1.io/x/exp/sandboxec"
	"go.sandbox.ec/sandboxec/internal/mcp"
)

// Run executes the sandboxec CLI workflow.
// It returns a process exit code for wrapped commands and an error for CLI/runtime failures.
func Run(argv []string) (int, error) {
	var configPath string
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
	flagSet.VarP(&fsFlag, "fs", "f", "Filesystem rule (repeatable)")
	flagSet.VarP(&networkFlag, "net", "n", "Network rule (repeatable)")
	flagSet.Int("abi", 0, "Landlock ABI version (1-6, 0 means default)")
	flagSet.Bool("best-effort", false, "Ignore unsupported ABI/Landlock availability")
	flagSet.Bool("ignore-if-missing", false, "Ignore missing fs rule paths")
	flagSet.Bool("restrict-scoped", false, "Enable scoped IPC restrictions (ABI v6+)")
	flagSet.Bool("unsafe-host-runtime", false, "Allow read_exec rights for host runtime paths")
	flagSet.VarP(&mode, "mode", "m", "Execution mode (run|mcp)")
	flagSet.BoolP("version", "V", false, "Show app version")
	flagSet.BoolP("help", "h", false, "Show help")

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
	if flagSet.Changed("ignore-if-missing") {
		cfg.IgnoreIfMissing, _ = flagSet.GetBool("ignore-if-missing")
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
	if cfg.Mode == "mcp" {
		if len(cmdArgs) > 0 {
			return 1, errors.New("mode mcp does not accept command arguments")
		}
		execOptions := buildOptions(cfg, fsRules, networkRules)
		if err := runMCPServer(mcp.Config{
			Name:        AppName,
			Version:     AppVersion,
			Description: AppDescription,
			Options:     execOptions,
		}); err != nil {
			return 1, err
		}
		return 0, nil
	}

	if len(cmdArgs) == 0 {
		flagSet.Usage()
		return 1, errors.New("missing command")
	}

	opts := buildOptions(cfg, fsRules, networkRules)

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

func buildOptions(cfg appConfig, fsRules []fsRule, networkRules []networkRule) []sandboxec.Option {
	opts := make([]sandboxec.Option, 0, 4+len(fsRules)+len(networkRules))
	if cfg.ABI != 0 {
		opts = append(opts, sandboxec.WithABI(cfg.ABI))
	}
	if cfg.BestEffort {
		opts = append(opts, sandboxec.WithBestEffort())
	}
	if cfg.IgnoreIfMissing {
		opts = append(opts, sandboxec.WithIgnoreIfMissing())
	}
	if cfg.RestrictScoped {
		opts = append(opts, sandboxec.WithRestrictScoped())
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
	return opts
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
