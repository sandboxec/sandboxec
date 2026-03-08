package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func runSandboxec(t *testing.T, args ...string) (string, error) {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	cmdArgs := append([]string{"run", "."}, args...)
	cmd := exec.Command("go", cmdArgs...)
	cmd.Dir = wd
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func mustFindUnixCmd(t *testing.T, name string) string {
	t.Helper()

	if runtime.GOOS == "windows" {
		t.Skipf("%s command lookup is only supported on Unix-like hosts", name)
	}

	for _, candidate := range []string{
		filepath.Join("/usr/bin", name),
		filepath.Join("/bin", name),
	} {
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate
		}
	}

	if p, err := exec.LookPath(name); err == nil {
		return p
	}

	t.Fatalf("required command %q not found in /usr/bin, /bin, or PATH", name)

	return ""
}

func exampleFSArgs() []string {
	args := []string{"--fs", "rx:/usr", "--fs", "rx:/bin"}
	if runtime.GOOS == "darwin" {
		args = append(args, "--fs", "rx:/System")
	}

	return args
}

func requireSandbox(t *testing.T) {
	t.Helper()
	truePath := mustFindUnixCmd(t, "true")

	out, err := runSandboxec(t, "--fs", "rx:/", "--", truePath)
	if err != nil {
		lower := strings.ToLower(out)

		hasUnavailableWord := strings.Contains(lower, "not supported") ||
			strings.Contains(lower, "unavailable") ||
			strings.Contains(lower, "unsupported")
		hasLandlockUnavailable := strings.Contains(lower, "landlock") && hasUnavailableWord
		hasSandboxUnavailable := strings.Contains(lower, "sandbox") && hasUnavailableWord
		hasSeatbeltUnavailable := strings.Contains(lower, "seatbelt is unavailable")

		if hasLandlockUnavailable || hasSandboxUnavailable || hasSeatbeltUnavailable {
			t.Skipf("skipping: sandbox backend unavailable on this host: %s", strings.TrimSpace(out))
		}
		t.Fatalf("landlock probe failed unexpectedly: %v\noutput:\n%s", err, out)
	}
}

func TestMainIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Run("HelpOutput", func(t *testing.T) {
		output, err := runSandboxec(t, "-h")
		if err != nil {
			t.Fatalf("go run -h failed: %v\noutput:\n%s", err, output)
		}

		for _, want := range []string{"Usage:", "Options:", "Rights:", "Examples:", "--mode", "--fs", "--net"} {
			if !strings.Contains(output, want) {
				t.Fatalf("help output missing %q\noutput:\n%s", want, output)
			}
		}
	})

	t.Run("ArgumentValidation", func(t *testing.T) {
		truePath := mustFindUnixCmd(t, "true")

		t.Run("MissingCommandFails", func(t *testing.T) {
			output, err := runSandboxec(t)
			if err == nil {
				t.Fatalf("expected missing-command failure, got success\noutput:\n%s", output)
			}
			if !strings.Contains(output, "missing command") {
				t.Fatalf("expected missing command error\noutput:\n%s", output)
			}
			if !strings.Contains(output, "Usage:") {
				t.Fatalf("expected usage text on missing command\noutput:\n%s", output)
			}
		})

		t.Run("InvalidFlagFails", func(t *testing.T) {
			output, err := runSandboxec(t, "--definitely-not-a-real-flag")
			if err == nil {
				t.Fatalf("expected invalid-flag failure, got success\noutput:\n%s", output)
			}
			if !strings.Contains(output, "unknown flag") {
				t.Fatalf("expected unknown flag error\noutput:\n%s", output)
			}
		})

		t.Run("InvalidModeFails", func(t *testing.T) {
			output, err := runSandboxec(t, "--mode", "invalid")
			if err == nil {
				t.Fatalf("expected invalid mode failure, got success\noutput:\n%s", output)
			}
			if !strings.Contains(output, "invalid mode") {
				t.Fatalf("expected invalid mode error\noutput:\n%s", output)
			}
		})

		t.Run("InvalidFSRuleRightsFails", func(t *testing.T) {
			out, err := runSandboxec(t, "--fs", "nope:/tmp", "--", truePath)
			if err == nil {
				t.Fatalf("expected invalid fs rule to fail\noutput:\n%s", out)
			}
			if !strings.Contains(out, "invalid fs rights") {
				t.Fatalf("expected invalid fs rights error\noutput:\n%s", out)
			}
		})

		t.Run("InvalidNetworkRulePortFails", func(t *testing.T) {
			out, err := runSandboxec(t, "--net", "c:notaport", "--", truePath)
			if err == nil {
				t.Fatalf("expected invalid network port to fail\noutput:\n%s", out)
			}
			if !strings.Contains(out, "invalid port") {
				t.Fatalf("expected invalid port error\noutput:\n%s", out)
			}
		})
	})

	t.Run("FSRules", func(t *testing.T) {
		requireSandbox(t)

		touchPath := mustFindUnixCmd(t, "touch")

		t.Run("AllowsTmpWrite", func(t *testing.T) {
			tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("sandboxec-fs-allow-%d", time.Now().UnixNano()))
			t.Cleanup(func() { _ = os.Remove(tmpFile) })

			out, err := runSandboxec(t,
				"--fs", "rx:/",
				"--fs", "rw:/tmp",
				"--",
				touchPath,
				tmpFile,
			)
			if err != nil {
				t.Fatalf("expected tmp write to succeed\nerr: %v\noutput:\n%s", err, out)
			}
			if _, statErr := os.Stat(tmpFile); statErr != nil {
				t.Fatalf("expected file to be created at %s: %v", tmpFile, statErr)
			}
		})

		t.Run("DeniesProjectWriteWhenOnlyTmpWritable", func(t *testing.T) {
			wd, err := os.Getwd()
			if err != nil {
				t.Fatalf("getwd: %v", err)
			}

			blockedFile := filepath.Join(wd, fmt.Sprintf(".sandboxec-fs-deny-%d", time.Now().UnixNano()))
			t.Cleanup(func() { _ = os.Remove(blockedFile) })

			out, err := runSandboxec(t,
				"--fs", "rx:/",
				"--fs", "rw:/tmp",
				"--",
				touchPath,
				blockedFile,
			)
			if runtime.GOOS == "linux" {
				if err == nil {
					t.Fatalf("expected write outside /tmp to fail on linux\noutput:\n%s", out)
				}
				if _, statErr := os.Stat(blockedFile); statErr == nil {
					t.Fatalf("expected blocked file not to be created on linux: %s", blockedFile)
				}
				return
			}

			if err != nil {
				t.Fatalf("expected write test command to run on %s\nerr: %v\noutput:\n%s", runtime.GOOS, err, out)
			}
			if _, statErr := os.Stat(blockedFile); statErr != nil {
				t.Fatalf("expected file to be created on %s: %v", runtime.GOOS, statErr)
			}
		})
	})

	t.Run("Examples", func(t *testing.T) {
		requireSandbox(t)
		echoPath := mustFindUnixCmd(t, "echo")
		lsPath := mustFindUnixCmd(t, "ls")
		curlPath := mustFindUnixCmd(t, "curl")
		fsArgs := exampleFSArgs()

		t.Run("EchoHello", func(t *testing.T) {
			args := append(append([]string{}, fsArgs...), "--", echoPath, "hello")
			out, err := runSandboxec(t, args...)
			if err != nil {
				t.Fatalf("expected echo example to succeed\nerr: %v\noutput:\n%s", err, out)
			}
			if !strings.Contains(out, "hello") {
				t.Fatalf("expected echo output to contain hello, got: %q", out)
			}
		})

		t.Run("ListUsr", func(t *testing.T) {
			args := append(append([]string{}, fsArgs...), "--", lsPath, "/usr")
			out, err := runSandboxec(t, args...)
			if err != nil {
				t.Fatalf("expected ls example to succeed\nerr: %v\noutput:\n%s", err, out)
			}
			if strings.TrimSpace(out) == "" {
				t.Fatalf("expected ls output, got empty output")
			}
		})

		t.Run("CurlLocalhostWithPortRule", func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("ok"))
			}))
			t.Cleanup(server.Close)

			_, portText, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
			if err != nil {
				t.Fatalf("split host/port: %v", err)
			}
			port, err := strconv.Atoi(portText)
			if err != nil {
				t.Fatalf("parse port: %v", err)
			}

			args := append(append([]string{}, fsArgs...),
				"--net", fmt.Sprintf("c:%d", port),
				"--",
				curlPath,
				"-fsS",
				fmt.Sprintf("http://127.0.0.1:%d", port),
			)
			out, err := runSandboxec(t, args...)
			if err != nil {
				t.Fatalf("expected curl localhost example to succeed\nerr: %v\noutput:\n%s", err, out)
			}
			if !strings.Contains(out, "ok") {
				t.Fatalf("expected response body in output, got: %q", out)
			}
		})
	})

	t.Run("NetworkRules", func(t *testing.T) {
		requireSandbox(t)

		curlPath := mustFindUnixCmd(t, "curl")

		t.Run("CurlAllowedPortSucceeds", func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("ok"))
			}))
			t.Cleanup(server.Close)

			_, portText, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
			if err != nil {
				t.Fatalf("split host/port: %v", err)
			}
			port, err := strconv.Atoi(portText)
			if err != nil {
				t.Fatalf("parse port: %v", err)
			}
			url := fmt.Sprintf("http://127.0.0.1:%d", port)

			out, err := runSandboxec(t,
				"--fs", "rx:/",
				"--net", fmt.Sprintf("c:%d", port),
				"--",
				curlPath,
				"-fsS",
				url,
			)
			if err != nil {
				t.Fatalf("expected curl connect to allowed port to succeed\nerr: %v\noutput:\n%s", err, out)
			}
			if !strings.Contains(out, "ok") {
				t.Fatalf("expected response body in output, got: %q", out)
			}
		})

		t.Run("CurlDeniedPortFails", func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("ok"))
			}))
			t.Cleanup(server.Close)

			_, portText, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
			if err != nil {
				t.Fatalf("split host/port: %v", err)
			}
			port, err := strconv.Atoi(portText)
			if err != nil {
				t.Fatalf("parse port: %v", err)
			}
			url := fmt.Sprintf("http://127.0.0.1:%d", port)

			out, err := runSandboxec(t,
				"--fs", "rx:/",
				"--net", fmt.Sprintf("b:%d", port),
				"--",
				curlPath,
				"-fsS",
				url,
			)
			if err == nil {
				t.Fatalf("expected curl connect to be denied\noutput:\n%s", out)
			}
		})
	})

	t.Run("ConfigPrecedence", func(t *testing.T) {
		requireSandbox(t)

		touchPath := mustFindUnixCmd(t, "touch")
		truePath := mustFindUnixCmd(t, "true")

		dir := t.TempDir()
		configPath := filepath.Join(dir, "sandboxec.yaml")
		configBody := strings.Join([]string{"fs:", "  - rx:/", "  - rw:/tmp"}, "\n") + "\n"
		if writeErr := os.WriteFile(configPath, []byte(configBody), 0o644); writeErr != nil {
			t.Fatalf("write config file: %v", writeErr)
		}

		tmpAllowed := filepath.Join(os.TempDir(), fmt.Sprintf("sandboxec-config-allow-%d", time.Now().UnixNano()))
		t.Cleanup(func() { _ = os.Remove(tmpAllowed) })

		out, err := runSandboxec(t,
			"--config", configPath,
			"--",
			touchPath,
			tmpAllowed,
		)
		if err != nil {
			t.Fatalf("expected config fs to allow /tmp write\nerr: %v\noutput:\n%s", err, out)
		}
		if _, statErr := os.Stat(tmpAllowed); statErr != nil {
			t.Fatalf("expected file created via config-based rules: %v", statErr)
		}

		tmpBlocked := filepath.Join(os.TempDir(), fmt.Sprintf("sandboxec-config-block-%d", time.Now().UnixNano()))
		t.Cleanup(func() { _ = os.Remove(tmpBlocked) })

		badConfigPath := filepath.Join(dir, "sandboxec-invalid-fs.yaml")
		badConfigBody := strings.Join([]string{"fs:", "  - nope:/tmp"}, "\n") + "\n"
		if writeErr := os.WriteFile(badConfigPath, []byte(badConfigBody), 0o644); writeErr != nil {
			t.Fatalf("write invalid config file: %v", writeErr)
		}

		out, err = runSandboxec(t,
			"--config", badConfigPath,
			"--fs", "rx:/",
			"--",
			truePath,
		)
		if err != nil {
			t.Fatalf("expected --fs flag to replace invalid config fs rules\nerr: %v\noutput:\n%s", err, out)
		}
	})
}
