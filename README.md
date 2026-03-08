# sandboxec

<a href="https://github.com/sandboxec/sandboxec/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/sandboxec/sandboxec?color=blueviolet" /></a>
<a href="https://github.com/sandboxec/sandboxec/actions/workflows/tests.yaml"><img alt="tests" src="https://github.com/sandboxec/sandboxec/actions/workflows/tests.yaml/badge.svg" /></a>
<a href="#"><img alt="Platform" src="https://img.shields.io/badge/platform-linux%20%7C%20darwin-green" /></a>
<a href="/LICENSE"><img alt="License" src="https://img.shields.io/badge/License-Apache%202.0-yellowgreen" /></a>

<img height="122" alt="sandboxec" href="#" src="https://github.com/user-attachments/assets/fe4a25bd-b317-4c3a-a5a9-a0a1a3d031c2" />

A lightweight command sandboxer, secure-by-default.

<img src="https://github.com/user-attachments/assets/2ff92aaa-7596-452f-a745-c0ae1e67f63f" href="#" height="280">

No daemon. No root. No image build step.

Use it to run risky commands with a tighter blast radius: third-party CLIs, untrusted scripts, generated code, and one-off tooling.

## Purpose

Running untrusted code is often an all-or-nothing choice.

Containers and VMs are great tools, but they can be too much for quick command-level isolation. Containers add image and runtime overhead. VMs add stronger isolation with higher setup and resource cost.

**`sandboxec`** focuses on a narrower job: sandbox one command on the current host, with low overhead and explicit allow rules.

**See also**:

* D. Siswanto, “The most practical, fast, tiny command sandboxing for AI agents,” Dwi Siswanto, Feb. 17, 2026. https://dw1.io/blog/2026/02/17/sandboxec/

## Why sandboxec?

- Sandbox existing binaries without modifying application code.
- Restrict filesystem and TCP access with allow-list rules.
- Apply policy right before command execution, so child processes inherit restrictions.
- Keep local workflows simple for CI jobs, local scripts, and developer tooling.

## When to use it?

Good fit:

- Running a third-party CLI against a local repo.
- Executing generated code in CI.
- Testing install scripts before trusting them with full host access.
- Wrapping build tools that only need a small slice of the filesystem.

## When't?

- You need stronger isolation boundaries than process-level sandboxing.
- You need multi-tenant isolation between untrusted users/workloads.
- You need resource isolation/quotas (CPU, memory, disk, I/O).
- You need custom root filesystems, full runtime images, or OS-level virtualization.

Use containers or VMs for those cases.

## Requirements

- Go 1.25+
- Linux (kernel >= 5.13) or macOS (Darwin)

### Linux kernel compatibility (Landlock)

| Capability | Landlock ABI | Typical minimum kernel |
| --- | --- | --- |
| Filesystem restrictions | v1+ | 5.13+ |
| TCP bind/connect restrictions | v4+ | 6.7+ |

## Security model

**`sandboxec`** limits what a process can:
- **Read / Write / Execute** on the filesystem.
- **Bind / Connect** on the network (TCP).

Restrictions are applied immediately before launching the target command. Once set, those restrictions apply to that process and its children.

> [!IMPORTANT]
> It's designed to reduce damage from buggy, risky, or malicious user-space programs by narrowing what they can touch, hence it does NOT protect against:
> 
> - Kernel bugs or privileged local attackers.
> - Resource exhaustion (CPU, memory, disk).
> - Every possible host interaction outside configured sandbox controls.
> 
> Treat it as a practical containment layer.

## Install

* Using script:

  ```bash
  curl -sSL https://get.sandbox.ec | sh
  ```

* Using Go compiler:

> [!NOTE]
> Requires [Go](https://go.dev/doc/install) 1.25.0 or later.

  ```bash
  go install go.sandbox.ec/sandboxec@v0.4.0
  ```

* Or download a pre-built binary from [releases page](https://github.com/sandboxec/sandboxec/releases).

* Or build from source:

> [!WARNING]
> The `master` branch contains the latest code changes and updates, which might not have undergone thorough testing and quality assurance - thus, you may encounter instability or unexpected behavior.

> [!TIP]
> On Darwin, build with `CGO_ENABLED=0`.

  ```bash
  git clone https://github.com/sandboxec/sandboxec.git
  cd sandboxec/
  # git checkout v0.4.0
  make build
  # ./bin/sandboxec --help
  ```

## Usage

```bash
sandboxec [OPTIONS] [COMMAND [ARG...]]
```

Examples:

```bash
sandboxec --fs rx:/usr /usr/bin/echo hello
sandboxec --fs rx:/usr -- /usr/bin/ls /usr
sandboxec --fs rx:/usr --net c:<PORT> -- /usr/bin/curl http://127.0.0.1:<PORT>
sandboxec --mode mcp --fs rx:/usr --fs rw:$PWD --net c:443
```

## Options

| Option | Description |
| --- | --- |
| `-c, --config` | Path to YAML config file. |
| `-C, --named-config` | Named config profile (mapped to sandboxec/profiles repository). |
| `-f, --fs RIGHTS:PATH` | Add filesystem rule (repeatable). |
| `-n, --net RIGHTS:PORT` | Add network rule (repeatable). |
| `--best-effort` | Continue even if the kernel lacks support for some features. |
| `--unsafe-host-runtime` | Allow read_exec rights for host runtime paths. |
| `-m, --mode string` | Execution mode (`run` or `mcp`). Default: `run`. |
| `-V, --version` | Show app version. |
| `-h, --help` | Show help. |

Available MCP tools:

- `exec`: Execute a command and return `stdout`, `stderr`, and `exit_code`.
  - Input: `command` (required), `args` (optional array).
  - Execution path uses `sandboxec` runtime with effective policy derived from CLI flags or YAML config.

> [!NOTE]
> * `--unsafe-host-runtime` broadens allowed runtime & library access and weakens least-privilege guarantees.
> * In `--mode mcp`, no wrapped command arguments are accepted.

## Rule format

### Filesystem rules

Format: `RIGHTS:PATH`

Accepted rights:

- `read` or `r`
- `read_exec` or `rx`
- `write` or `w`
- `read_write` or `rw`
- `read_write_exec` or `rwx`

> [!NOTE]
> Filesystem restrictions require Landlock support on Linux (5.13+). On Darwin, filesystem rules are translated to Seatbelt policy rules.

### Network rules

Format: `RIGHTS:PORT`

Accepted rights:

- `bind` or `b`
- `connect` or `c`
- `bind_connect` or `bc`

> [!NOTE]
> Network restrictions (`bind` / `connect`) require newer Landlock support on Linux (ABI v4+, typically Linux 6.7+). On Darwin, network policy is deny-by-default and `--net` allow-lists selected ports.

> [!IMPORTANT]
> If the running kernel does not support requested features, use `--best-effort` to degrade gracefully.

## Rule behavior

- Rules are allow-list based: if it is not allowed, it is denied. It is what it is.
- Multiple `--fs` and `--net` entries are cumulative.
- Rules should include every runtime dependency your command needs.

## Configuration

Configuration is YAML-only.

### Keys

```yaml
best-effort: false
unsafe-host-runtime: false
fs:
  - rx:/bin
net:
  - c:443
mode: run
```

### Config lookup

- If `--config` is set, that file is used.
- If `--named-config` is set, the value maps to a profile in the [sandboxec/profiles](https://github.com/sandboxec/profiles) repository.
- Otherwise, `sandboxec.yaml` or `sandboxec.yml` is searched in:
  1. `$XDG_CONFIG_HOME/sandboxec`
  2. `$HOME/.config/sandboxec`
  3. `/etc/sandboxec`

If no config file is found, defaults are used.

### Precedence rules

- `--config` and `--named-config` cannot be used together.
- CLI flags override config values for scalar options.
- `--fs` and `--net` replace config lists when those flags are set.
- If those flags are not set, rules come from config.

### Example profile

```yaml
best-effort: true
unsafe-host-runtime: false
fs:
  - rx:/bin
  - rx:/usr
  - rx:/lib
  - rx:/usr/lib
  - rw:/tmp
net:
  - c:443
```

### Profiles repository

Looking for ready-made policy profiles? See [sandboxec/profiles](https://github.com/sandboxec/profiles) repository.

## Exit codes

- `0`: Wrapped command succeeded.
- `N`: Wrapped command exited with code `N`.
- `1`: **`sandboxec`** failed to setup (parsing error, policy enforcement failure).

## Practical notes

- **Allow-list only**: If a path isn't listed, it is invisible or inaccessible.
- **Dependencies**: Binaries often need to read `/lib`, `/usr/lib`, or shared object dependencies (`.so` files).
- **Unsafe runtime behavior**: `--unsafe-host-runtime` adds `read_exec` rights for PATH-derived runtime targets and its resolved shared-library dependency files discovered from executable entries, hence it can significantly increase startup latency, especially for short-lived commands.
- **Network**: Rules control TCP bind/connect. They do not replace firewalls.
- **Scope**: This is not a full container or VM replacement. It is a fast, command-level control layer for risky workloads.

## Examples

### Minimal sandboxed command

```bash
sandboxec --fs rx:/usr -- /usr/bin/id
```

### Restrict to read+exec on system binaries and read/write on tmp

```bash
sandboxec \
  --fs rx:/bin \
  --fs rx:/usr \
  --fs rw:/tmp \
  -- /bin/ls /tmp
```

### Lock a command to local-only filesystem access

```bash
sandboxec \
  --fs rx:/usr \
  --fs rw:$PWD \
  -- your-command
```

### Outbound HTTPS only (connect on 443)

```bash
sandboxec --fs rx:/usr --net c:443 -- /usr/bin/curl https://example.com
```

### Use unsafe host runtime for host-linked tooling

```bash
sandboxec \
  --unsafe-host-runtime \
  --fs rw:$PWD \
  --fs rw:/tmp \
  --net c:443 \
  -- your-build-command
```

### Run with explicit config file

```bash
sandboxec --config ./sandboxec.yaml -- /bin/echo ok
```

### Run with named profile config

```bash
sandboxec --named-config agents/claude -- claude --dangerously-skip-permissions
```

### Build step with outbound package fetch only

```bash
sandboxec \
  --fs rx:/usr \
  --fs rw:$PWD \
  --fs rw:/tmp \
  --net c:443 \
  -- your-build-command
```

### MCP configuration

```json
{
  "mcpServers": {
    "sandboxec": {
      "command": "/path/to/go/bin/sandboxec",
      "args": [
        "--mode", "mcp",
        "--fs", "rx:/usr",
        "--fs", "rw:/tmp",
        "--fs", "rw:/path/to/your/workspace",
        "--net", "c:443"
      ]
    }
  }
}
```

## Troubleshooting

- **`invalid fs rights`**: Check spelling (`rx`, `rw`, etc.).
- **Sandbox policy failures**:
  - Linux: your kernel might be too old for requested Landlock features.
  - Use `--best-effort` for compatibility fallback when strict enforcement is not required.

If commands fail with `permission denied`:

- Add missing runtime paths (`/usr`, `/lib`, `/usr/lib`, `/etc` as needed).
- Check platform capability for requested rule types.
- Retry with `--best-effort` to confirm whether unsupported platform features are the blocker.

# License

**sandboxec** is released with ♡ by [**@dwisiswant0**](https://dw1.io) under the Apache 2.0 license. See [`LICENSE`](/LICENSE).
