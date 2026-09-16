# prongs

![Release Build](https://img.shields.io/github/actions/workflow/status/thomaslaurenson/prongs/tag.yml?style=flat&label=release&logo=github) ![Main Build](https://img.shields.io/github/actions/workflow/status/thomaslaurenson/prongs/main.yml?style=flat&label=main&logo=github)

![Release Version](https://img.shields.io/github/v/release/thomaslaurenson/prongs?style=flat&logo=github) ![Release downloads](https://img.shields.io/github/downloads/thomaslaurenson/prongs/total?style=flat&label=downloads&logo=github)

![Go Version](https://img.shields.io/github/go-mod/go-version/thomaslaurenson/prongs?style=flat&logo=go) ![Code Coverage](https://img.shields.io/badge/Coverage-96.4%25-blue?style=flat&logo=go)

Fast, custom security scanner.

## Installation

Download a pre-built binary from the [releases page](https://github.com/thomaslaurenson/prongs/releases). For easier install, use the bash installer script:

```sh
curl -fsSL https://github.com/thomaslaurenson/prongs/releases/latest/download/install.sh | bash
```

Or the PowerShell installer script if on Windows:

```ps
irm https://github.com/thomaslaurenson/prongs/releases/latest/download/install.ps1 | iex
```

Install from source:

```sh
go install github.com/thomaslaurenson/prongs@latest
```

## Usage

```
prongs scan --scanner <name>  --target <CIDR|file>
prongs scan --all             --target <CIDR|file>
prongs --version
```

Targets are CIDR ranges or single IPs, supplied via `--target` (repeatable and/or comma-separated) or `--target-file` (one entry per line). The two flags are mutually exclusive. If neither is provided, the `TARGET_CIDRS` environment variable (comma-separated) is used as a fallback.

Findings go to stdout, one per line. Progress and diagnostics go to stderr, and progress is suppressed when stderr is not a terminal, so `prongs scan ... > findings.tsv` captures the findings and nothing else.

Interrupting a scan with Ctrl-C stops it without a message and exits 130.

### Flags

| Flag | Description | Default |
|---|---|---|
| `--target` | CIDR(s) or IP(s) to scan (repeatable and/or comma-separated) | |
| `--target-file` | Path to a file of CIDRs or IPs, one per line | |
| `--scanner` | Scanner to run (repeatable); see [Scanners](#scanners) | |
| `--all` | Run every default-enabled scanner | `false` |
| `--output` | Output format: `text` (tab-separated) or `pretty` (human-readable) | `text` |
| `--concurrency`, `-c` | Maximum concurrent probes | `200` |
| `--debug` | Log diagnostics to stderr | `false` |

`--target` and `--target-file` are mutually exclusive, and so are `--all` and `--scanner`.

### Shell completion

`prongs completion <bash|zsh|fish|powershell>` prints the completion script for a shell. Where it is installed is up to you; the installer scripts deliberately leave it alone.

### Scanners

| Name | Description | Default |
|---|---|---|
| `password-ssh` | Detects SSH servers accepting password authentication | yes |
| `accessible-rdp` | Detects RDP services accepting unauthenticated connections | no |
| `accessible-db` | Detects databases accepting unauthenticated connections | yes |
| `insecure-http` | Detects websites served over plaintext HTTP without an HTTPS redirect | yes |

Each network step a probe makes is bounded at two seconds, and that budget is not currently configurable. It is generous for a local network and tight for a distant one: probing a host in California from New Zealand spends about 150ms dialling and about 915ms on the SSH handshake, so roughly half the budget. A host further away, or one dropping packets, may go unreported. Scan from somewhere near the targets, or raise `DefaultTimeout` and rebuild, until there is a `--timeout` flag.

### Examples

```bash
# Run one scanner against a single network
prongs scan --scanner password-ssh --target 192.168.0.0/24

# Detect websites served over plaintext HTTP
prongs scan --scanner insecure-http --target 192.168.0.0/24

# Run all default scanners against multiple networks
prongs scan --all --target 192.168.0.0/24 --target 10.0.0.0/24

# Multiple networks as a single comma-separated value
prongs scan --all --target 192.168.0.0/24,10.0.0.0/24

# Load targets from a file
prongs scan --all --target-file targets.txt

# Pretty-print output
prongs scan --all --target 192.168.0.0/24 --output pretty

# Limit the number of concurrent probes
prongs scan --all --target 192.168.0.0/24 --concurrency 50

# Use the TARGET_CIDRS environment variable for a single target
TARGET_CIDRS=192.168.0.0/24 prongs scan --all

# ...or multiple comma-separated targets
TARGET_CIDRS=192.168.0.0/24,10.0.0.0/24 prongs scan --all

# Capture only the findings, with progress still shown on the terminal
prongs scan --all --target 192.168.0.0/24 > findings.tsv

# Report what was resolved and probed
prongs --debug scan --all --target 192.168.0.0/24
```

## Development

```sh
make help              # list every target
make ci                # everything CI runs: static checks and tests
make test_coverage     # coverage over internal/, the figure behind the badge
make test_integration  # the tests needing a real host, see below
```

The integration tests probe a real host and are excluded from `make test` and from CI by a build tag. Point them at a host with SSH password authentication enabled and no RDP or database port exposed:

```sh
PRONGS_TEST_HOST=45.33.32.156 make test_integration
```

They skip, rather than fail, when `PRONGS_TEST_HOST` is unset.
