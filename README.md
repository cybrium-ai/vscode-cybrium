# Cybrium Security Scanner for VS Code

Real-time SAST, SCA, and secrets detection in your editor — powered by [cyscan](https://github.com/cybrium-ai/cyscan).

## Features

- **1,067 rules** across 19 languages — Python, JavaScript, TypeScript, Go, Java, Ruby, PHP, Rust, C/C++, Terraform, Docker, YAML, and more
- **Real-time scanning** — findings appear as you save
- **Quick Fix** — one-click code fixes for detected vulnerabilities
- **Reachability** — CVE findings marked as "unreachable" when the vulnerable function isn't called
- **Severity filtering** — show only critical/high, or everything
- **Status bar** — live finding count with click to scan

## Prerequisites

Install cyscan:

```bash
brew tap cybrium-ai/cli
brew install cyscan
```

Or download from [GitHub Releases](https://github.com/cybrium-ai/cyscan/releases).

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `cybrium.autoScan` | `true` | Scan files automatically on save |
| `cybrium.cyscanPath` | (auto-detect) | Path to cyscan binary |
| `cybrium.severityFilter` | `info` | Minimum severity to display |
| `cybrium.apiUrl` | `https://app.cybrium.ai` | Platform URL for dashboard links |
| `cybrium.apiKey` | (empty) | API key for platform features |

## Commands

- **Cybrium: Scan Current File** — scan the active file
- **Cybrium: Scan Workspace** — scan entire workspace
- **Cybrium: Open Dashboard** — open Cybrium platform in browser

## License

Apache 2.0
