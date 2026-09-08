<!-- AUTO-GENERATED README — DO NOT EDIT. Changes will be overwritten on next publish. -->
# claude-code-plugin-gorgias

Dedicated agent for Gorgias helpdesk operations with isolated API access

![Version](https://img.shields.io/badge/version-1.7.0-blue) ![License: MIT](https://img.shields.io/badge/License-MIT-green) ![Node >= 18](https://img.shields.io/badge/node-%3E%3D18-brightgreen)

## Features

- Ticket
- **list-tickets** — List tickets
- **get-ticket** — Get ticket details
- **create-ticket** — Create a new ticket
- **add-message** — Add an API-channel message to a non-email ticket
- Customer
- **list-customers** — List customers
- **get-customer** — Get customer details
- **export-customers** — Export masked/hashed customer dedupe evidence
- **generate-merge-manifest** — Generate a customer merge approval manifest from an export
- **discover-customer-matches** — Exhaustively scan customers/tickets/messages into encrypted staging and produce a non-executable v2 review proposal
- **merge-customers** — Shadow-report, enforce, or execute an approved customer merge batch
- **verify-merge-batch** — Verify target/source status after a merge batch
- Utility
- **list-tools** — List all available CLI commands

## Prerequisites

- [Node.js](https://nodejs.org/) >= 18
- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI
- API credentials for the target service (see Configuration)

## Quick Start

```bash
git clone https://github.com/bigl34/claude-code-plugin-gorgias.git
cd claude-code-plugin-gorgias
cp config.template.json config.json  # fill in your credentials
npm --prefix scripts install
```

```bash
npm --prefix scripts run cli -- list-tickets
```

## Installation

1. Clone this repository
2. Copy `config.template.json` to `config.json` and fill in your credentials
3. Install dependencies:
   ```bash
   cd scripts && npm install
   ```

## Available Commands

### Ticket Commands

| Command         | Description                                      | Options                                                                                                               |
| --------------- | ------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------- |
| `list-tickets`  | List tickets                                     | `--limit`, `--status`, `--search`, `--order-by`, `--cursor`, `--resume-token`, `--checkpoint-path`, `--updated-after` |
| `get-ticket`    | Get ticket details                               | `--id` (required)                                                                                                     |
| `create-ticket` | Create a new ticket                              | `--customer-email`, `--subject`, `--message` (all required)                                                           |
| `add-message`   | Add an API-channel message to a non-email ticket | `--ticket-id`, `--message`, `--from-agent` (all required)                                                             |

### Customer Commands

| Command                     | Description                                                                                                         | Options                                                                                                                                                                                |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `list-customers`            | List customers                                                                                                      | `--limit`, `--email`                                                                                                                                                                   |
| `get-customer`              | Get customer details                                                                                                | `--id` (required)                                                                                                                                                                      |
| `export-customers`          | Export masked/hashed customer dedupe evidence                                                                       | `--limit`, `--page-limit`, `--max-pages`, `--output-path`                                                                                                                              |
| `generate-merge-manifest`   | Generate a customer merge approval manifest from an export                                                          | `--export-path`, `--output-path`, `--batch-id`                                                                                                                                         |
| `discover-customer-matches` | Exhaustively scan customers/tickets/messages into encrypted staging and produce a non-executable v2 review proposal | `--run-dir`, `--key-path`, `--default-country`, `--expected-customer-count`, `--request-interval-ms`, `--max-retries`, `--max-stabilization-passes`, `--resume`, `--audit-per-stratum` |
| `merge-customers`           | Shadow-report, enforce, or execute an approved customer merge batch                                                 | `--manifest`, `--batch`, `--execute`, `--integration-mode shadow\                                                                                                                      |
| `verify-merge-batch`        | Verify target/source status after a merge batch                                                                     | `--manifest`, `--batch`                                                                                                                                                                |

### Utility Commands

| Command      | Description                     |
| ------------ | ------------------------------- |
| `list-tools` | List all available CLI commands |

## Usage Examples

```bash
# List recent tickets
npm --prefix "scripts" run cli -- list-tickets --limit 10

# List open tickets
npm --prefix "scripts" run cli -- list-tickets --status open --limit 10

# Get specific ticket
npm --prefix "scripts" run cli -- get-ticket --id 12345

# Search customers by email
npm --prefix "scripts" run cli -- list-customers --email john@example.com

# Export dedupe evidence without raw emails/phones
npm --prefix "scripts" run cli -- export-customers --output-path /tmp/gorgias-customers-export.json

# Generate a review manifest; edit approvals in the manifest before any write
npm --prefix "scripts" run cli -- generate-merge-manifest --export-path /tmp/gorgias-customers-export.json --output-path /tmp/gorgias-merge-manifest.json

# Build an exhaustive proposal-only review run; this never merges customers
npm --prefix "scripts" run cli -- discover-customer-matches --run-dir "$HOME/biz/var/gorgias-customer-dedupe/review-run" --key-path "$HOME/biz/var/gorgias-customer-dedupe/review-run/run.key" --default-country GB --expected-customer-count "<customer count from your preview>" --request-interval-ms 1000

# Shadow-report an approved batch; use enforce for the final dry-run gate
npm --prefix "scripts" run cli -- merge-customers --manifest /tmp/gorgias-merge-manifest.json --batch batch-1 --dry-run

# Live execution requires an enforced preflight and explicit confirmation
npm --prefix "scripts" run cli -- merge-customers --manifest /tmp/gorgias-merge-manifest.json --batch batch-1 --integration-mode enforce --execute --confirm

# Add an API-channel message to a non-email ticket (from agent)
npm --prefix "scripts" run cli -- add-message --ticket-id 12345 --message "Thank you for contacting us" --from-agent true
```

## How It Works

This plugin connects directly to the service's HTTP API. The CLI handles authentication, request formatting, pagination, and error handling, returning structured JSON responses.

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Authentication errors | Verify credentials in `config.json` |
| `ERR_MODULE_NOT_FOUND` | Run `cd scripts && npm install` |
| Rate limiting | The CLI handles retries automatically; wait and retry if persistent |
| Unexpected JSON output | Check API credentials haven't expired |

## Contributing

Issues and pull requests are welcome.

## License

MIT
