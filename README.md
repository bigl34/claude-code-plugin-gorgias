<!-- AUTO-GENERATED README — DO NOT EDIT. Changes will be overwritten on next publish. -->
# claude-code-plugin-gorgias

Dedicated agent for Gorgias helpdesk operations with isolated API access

![Version](https://img.shields.io/badge/version-1.1.11-blue) ![License: MIT](https://img.shields.io/badge/License-MIT-green) ![Node >= 18](https://img.shields.io/badge/node-%3E%3D18-brightgreen)

## Features

- Ticket
- **list-tickets** — List tickets
- **get-ticket** — Get ticket details
- **create-ticket** — Create a new ticket
- **add-message** — Add message to ticket
- Customer
- **list-customers** — List customers
- **get-customer** — Get customer details
- Utility
- **list-tools** — List all available CLI commands

## Prerequisites

- [Node.js](https://nodejs.org/) >= 18
- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI
- API credentials for the target service (see Configuration)

## Quick Start

```bash
git clone https://github.com/YOUR_GITHUB_USER/claude-code-plugin-gorgias.git
cd claude-code-plugin-gorgias
cp config.template.json config.json  # fill in your credentials
cd scripts && npm install
```

```bash
node scripts/dist/cli.js list-tickets
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

| Command         | Description           | Options                                                     |
| --------------- | --------------------- | ----------------------------------------------------------- |
| `list-tickets`  | List tickets          | `--limit`, `--status`, `--order-by`                         |
| `get-ticket`    | Get ticket details    | `--id` (required)                                           |
| `create-ticket` | Create a new ticket   | `--customer-email`, `--subject`, `--message` (all required) |
| `add-message`   | Add message to ticket | `--ticket-id`, `--message`, `--from-agent` (all required)   |

### Customer Commands

| Command          | Description          | Options              |
| ---------------- | -------------------- | -------------------- |
| `list-customers` | List customers       | `--limit`, `--email` |
| `get-customer`   | Get customer details | `--id` (required)    |

### Utility Commands

| Command      | Description                     |
| ------------ | ------------------------------- |
| `list-tools` | List all available CLI commands |

## Usage Examples

```bash
# List recent tickets
node scripts/dist/cli.js list-tickets --limit 10

# List open tickets
node scripts/dist/cli.js list-tickets --status open --limit 10

# Get specific ticket
node scripts/dist/cli.js get-ticket --id 12345

# Search customers by email
node scripts/dist/cli.js list-customers --email john@example.com

# Add a message to a ticket (from agent)
node scripts/dist/cli.js add-message --ticket-id 12345 --message "Thank you for contacting us" --from-agent true
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
