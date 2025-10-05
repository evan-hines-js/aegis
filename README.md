# Aegis

Model Context Protocol hub implementation.

## Features

- MCP server-side protocol implementation
- OAuth 2.0/OIDC authentication
- API key management
- Resource-level access control
- Multi-node clustering support
- Rate limiting
- Session management

## Stack

- Elixir 1.15+
- Phoenix 1.8
- Ash Framework 3.0
- PostgreSQL
- Oban

## Setup

```bash
mix setup

export SECRET_KEY_BASE=$(mix phx.gen.secret)
export ENCRYPTION_KEY=$(mix phx.gen.secret 32)
export TOKEN_SIGNING_SECRET=$(mix phx.gen.secret)
export DATABASE_URL=postgresql://postgres:postgres@localhost:5432/aegis_dev

mix phx.server
```

## Configuration

Copy `.env.example` to `.env`.

Required:
- `DATABASE_URL`
- `SECRET_KEY_BASE`
- `ENCRYPTION_KEY`
- `TOKEN_SIGNING_SECRET`

See `.env.example` for full configuration.

## Development

```bash
mix test               # Run tests
mix precommit          # Compile, format, test
mix phx.server         # Start server
```

## Deployment

```bash
docker-compose up
```

Or:

```bash
MIX_ENV=prod mix release
_build/prod/rel/aegis/bin/aegis start
```

## License

GNU Affero General Public License v3.0
