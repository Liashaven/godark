# GoDark account service source

This folder contains the Node.js/MySQL account API, its account-facing pages, database migration, tests, and container recipe. It is source code only; it is **not deployed** by the Cloudflare Pages static site in `../site/`. The public `/account` page has no form and does not send data to this service.

## Readiness gate

Registration, sign-in, and optional telemetry must remain unavailable until a permanent HTTPS API origin is configured, the daily retention callback is registered and verified, the database provider's backup-retention limit is confirmed at 90 days or less, and the required security and legal reviews are complete. The API checks the `service_readiness` row before allowing account or telemetry operations. Do not set it to enabled as a substitute for completing and documenting those checks.

The retention endpoint is `POST /api/scheduled/retention`. It accepts only a valid scheduled-task identity for the configured project and the exact task UID recorded in readiness. Its `pruneExpired` routine removes expired sessions, diagnostics older than 90 days, usage events older than 12 months, and security events older than 30 days. Running the endpoint manually is not proof that a recurring schedule is configured or healthy.

## Development and tests

Requirements: Node.js 22 and pnpm 11.25.0. From this directory:

```sh
pnpm install --frozen-lockfile
pnpm test
```

A database and runtime configuration are required to start the service. Copy `.env.example` to a local, untracked environment file and supply secrets only through a protected runtime configuration. Never commit production credentials or a real `.env` file. `Dockerfile` is provided for a later reviewed deployment; this repository's static Cloudflare Pages deployment does not use it.

## Data boundaries

Account records contain account and consent metadata. Optional usage events and diagnostics are accepted only when their separate consent is enabled and fields pass strict allowlists. The API does not accept message content, group codes or keys, contacts, check-in contents, or precise location. Disabling a consent deletes existing records for that optional category. Account deletion removes account-linked active records but cannot erase local app data, copies on other devices, independent relay copies, or provider backups.

`PRIVACY.md` and `TERMS.md` at the repository root and the corresponding public pages are drafts, not legal advice or a guarantee against claims. The operator identity and support contact remain unconfigured; obtain qualified jurisdiction-specific review before launching accounts or a finished app release.
