# WRP Activation Backend

Node.js activation API and mobile-friendly admin dashboard for WRP.

## Endpoints

- `GET /health` — health status and storage mode (does not expose credentials).
- `GET /admin` — admin dashboard.
- `POST /api/activate` — validates an activation key and binds it to the first installation.
- `GET /api/admin/keys` — list keys (requires an admin Bearer token).
- `POST /api/admin/keys` — issue a key (requires an admin Bearer token).
- `POST /api/admin/keys/revoke` — revoke a key (requires an admin Bearer token).

## Required environment variables

- `ADMIN_TOKEN`: secret value of at least 32 characters.
- `KEY_PEPPER`: a different secret value of at least 32 characters.
- `DATABASE_URL`: PostgreSQL connection URL for durable storage. Use the **Internal Database URL** when the database and web service are in the same Render region.

Never commit these values to GitHub or paste them into public chats.

## Storage behavior

When `DATABASE_URL` is configured, the service creates the `wrp_activation_keys` table and stores keys in PostgreSQL. The schema is created automatically at startup.

Without `DATABASE_URL`, the service falls back to a local JSON file for development only. Files on Render Free web services are ephemeral and can be lost during restart, spin-down, or redeploy; do not issue production keys in this mode.

**Important migration note:** Switching from local JSON storage to PostgreSQL starts with an empty database. Existing local key records are not automatically migrated. Before enabling the database, account for existing keys and issue replacement keys only when appropriate. Raw activation keys cannot be recovered from their stored hashes.

Render Free PostgreSQL databases expire after 30 days. Use a durable paid database plan (or another properly backed-up persistent datastore) for ongoing real-user use.

## Run locally

Requires Node.js 20+.

```bash
npm install
ADMIN_TOKEN='use-a-long-random-secret-value-at-least-32-chars' KEY_PEPPER='use-a-different-long-random-secret-value-32-chars' npm start
```

Without `DATABASE_URL`, local development uses `./wrp-data/keys.json`.
