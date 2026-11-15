# DLL-LULZ-AI Web Licensing (MVP)

This folder contains the first, payment-free licensing prototype for DLL-LULZ-AI 0.7.0.

## Architecture

- `site/`: static landing page, suitable for Cloudflare Pages.
- `worker/`: Cloudflare Worker API.
- Cloudflare D1: stores SHA-256 hashes of license keys and expiry/status metadata.

The MVP intentionally does not collect payments, passwords, or personal data. Create test licenses manually in D1 until the validation flow is tested. Never commit real license keys, API tokens, or Cloudflare credentials.

## Deploy outline

1. Create a Cloudflare D1 database named `dll-lulz-licenses`.
2. Apply `worker/schema.sql` to that database.
3. Copy the database ID into `worker/wrangler.toml`.
4. From the `web/worker` directory, run `npx wrangler deploy`.
5. Deploy `web/site` as a Cloudflare Pages static site.
6. Set `API_BASE_URL` in `web/site/config.js` to the deployed Worker URL.

Cloudflare account authentication and deployment must be completed by the repository owner. Free-tier limits and availability can change; this is a prototype, not a production SLA.

## Test license creation

Generate a random key locally, calculate its SHA-256 hex digest, then insert only the digest into D1:

```sql
INSERT INTO licenses (key_hash, status, expires_at, max_devices)
VALUES ('<64-character-sha256-hex>', 'active', '2026-12-15T00:00:00Z', 1);
```

Do not put the plaintext key in SQL, source control, logs, or screenshots. The API accepts the plaintext key over HTTPS and compares its digest.

## API

- `GET /api/health` — service health.
- `POST /api/license/validate` — JSON body: `{"license_key":"..."}`.

The API returns validity and expiry only. Device activation, account login, payment processing, admin UI, and production abuse controls are not implemented yet.
