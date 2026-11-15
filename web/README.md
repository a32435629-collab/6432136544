# DLL-LULZ-AI Web Licensing (MVP)

This folder contains the first, payment-free licensing prototype for DLL-LULZ-AI 0.7.0.

## Architecture

- `site/`: static landing page, suitable for Cloudflare Pages.
- `worker/`: Cloudflare Worker API.
- Cloudflare D1: stores SHA-256 hashes of license keys and expiry/status metadata.

The MVP intentionally does not collect payments, passwords, or personal data. Create test licenses manually in D1 until the validation flow is tested. Never commit real license keys, API tokens, or Cloudflare credentials.

## Deploy the API

1. Create a Cloudflare account and install Node.js LTS locally.
2. Install Wrangler: `npm install -g wrangler`.
3. Authenticate: `wrangler login`.
4. Create the D1 database: `wrangler d1 create dll-lulz-licenses`.
5. Copy the returned database ID into `worker/wrangler.toml`, replacing `REPLACE_WITH_YOUR_D1_DATABASE_ID`.
6. From this directory, run:
   ```powershell
   cd worker
   wrangler d1 execute dll-lulz-licenses --remote --file schema.sql
   wrangler secret put ALLOWED_ORIGIN
   ```
   When prompted for `ALLOWED_ORIGIN`, enter the exact HTTPS origin of the deployed Pages site, for example `https://dll-lulz-ai.pages.dev` (no trailing slash).
7. Deploy the Worker: `wrangler deploy`.
8. Test `https://<worker-name>.<account-subdomain>.workers.dev/api/health`.

## Deploy the website

1. In Cloudflare Pages, create a project connected to this GitHub repository.
2. Set the project root directory to `web/site`.
3. Use no build command; set the output directory to `/` (or leave the static root setting as recommended by Pages).
4. After Pages provides its HTTPS URL, open `site/config.js` and replace `https://YOUR-WORKER-URL` with the deployed Worker URL.
5. Commit the config change and redeploy Pages.

If the Pages hostname changes, update the Worker secret `ALLOWED_ORIGIN` to the new exact origin.

## Test license creation

Generate a random key locally and calculate its SHA-256 hex digest, then insert only the digest into D1:

```sql
INSERT INTO licenses (key_hash, status, expires_at, max_devices)
VALUES ('<64-character-sha256-hex>', 'active', '2026-12-15T00:00:00Z', 1);
```

Do not put the plaintext key in SQL, source control, logs, or screenshots. The API accepts the plaintext key over HTTPS and compares its digest.

## API

- `GET /api/health` — service health.
- `POST /api/license/validate` — JSON body: `{"license_key":"..."}`.

The API returns validity and expiry only. Device activation, account login, payment processing, admin UI, and production abuse controls are not implemented yet.
