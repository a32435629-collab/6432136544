function corsHeaders(request, env) {
  const origin = request.headers.get("Origin");
  const allowed = env.ALLOWED_ORIGIN;
  const headers = {
    "access-control-allow-methods": "POST, GET, OPTIONS",
    "access-control-allow-headers": "Content-Type",
    "access-control-max-age": "86400",
    "vary": "Origin"
  };
  if (origin && allowed && origin === allowed) headers["access-control-allow-origin"] = origin;
  return headers;
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...headers, "content-type": "application/json; charset=utf-8", "cache-control": "no-store" }
  });
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
}

function validKeyFormat(value) {
  return typeof value === "string" && value.length >= 20 && value.length <= 160 &&
    /^[A-Za-z0-9-]+$/.test(value);
}

function validDeviceId(value) {
  return typeof value === "string" && /^[a-fA-F0-9-]{32,64}$/.test(value);
}

async function findActiveLicense(env, keyHash) {
  const row = await env.DB.prepare(
    "SELECT id, status, expires_at, max_devices FROM licenses WHERE key_hash = ? LIMIT 1"
  ).bind(keyHash).first();

  if (!row) return { error: "license_not_found" };
  if (row.status !== "active") return { error: "license_revoked" };
  const expiry = Date.parse(row.expires_at);
  if (!Number.isFinite(expiry) || expiry <= Date.now()) return { error: "license_expired" };
  return { row };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin");
    const headers = corsHeaders(request, env);

    if (origin && (!env.ALLOWED_ORIGIN || origin !== env.ALLOWED_ORIGIN)) {
      return json({ error: "Origin not allowed" }, 403);
    }
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers });
    if (request.method === "GET" && url.pathname === "/api/health") {
      return json({ ok: true, service: "dll-lulz-license-api", mode: "prototype" }, 200, headers);
    }
    if (request.method !== "POST" ||
        !["/api/license/validate", "/api/license/activate"].includes(url.pathname)) {
      return json({ error: "Not found" }, 404, headers);
    }
    if (!env.DB) return json({ error: "License database is not configured" }, 503, headers);

    let body;
    try { body = await request.json(); }
    catch { return json({ error: "Expected a JSON request body" }, 400, headers); }

    const licenseKey = body?.license_key;
    if (!validKeyFormat(licenseKey)) {
      return json({ valid: false, reason: "invalid_key_format" }, 400, headers);
    }

    try {
      const keyHash = await sha256Hex(licenseKey);
      const found = await findActiveLicense(env, keyHash);
      if (found.error) return json({ valid: false, reason: found.error }, 200, headers);
      const license = found.row;

      if (url.pathname === "/api/license/activate") {
        const deviceId = body?.device_id;
        if (!validDeviceId(deviceId)) {
          return json({ activated: false, reason: "invalid_device_id" }, 400, headers);
        }
        const deviceHash = await sha256Hex(deviceId.toLowerCase());
        try {
          await env.DB.prepare(
            "INSERT INTO license_devices (license_id, device_hash) VALUES (?, ?) ON CONFLICT(license_id, device_hash) DO NOTHING"
          ).bind(license.id, deviceHash).run();
        } catch (error) {
          if (String(error?.message || error).includes("device_limit_reached")) {
            return json({ activated: false, reason: "device_limit_reached" }, 200, headers);
          }
          throw error;
        }
        await env.DB.prepare(
          "UPDATE license_devices SET last_seen_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') WHERE license_id = ? AND device_hash = ?"
        ).bind(license.id, deviceHash).run();
        const count = await env.DB.prepare(
          "SELECT COUNT(*) AS count FROM license_devices WHERE license_id = ?"
        ).bind(license.id).first();
        return json({
          activated: true,
          expires_at: license.expires_at,
          devices_used: count?.count ?? 0,
          max_devices: license.max_devices
        }, 200, headers);
      }

      return json({
        valid: true,
        expires_at: license.expires_at,
        max_devices: license.max_devices
      }, 200, headers);
    } catch {
      return json({ error: "License service temporarily unavailable" }, 503, headers);
    }
  }
};
