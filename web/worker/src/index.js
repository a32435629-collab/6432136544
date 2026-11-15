function corsHeaders(request, env) {
  const origin = request.headers.get("Origin");
  const allowed = env.ALLOWED_ORIGIN;
  const headers = {
    "access-control-allow-methods": "POST, GET, OPTIONS",
    "access-control-allow-headers": "Content-Type",
    "access-control-max-age": "86400",
    "vary": "Origin"
  };
  if (origin && allowed && origin === allowed) {
    headers["access-control-allow-origin"] = origin;
  }
  return headers;
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...headers, "content-type": "application/json; charset=utf-8", "cache-control": "no-store" }
  });
}

async function sha256Hex(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
}

function validKeyFormat(value) {
  return typeof value === "string" && value.length >= 20 && value.length <= 160 &&
    /^[A-Za-z0-9-]+$/.test(value);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin");
    const headers = corsHeaders(request, env);

    if (origin && (!env.ALLOWED_ORIGIN || origin !== env.ALLOWED_ORIGIN)) {
      return json({ error: "Origin not allowed" }, 403);
    }

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers });
    }

    if (request.method === "GET" && url.pathname === "/api/health") {
      return json({ ok: true, service: "dll-lulz-license-api", mode: "prototype" }, 200, headers);
    }

    if (request.method !== "POST" || url.pathname !== "/api/license/validate") {
      return json({ error: "Not found" }, 404, headers);
    }

    if (!env.DB) {
      return json({ error: "License database is not configured" }, 503, headers);
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return json({ error: "Expected a JSON request body" }, 400, headers);
    }

    const licenseKey = body?.license_key;
    if (!validKeyFormat(licenseKey)) {
      return json({ valid: false, reason: "invalid_key_format" }, 400, headers);
    }

    try {
      const keyHash = await sha256Hex(licenseKey);
      const row = await env.DB.prepare(
        "SELECT status, expires_at, max_devices FROM licenses WHERE key_hash = ? LIMIT 1"
      ).bind(keyHash).first();

      if (!row) {
        return json({ valid: false, reason: "license_not_found" }, 200, headers);
      }

      const expiry = Date.parse(row.expires_at);
      if (row.status !== "active") {
        return json({ valid: false, reason: "license_revoked" }, 200, headers);
      }
      if (!Number.isFinite(expiry) || expiry <= Date.now()) {
        return json({ valid: false, reason: "license_expired" }, 200, headers);
      }

      return json({
        valid: true,
        expires_at: row.expires_at,
        max_devices: row.max_devices
      }, 200, headers);
    } catch {
      return json({ error: "License service temporarily unavailable" }, 503, headers);
    }
  }
};
