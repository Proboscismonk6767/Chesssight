// ChessSight API Worker — proxies image analysis to Gemini.
// Keeps the API key server-side, rate-limits per IP, validates input.

const MAX_REQUEST_BYTES   = 30 * 1024 * 1024;  // 30 MB hard cap
const RATE_LIMIT_PER_HOUR = 20;                 // anonymous users
const RATE_LIMIT_BURST    = 5;                  // per minute
const REQUEST_TIMEOUT_MS  = 60_000;             // 60s for video analyses

const ALLOWED_ORIGINS = [
  'https://chesssight.uk',
  'https://cs3-5zx.pages.dev'
];

export default {
  async fetch(request, env, ctx) {
    // ── CORS ─────────────────────────────────────────────────
    const origin = request.headers.get('Origin') || '';
    const corsHeaders = buildCorsHeaders(origin);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    if (request.method !== 'POST') {
      return json({ error: 'method_not_allowed' }, 405, corsHeaders);
    }

    // Reject requests not from an allowed origin (defense in depth — the
    // browser blocks them too, but a non-browser client wouldn't).
    if (!ALLOWED_ORIGINS.includes(origin)) {
      return json({ error: 'forbidden_origin' }, 403, corsHeaders);
    }

    // ── Rate limiting ────────────────────────────────────────
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const rl = await checkRateLimit(env.RATE_LIMIT_KV, ip);
    if (!rl.ok) {
      return json(
        { error: 'rate_limited', retry_after_seconds: rl.retryAfter },
        429,
        { ...corsHeaders, 'Retry-After': String(rl.retryAfter) }
      );
    }

    // ── Payload size guard (read header before reading body) ─
    const contentLength = parseInt(request.headers.get('Content-Length') || '0', 10);
    if (contentLength > MAX_REQUEST_BYTES) {
      return json({ error: 'payload_too_large' }, 413, corsHeaders);
    }

    // ── Body validation ──────────────────────────────────────
    let body;
    try {
      body = await request.json();
    } catch (_) {
      return json({ error: 'invalid_json' }, 400, corsHeaders);
    }
    const validation = validateBody(body);
    if (!validation.ok) {
      return json({ error: validation.reason }, 400, corsHeaders);
    }

    // ── Build Gemini request ─────────────────────────────────
    const geminiUrl =
      `https://generativelanguage.googleapis.com/v1beta/models/${env.GEMINI_MODEL}:generateContent`;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    let geminiRes;
    try {
      geminiRes = await fetch(`${geminiUrl}?key=${env.GEMINI_API_KEY}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: controller.signal
      });
    } catch (err) {
      clearTimeout(timeout);
      console.error('Gemini fetch failed:', err.name);
      return json({ error: 'upstream_unreachable' }, 502, corsHeaders);
    }
    clearTimeout(timeout);

    // ── Forward response, but strip any sensitive error details ──
    if (!geminiRes.ok) {
      // Log full error server-side, return generic status to client.
      const errBody = await geminiRes.text().catch(() => '');
      console.error('Gemini error', geminiRes.status, errBody.slice(0, 500));

      // Map upstream codes to safe client codes.
      const safeStatus =
        geminiRes.status === 400 ? 400 :
        geminiRes.status === 413 ? 413 :
        geminiRes.status === 429 ? 429 :
        geminiRes.status >= 500  ? 502 :
        500;
      return json({ error: 'upstream_error', upstream_status: safeStatus }, safeStatus, corsHeaders);
    }

    const data = await geminiRes.json();

    // Successful response: increment rate-limit counters AFTER success so a
    // failed call doesn't cost the user a quota slot.
    ctx.waitUntil(recordRateLimitHit(env.RATE_LIMIT_KV, ip));

    return json(data, 200, corsHeaders);
  }
};

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

function buildCorsHeaders(origin) {
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : '';
  return {
    'Access-Control-Allow-Origin':  allowed,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age':       '86400',
    'Vary':                         'Origin'
  };
}

function json(payload, status, extraHeaders = {}) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'X-Content-Type-Options': 'nosniff',
      ...extraHeaders
    }
  });
}

function validateBody(body) {
  if (!body || typeof body !== 'object')             return { ok: false, reason: 'body_not_object' };
  if (!body.contents || !Array.isArray(body.contents))  return { ok: false, reason: 'missing_contents' };
  if (body.contents.length !== 1)                       return { ok: false, reason: 'bad_contents_length' };

  const parts = body.contents[0]?.parts;
  if (!Array.isArray(parts) || parts.length === 0)      return { ok: false, reason: 'missing_parts' };
  if (parts.length > 12)                                return { ok: false, reason: 'too_many_parts' };

  // Whitelist mime types so a client can't send arbitrary attachment kinds.
  const ALLOWED_MIMES = new Set([
    'image/jpeg', 'image/png', 'image/webp', 'image/heic', 'image/heif',
    'video/mp4',  'video/quicktime', 'video/webm'
  ]);

  for (const p of parts) {
    if (p.text) continue; // input_type hint
    const mime = p.inlineData?.mimeType;
    const data = p.inlineData?.data;
    if (!mime || !data)                                 return { ok: false, reason: 'missing_inline_data' };
    if (!ALLOWED_MIMES.has(mime))                       return { ok: false, reason: 'mime_not_allowed' };
    if (typeof data !== 'string' || data.length > 30_000_000)
                                                        return { ok: false, reason: 'inline_data_too_large' };
  }
  return { ok: true };
}

// ── Rate limiting (token-bucket-ish via KV) ──────────────────

async function checkRateLimit(kv, ip) {
  const hourKey   = `rl:hour:${ip}:${Math.floor(Date.now() / 3600_000)}`;
  const minuteKey = `rl:min:${ip}:${Math.floor(Date.now() / 60_000)}`;

  const [hourCount, minCount] = await Promise.all([
    kv.get(hourKey).then(v => parseInt(v || '0', 10)),
    kv.get(minuteKey).then(v => parseInt(v || '0', 10))
  ]);

  if (minCount >= RATE_LIMIT_BURST) {
    return { ok: false, retryAfter: 60 };
  }
  if (hourCount >= RATE_LIMIT_PER_HOUR) {
    return { ok: false, retryAfter: 3600 - (Math.floor(Date.now() / 1000) % 3600) };
  }
  return { ok: true };
}

async function recordRateLimitHit(kv, ip) {
  const hourBucket   = Math.floor(Date.now() / 3600_000);
  const minuteBucket = Math.floor(Date.now() / 60_000);
  const hourKey   = `rl:hour:${ip}:${hourBucket}`;
  const minuteKey = `rl:min:${ip}:${minuteBucket}`;

  const [hourCount, minCount] = await Promise.all([
    kv.get(hourKey).then(v => parseInt(v || '0', 10)),
    kv.get(minuteKey).then(v => parseInt(v || '0', 10))
  ]);

  await Promise.all([
    kv.put(hourKey,   String(hourCount + 1), { expirationTtl: 3700 }),
    kv.put(minuteKey, String(minCount + 1),  { expirationTtl: 70 })
  ]);
}
