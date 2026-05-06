/**
 * Project VANGUARD — Cloudflare Worker
 *
 * Deploys VANGUARD's lightweight edge inspection layer as a Cloudflare Worker.
 * This Worker performs fast heuristic checks at the CDN edge before forwarding
 * clean requests to the full VANGUARD proxy (or directly to your origin).
 *
 * Checks performed at the Cloudflare edge (zero-latency):
 *   1. IP reputation (Cloudflare Threat Score)
 *   2. Bot detection via User-Agent and header heuristics
 *   3. SQL / XSS / path-traversal pattern matching
 *   4. Request rate limiting per IP
 *   5. Geo-blocking for specified regions (optional)
 *
 * For deep ML-based inspection, requests are forwarded to the VANGUARD proxy
 * running on your origin infrastructure.
 *
 * Deploy:
 *   wrangler deploy
 */

// ─── Configuration ─────────────────────────────────────────────────────────
const CONFIG = {
  // URL of your full VANGUARD proxy (or origin if not using a proxy)
  ORIGIN: "https://your-origin.example.com",

  // Maximum requests per IP per minute (edge-level rate limiting)
  RATE_LIMIT_RPM: 500,

  // Optional: ISO 3166-1 alpha-2 country codes to block
  BLOCKED_COUNTRIES: [],

  // Paths that bypass all VANGUARD checks (e.g. static assets)
  BYPASS_PATHS: ["/favicon.ico", "/robots.txt"],
};

// ─── In-memory rate limit store (resets per Worker isolate) ────────────────
const rateLimitStore = new Map();

function getRateLimit(ip) {
  const now = Date.now();
  const windowMs = 60_000;
  const entry = rateLimitStore.get(ip) || { count: 0, windowStart: now };

  if (now - entry.windowStart > windowMs) {
    entry.count = 0;
    entry.windowStart = now;
  }
  entry.count += 1;
  rateLimitStore.set(ip, entry);
  return entry.count;
}

// ─── Signature patterns ────────────────────────────────────────────────────
const SQL_PATTERN = /(\bOR\b\s+[\w'"]+\s*=\s*[\w'"]+|UNION\s+SELECT|DROP\s+TABLE|--\s*$|\/\*.*\*\/|SLEEP\s*\(|WAITFOR\s+DELAY)/i;
const XSS_PATTERN = /(<script|javascript:|onerror=|onload=|<svg\s+onload|<img\s+src=x)/i;
const TRAVERSAL_PATTERN = /(\.\.\/)|(\.\.\\)|(%2e%2e)/i;
const CMD_INJECTION_PATTERN = /([|;&`$]\s*(ls|cat|rm|wget|curl|nc|bash|sh|python|perl|ruby))/i;
const BOT_UA_PATTERN = /^(python-requests|curl|wget|scrapy|go-http|java\/|libwww|zgrab|masscan|nmap|nikto|sqlmap|dirbuster)/i;

// ─── Header anomaly checks ─────────────────────────────────────────────────
function isSuspiciousHeaders(request) {
  const ua = request.headers.get("User-Agent") || "";
  const accept = request.headers.get("Accept");

  // Missing User-Agent
  if (!ua) return { suspicious: true, reason: "Missing User-Agent" };

  // Known attack tool User-Agent
  if (BOT_UA_PATTERN.test(ua)) {
    return { suspicious: true, reason: `Attack tool UA: ${ua.substring(0, 50)}` };
  }

  // Missing Accept header (common in automated requests)
  if (!accept) {
    return { suspicious: true, reason: "Missing Accept header" };
  }

  return { suspicious: false, reason: "" };
}

// ─── URL inspection ────────────────────────────────────────────────────────
function inspectUrl(url) {
  const fullUrl = url.pathname + "?" + url.searchParams.toString();

  if (SQL_PATTERN.test(fullUrl)) return { blocked: true, reason: "SQL injection pattern" };
  if (XSS_PATTERN.test(fullUrl)) return { blocked: true, reason: "XSS pattern" };
  if (TRAVERSAL_PATTERN.test(fullUrl)) return { blocked: true, reason: "Path traversal pattern" };
  if (CMD_INJECTION_PATTERN.test(fullUrl)) return { blocked: true, reason: "Command injection pattern" };

  return { blocked: false, reason: "" };
}

// ─── Response helpers ──────────────────────────────────────────────────────
function blockResponse(reason, status = 403) {
  return new Response(`Forbidden — ${reason}`, {
    status,
    headers: {
      "Content-Type": "text/plain",
      "X-VANGUARD-Block-Reason": reason.substring(0, 200),
      "X-VANGUARD-Edge": "cloudflare",
    },
  });
}

function rateLimitResponse() {
  return new Response("Too Many Requests", {
    status: 429,
    headers: {
      "Content-Type": "text/plain",
      "Retry-After": "60",
      "X-VANGUARD-Edge": "cloudflare",
    },
  });
}

// ─── Main handler ──────────────────────────────────────────────────────────
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const clientIP = request.headers.get("CF-Connecting-IP") || "unknown";
    const cfThreatScore = parseInt(request.headers.get("CF-Threat-Score") || "0", 10);

    // Bypass check for static assets
    if (CONFIG.BYPASS_PATHS.some((p) => url.pathname.startsWith(p))) {
      return fetch(new Request(CONFIG.ORIGIN + url.pathname + url.search, request));
    }

    // ── Geo-blocking ───────────────────────────────────────────────────────
    const country = request.headers.get("CF-IPCountry") || "";
    if (CONFIG.BLOCKED_COUNTRIES.length > 0 && CONFIG.BLOCKED_COUNTRIES.includes(country)) {
      return blockResponse(`Region blocked: ${country}`);
    }

    // ── Cloudflare Threat Score ────────────────────────────────────────────
    if (cfThreatScore > 50) {
      return blockResponse(`High threat score: ${cfThreatScore}`);
    }

    // ── Rate limiting ──────────────────────────────────────────────────────
    const requestCount = getRateLimit(clientIP);
    if (requestCount > CONFIG.RATE_LIMIT_RPM) {
      return rateLimitResponse();
    }

    // ── Header inspection ──────────────────────────────────────────────────
    const headerCheck = isSuspiciousHeaders(request);
    if (headerCheck.suspicious) {
      // Soft block: challenge rather than hard block for header anomalies
      return blockResponse(headerCheck.reason, 429);
    }

    // ── URL inspection ─────────────────────────────────────────────────────
    const urlCheck = inspectUrl(url);
    if (urlCheck.blocked) {
      return blockResponse(urlCheck.reason);
    }

    // ── Forward to VANGUARD / origin ───────────────────────────────────────
    const originUrl = CONFIG.ORIGIN + url.pathname + url.search;
    const originRequest = new Request(originUrl, {
      method: request.method,
      headers: request.headers,
      body: request.method !== "GET" && request.method !== "HEAD"
        ? request.body
        : undefined,
    });

    try {
      const response = await fetch(originRequest);
      const newResponse = new Response(response.body, response);
      newResponse.headers.set("X-VANGUARD-Edge", "cloudflare");
      return newResponse;
    } catch (err) {
      return new Response("Bad Gateway", { status: 502 });
    }
  },
};
