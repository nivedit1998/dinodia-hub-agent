const fs = require("fs");
const http = require("http");
const https = require("https");
const crypto = require("crypto");
const { WebSocketServer, WebSocket } = require("ws");

const OPTIONS_PATH = "/data/options.json";
const TOKEN_STATE_PATH = "/data/dinodia_token_state.json";

const DEFAULT_PAIR_ENDPOINT = "/api/hub-agent/pair";
const DEFAULT_TOKEN_STATE_ENDPOINT = "/api/hub-agent/token-state";

function sha256Hex(s) {
  return crypto.createHash("sha256").update(String(s || ""), "utf8").digest("hex");
}

function loadJsonFile(path) {
  try {
    return JSON.parse(fs.readFileSync(path, "utf8"));
  } catch {
    return null;
  }
}

function writeJsonFile(path, data) {
  try {
    fs.writeFileSync(path, JSON.stringify(data, null, 2));
  } catch {
    // ignore
  }
}

function loadOptions() {
  const defaults = {
    port: 8099,
    hub_tokens: [],
    hub_token_hashes: [],
    ws_auth_mode: "auto",
    ha_access_token: "",
    allowed_path_regex: [
      "^/api/?$",
      "^/api/states($|/.*)",
      "^/api/services/.*",
      "^/api/template$",
      "^/api/config.*",
      "^/api/camera_proxy/.*",
      "^/api/websocket$"
    ],
    log_level: "info",

    platform_sync_enabled: false,
    platform_base_url: "",
    platform_token_state_endpoint: DEFAULT_TOKEN_STATE_ENDPOINT,
    platform_sync_interval_minutes: 5,
    hub_agent_id: "",       // platform HubInstall.serial
    hub_agent_secret: ""    // bootstrap secret (printed/installer)
  };

  const parsed = loadJsonFile(OPTIONS_PATH);
  return { ...defaults, ...(parsed || {}) };
}

const opts = loadOptions();

const LOG_LEVELS = new Set(["trace", "debug", "info", "warn", "error"]);
const logLevel = LOG_LEVELS.has(opts.log_level) ? opts.log_level : "info";

function log(level, msg, extra) {
  const order = { trace: 10, debug: 20, info: 30, warn: 40, error: 50 };
  if (order[level] < order[logLevel]) return;
  const line = `[dinodia-hub-agent] ${level.toUpperCase()} ${msg}`;
  if (extra !== undefined) console.log(line, extra);
  else console.log(line);
}

const SUPERVISOR_TOKEN = process.env.SUPERVISOR_TOKEN || "";
if (!SUPERVISOR_TOKEN) {
  log("warn", "SUPERVISOR_TOKEN is missing; HTTP proxy to supervisor/core will fail.");
}

const allowedPathRegex = (Array.isArray(opts.allowed_path_regex) ? opts.allowed_path_regex : [])
  .map((s) => {
    try { return new RegExp(String(s)); } catch { return null; }
  })
  .filter(Boolean);

function isPathAllowed(pathname) {
  if (!allowedPathRegex.length) return false;
  return allowedPathRegex.some((re) => re.test(pathname));
}

function extractBearerTokenFromAuthHeader(value) {
  if (!value) return null;
  const m = String(value).match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
}

let syncedTokenHashes = new Set();
let agentSeenVersion = 0;
let syncSecret = "";

function loadSyncedStateFromDisk() {
  const state = loadJsonFile(TOKEN_STATE_PATH);
  if (!state || typeof state !== "object") return;

  const hashes = Array.isArray(state.hubTokenHashes) ? state.hubTokenHashes : [];
  const next = new Set();
  for (const h of hashes) {
    if (typeof h === "string" && h.trim()) next.add(h.trim().toLowerCase());
  }
  syncedTokenHashes = next;

  const v =
    Number.isFinite(state.agentSeenVersion) ? Number(state.agentSeenVersion) :
    Number.isFinite(state.latestVersion) ? Number(state.latestVersion) :
    Number.isFinite(state.version) ? Number(state.version) :
    0;
  agentSeenVersion = v;

  const ss = typeof state.syncSecret === "string" ? state.syncSecret.trim() : "";
  if (ss) syncSecret = ss;

  log("info", "Loaded cached token state", { agentSeenVersion, hashes: syncedTokenHashes.size, hasSyncSecret: Boolean(syncSecret) });
}

function persistSyncedState(extra = {}) {
  writeJsonFile(TOKEN_STATE_PATH, {
    agentSeenVersion,
    syncSecret,
    hubTokenHashes: Array.from(syncedTokenHashes),
    updatedAt: new Date().toISOString(),
    ...extra
  });
}

function isHubTokenValid(token) {
  const t = String(token || "").trim();
  if (!t) return false;

  // 1) Synced hashes (preferred)
  if (syncedTokenHashes.size > 0) {
    const h = sha256Hex(t);
    if (syncedTokenHashes.has(h)) return true;
  }

  // 2) Local plaintext tokens (fallback)
  const tokens = Array.isArray(opts.hub_tokens) ? opts.hub_tokens.map(String) : [];
  if (tokens.some((x) => x && x.trim() === t)) return true;

  // 3) Local hashes (fallback)
  const hashes = Array.isArray(opts.hub_token_hashes) ? opts.hub_token_hashes.map(String) : [];
  if (hashes.length > 0) {
    const h = sha256Hex(t);
    if (hashes.some((x) => x && x.trim().toLowerCase() === h)) return true;
  }

  return false;
}

function randomNonce() {
  return crypto.randomBytes(16).toString("hex");
}

function sign(serial, secret) {
  const ts = Math.floor(Date.now() / 1000);
  const nonce = randomNonce();
  const data = `${serial}.${ts}.${nonce}`;
  const sig = crypto.createHmac("sha256", secret).update(data, "utf8").digest("hex");
  return { serial, ts, nonce, sig };
}

async function postJson(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  const text = await res.text().catch(() => "");
  if (!res.ok) {
    throw new Error(`HTTP ${res.status}: ${text.slice(0, 200)}`);
  }
  const data = text ? JSON.parse(text) : null;
  return data;
}

function getPlatformBaseUrl() {
  return String(opts.platform_base_url || "").trim().replace(/\/+$/, "");
}

function getSerial() {
  return String(opts.hub_agent_id || "").trim();
}

function getBootstrapSecret() {
  return String(opts.hub_agent_secret || "").trim();
}

function isValidIpv4(ip) {
  const parts = String(ip || "").trim().split(".");
  if (parts.length !== 4) return false;
  for (const p of parts) {
    if (!/^\\d+$/.test(p)) return false;
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 255) return false;
  }
  return true;
}

function isPrivateIpv4(ip) {
  if (!isValidIpv4(ip)) return false;
  const [a, b] = ip.split(".").map((x) => Number(x));
  if (a === 10) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  return false;
}

function isBadLanCandidate(ip) {
  if (!isValidIpv4(ip)) return true;
  if (ip === "0.0.0.0") return true;
  if (ip.startsWith("127.")) return true;
  if (ip.startsWith("169.254.")) return true;
  return false;
}

function privateRank(ip) {
  if (!isValidIpv4(ip)) return 0;
  if (ip.startsWith("192.168.")) return 30;
  if (ip.startsWith("10.")) return 20;
  if (ip.startsWith("172.")) return 10;
  return 1;
}

function looksLikeDockerRange(ip) {
  // Heuristic only; will not block updates if this is the only private IP found.
  return (
    ip.startsWith("172.17.") ||
    ip.startsWith("172.18.") ||
    ip.startsWith("172.19.") ||
    ip.startsWith("172.30.")
  );
}

function collectIpv4Strings(value, out) {
  if (!value) return;
  if (typeof value === "string") {
    if (isValidIpv4(value)) out.push(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const v of value) collectIpv4Strings(v, out);
    return;
  }
  if (typeof value === "object") {
    // common shapes
    if (typeof value.address === "string") collectIpv4Strings(value.address, out);
    if (typeof value.ip === "string") collectIpv4Strings(value.ip, out);
    if (typeof value.ip_address === "string") collectIpv4Strings(value.ip_address, out);
    if (typeof value.local_ip === "string") collectIpv4Strings(value.local_ip, out);
    if (typeof value.localIp === "string") collectIpv4Strings(value.localIp, out);
  }
}

function pickBestLanIpv4FromSupervisorInfo(info) {
  const candidates = [];

  // Try structured interface parsing first
  const interfaces = info?.data?.interfaces || info?.interfaces;
  if (Array.isArray(interfaces)) {
    for (const iface of interfaces) {
      const ips = [];
      collectIpv4Strings(iface?.ipv4, ips);
      collectIpv4Strings(iface?.ipv4_addresses, ips);
      collectIpv4Strings(iface?.addr_info, ips);

      // Also look for nested arrays/objects
      collectIpv4Strings(iface?.ipv4?.address, ips);
      collectIpv4Strings(iface?.ipv4?.addresses, ips);

      const hasGateway = Boolean(
        iface?.gateway ||
        iface?.gateway_ipv4 ||
        iface?.gw4 ||
        iface?.ipv4?.gateway
      );

      for (const ip of ips) {
        if (isBadLanCandidate(ip)) continue;
        if (!isPrivateIpv4(ip)) continue;
        candidates.push({
          ip,
          score:
            privateRank(ip) +
            (hasGateway ? 100 : 0) +
            (looksLikeDockerRange(ip) ? -5 : 0)
        });
      }
    }
  }

  // Fallback: regex scan entire JSON if nothing found
  if (candidates.length === 0) {
    const text = (() => {
      try { return JSON.stringify(info); } catch { return ""; }
    })();
    const ips = text.match(/\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b/g) || [];
    for (const ip of ips) {
      if (isBadLanCandidate(ip)) continue;
      if (!isPrivateIpv4(ip)) continue;
      candidates.push({
        ip,
        score: privateRank(ip) + (looksLikeDockerRange(ip) ? -5 : 0)
      });
    }
  }

  if (candidates.length === 0) return null;
  candidates.sort((a, b) => b.score - a.score);
  return candidates[0].ip;
}

async function getLanBaseUrlFromSupervisor() {
  if (!SUPERVISOR_TOKEN) return null;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 2500);

  try {
    const res = await fetch("http://supervisor/network/info", {
      method: "GET",
      headers: {
        Authorization: `Bearer ${SUPERVISOR_TOKEN}`,
        "content-type": "application/json"
      },
      signal: controller.signal
    });

    const text = await res.text().catch(() => "");
    if (!res.ok) {
      log("debug", "Supervisor network/info failed", { status: res.status, body: text.slice(0, 120) });
      return null;
    }

    let info;
    try { info = text ? JSON.parse(text) : null; } catch { info = null; }
    const ip = pickBestLanIpv4FromSupervisorInfo(info);
    if (!ip) return null;

    return `http://${ip}:8123`;
  } catch (err) {
    log("debug", "Supervisor network/info error", String(err && err.message ? err.message : err));
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

async function ensurePaired() {
  if (syncSecret) return syncSecret;

  const base = getPlatformBaseUrl();
  const serial = getSerial();
  const bootstrap = getBootstrapSecret();

  if (!base || !serial || !bootstrap) {
    throw new Error("Platform sync requires platform_base_url, hub_agent_id (serial), and hub_agent_secret (bootstrap).");
  }

  const url = new URL(DEFAULT_PAIR_ENDPOINT, base);
  const payload = sign(serial, bootstrap);

  const data = await postJson(url, payload);
  const ss = data && typeof data.syncSecret === "string" ? data.syncSecret.trim() : "";
  if (!ss) throw new Error("Pair response missing syncSecret.");

  const hashes = Array.isArray(data.hubTokenHashes) ? data.hubTokenHashes : [];
  const next = new Set();
  for (const h of hashes) {
    if (typeof h === "string" && h.trim()) next.add(h.trim().toLowerCase());
  }
  if (next.size > 0) syncedTokenHashes = next;

  const latest = Number.isFinite(data.latestVersion) ? Number(data.latestVersion) : 0;
  agentSeenVersion = Math.max(agentSeenVersion, latest);
  syncSecret = ss;

  persistSyncedState({ pairedAt: new Date().toISOString() });
  log("info", "Paired with platform", { hashes: syncedTokenHashes.size, agentSeenVersion });
  return syncSecret;
}

async function syncFromPlatformOnce() {
  if (!opts.platform_sync_enabled) return;

  const base = getPlatformBaseUrl();
  if (!base) return;

  const serial = getSerial();
  if (!serial) return;

  try {
    const ss = await ensurePaired();
    const endpoint = String(opts.platform_token_state_endpoint || DEFAULT_TOKEN_STATE_ENDPOINT);
    const url = new URL(endpoint, base);

    const lanBaseUrl = await getLanBaseUrlFromSupervisor();

    const payload = { ...sign(serial, ss), agentSeenVersion };
    if (lanBaseUrl) payload.lanBaseUrl = lanBaseUrl;

    const data = await postJson(url, payload);

    const hashes = Array.isArray(data?.hubTokenHashes) ? data.hubTokenHashes : [];
    const next = new Set();
    for (const h of hashes) {
      if (typeof h === "string" && h.trim()) next.add(h.trim().toLowerCase());
    }
    if (next.size === 0) {
      log("warn", "Platform token-state returned zero hashes; ignoring");
      return;
    }

    const latest = Number.isFinite(data?.latestVersion) ? Number(data.latestVersion) : agentSeenVersion;
    syncedTokenHashes = next;
    agentSeenVersion = Math.max(agentSeenVersion, latest);

    persistSyncedState({
      lastSyncAt: new Date().toISOString(),
      publishedVersion: Number.isFinite(data?.publishedVersion) ? Number(data.publishedVersion) : null,
      latestVersion: Number.isFinite(data?.latestVersion) ? Number(data.latestVersion) : null,
      lanBaseUrl: lanBaseUrl || null
    });

    log("info", "Platform sync updated tokens", { hashes: syncedTokenHashes.size, agentSeenVersion, lanBaseUrl: lanBaseUrl || null });
  } catch (err) {
    log("warn", "Platform sync failed", String(err && err.message ? err.message : err));
  }
}

function schedulePlatformSyncLoop() {
  if (!opts.platform_sync_enabled) {
    log("info", "Platform sync disabled");
    return;
  }

  const mins = Number(opts.platform_sync_interval_minutes);
  const intervalMinutes = Number.isFinite(mins) && mins >= 2 ? mins : 2;

  const loop = async () => {
    await syncFromPlatformOnce();
    const jitter = Math.floor(Math.random() * 60 * 1000);
    const nextMs = intervalMinutes * 60 * 1000 + jitter;
    const t = setTimeout(loop, nextMs);
    if (t && typeof t.unref === "function") t.unref();
  };

  const firstDelay = 2000 + Math.floor(Math.random() * 4000);
  const t0 = setTimeout(loop, firstDelay);
  if (t0 && typeof t0.unref === "function") t0.unref();

  log("info", "Platform sync scheduled", { everyMinutes: intervalMinutes, jitterSeconds: 60 });
}

function writeJson(res, status, obj) {
  const body = Buffer.from(JSON.stringify(obj));
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": String(body.length)
  });
  res.end(body);
}

function sanitizeHopByHopHeaders(headers) {
  const hopByHop = new Set([
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade"
  ]);
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    if (!k) continue;
    if (hopByHop.has(String(k).toLowerCase())) continue;
    if (v === undefined) continue;
    out[k] = v;
  }
  return out;
}

function proxyHttpToSupervisorCore(req, res) {
  const clientUrl = new URL(req.url || "/", "http://localhost");
  const rawPath = clientUrl.pathname || "/";
  const clientPath = rawPath.replace(/\/{2,}/g, "/"); // normalize //api/... => /api/...

  if (!isPathAllowed(clientPath)) {
    return writeJson(res, 403, { error: "Path not allowed.", path: clientPath });
  }

  const clientToken = extractBearerTokenFromAuthHeader(req.headers.authorization);
  if (!isHubTokenValid(clientToken)) {
    return writeJson(res, 401, { error: "Unauthorized." });
  }

  const upstreamUrl = new URL(clientPath.replace(/^\\//, "") + clientUrl.search, "http://supervisor/core/");

  const upstreamHeaders = sanitizeHopByHopHeaders(req.headers);
  delete upstreamHeaders.host;
  upstreamHeaders["authorization"] = `Bearer ${SUPERVISOR_TOKEN}`;

  const lib = upstreamUrl.protocol === "https:" ? https : http;

  const upstreamReq = lib.request(
    upstreamUrl,
    { method: req.method, headers: upstreamHeaders },
    (upstreamRes) => {
      const outHeaders = sanitizeHopByHopHeaders(upstreamRes.headers);
      res.writeHead(upstreamRes.statusCode || 502, outHeaders);
      upstreamRes.pipe(res);
    }
  );

  upstreamReq.on("error", (err) => {
    log("warn", "Upstream HTTP error", String(err && err.message ? err.message : err));
    if (!res.headersSent) writeJson(res, 502, { error: "Upstream error." });
    else res.end();
  });

  req.pipe(upstreamReq);
}

const server = http.createServer((req, res) => {
  try {
    if (req.method === "GET" && req.url === "/_dinodia/sync-status") {
      return writeJson(res, 200, {
        ok: true,
        platformSyncEnabled: Boolean(opts.platform_sync_enabled),
        agentSeenVersion,
        hashes: syncedTokenHashes.size,
        hasSyncSecret: Boolean(syncSecret),
      });
    }

    if (!req.url || !req.url.startsWith("/")) return writeJson(res, 400, { error: "Bad request." });
    proxyHttpToSupervisorCore(req, res);
  } catch (err) {
    log("error", "Unhandled HTTP handler error", String(err && err.message ? err.message : err));
    writeJson(res, 500, { error: "Internal error." });
  }
});

const wss = new WebSocketServer({ noServer: true });

server.on("upgrade", (req, socket, head) => {
  try {
    const url = new URL(req.url, "http://localhost");
    const path = (url.pathname || "/").replace(/\\/{2,}/g, "/");
    if (path !== "/api/websocket") {
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (clientWs) => wss.emit("connection", clientWs, req));
  } catch {
    socket.destroy();
  }
});

function pickUpstreamAuthTokens() {
  const supervisor = SUPERVISOR_TOKEN;
  const ha = String(opts.ha_access_token || "").trim();
  const mode = String(opts.ws_auth_mode || "auto");

  if (mode === "supervisor") return [supervisor].filter(Boolean);
  if (mode === "ha") return [ha].filter(Boolean);
  return [supervisor, ha].filter(Boolean);
}

wss.on("connection", (clientWs) => {
  const upstreamUrl = "ws://supervisor/core/api/websocket";
  const upstreamWs = new WebSocket(upstreamUrl, {
    headers: SUPERVISOR_TOKEN ? { Authorization: `Bearer ${SUPERVISOR_TOKEN}` } : undefined
  });

  let clientAuthed = false;
  let hubTokenOk = false;

  let upstreamNeedsAuth = false;
  let upstreamAuthed = false;
  let authAttemptIndex = 0;
  const upstreamAuthTokens = pickUpstreamAuthTokens();

  const clientMsgBuffer = [];

  function sendToClient(obj) {
    if (clientWs.readyState !== WebSocket.OPEN) return;
    clientWs.send(JSON.stringify(obj));
  }

  function sendToUpstream(obj) {
    if (upstreamWs.readyState !== WebSocket.OPEN) return;
    upstreamWs.send(JSON.stringify(obj));
  }

  function tryAuthUpstream() {
    if (!upstreamNeedsAuth) return;
    if (!clientAuthed || !hubTokenOk) return;
    if (upstreamAuthed) return;

    const token = upstreamAuthTokens[authAttemptIndex] || "";
    if (!token) {
      sendToClient({ type: "auth_invalid", message: "Hub agent is missing HA auth token." });
      clientWs.close();
      upstreamWs.close();
      return;
    }
    sendToUpstream({ type: "auth", access_token: token });
  }

  upstreamWs.on("message", (data) => {
    let msg;
    try { msg = JSON.parse(String(data)); } catch { return; }

    if (msg && msg.type === "auth_required") {
      upstreamNeedsAuth = true;
      sendToClient(msg);
      tryAuthUpstream();
      return;
    }

    if (msg && msg.type === "auth_ok") {
      upstreamAuthed = true;
      sendToClient(msg);
      while (clientMsgBuffer.length) sendToUpstream(clientMsgBuffer.shift());
      return;
    }

    if (msg && msg.type === "auth_invalid") {
      if (!upstreamAuthed && authAttemptIndex + 1 < upstreamAuthTokens.length) {
        authAttemptIndex += 1;
        sendToClient(msg);
        tryAuthUpstream();
        return;
      }
      sendToClient(msg);
      clientWs.close();
      upstreamWs.close();
      return;
    }

    sendToClient(msg);
  });

  upstreamWs.on("close", () => {
    if (clientWs.readyState === WebSocket.OPEN) clientWs.close();
  });

  upstreamWs.on("error", () => {
    if (clientWs.readyState === WebSocket.OPEN) clientWs.close();
  });

  clientWs.on("message", (data) => {
    let msg;
    try { msg = JSON.parse(String(data)); } catch { return; }

    if (msg && msg.type === "auth") {
      clientAuthed = true;
      const presented = String(msg.access_token || "").trim();
      hubTokenOk = isHubTokenValid(presented);

      if (!hubTokenOk) {
        sendToClient({ type: "auth_invalid", message: "Invalid hub token." });
        clientWs.close();
        upstreamWs.close();
        return;
      }

      tryAuthUpstream();
      return;
    }

    if (!upstreamAuthed) {
      clientMsgBuffer.push(msg);
      return;
    }

    sendToUpstream(msg);
  });

  clientWs.on("close", () => {
    if (upstreamWs.readyState === WebSocket.OPEN) upstreamWs.close();
  });

  clientWs.on("error", () => {
    if (upstreamWs.readyState === WebSocket.OPEN) upstreamWs.close();
  });
});

loadSyncedStateFromDisk();
schedulePlatformSyncLoop();

server.listen(opts.port, "0.0.0.0", () => {
  log("info", `Listening on 0.0.0.0:${opts.port}`);
});
