const fs = require("fs");
const http = require("http");
const https = require("https");
const crypto = require("crypto");
const { WebSocketServer, WebSocket } = require("ws");

const OPTIONS_PATH = process.env.DINODIA_OPTIONS_PATH || "/data/options.json";
const TOKEN_STATE_PATH = process.env.DINODIA_TOKEN_STATE_PATH || "/data/dinodia_token_state.json";
const HEATING_USAGE_STATE_PATH_ENV = process.env.DINODIA_HEATING_USAGE_STATE_PATH || "";

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
    platform_sync_interval_minutes: 2,
    sync_status_token: "",
    hub_agent_id: "",       // platform HubInstall.serial
    hub_agent_secret: "",   // bootstrap secret (printed/installer)

    heating_usage_tracking_enabled: true,
    heating_usage_tracking_labels: ["Boiler", "Radiator"],
    heating_usage_persist_path: "/data/heating_usage_state.json",
    heating_usage_max_tracked_entities: 200,
    heating_usage_min_process_interval_ms: 1000,
    heating_usage_label_refresh_minutes: 30,
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

function getHeaderStringValue(headers, key) {
  const raw = headers && headers[key];
  if (Array.isArray(raw)) return raw[0] ? String(raw[0]) : "";
  return raw ? String(raw) : "";
}

function safeTokenEqual(a, b) {
  const aBuf = Buffer.from(String(a || ""), "utf8");
  const bBuf = Buffer.from(String(b || ""), "utf8");
  if (aBuf.length === 0 || bBuf.length === 0 || aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

function isSyncStatusAuthorized(req) {
  const requiredToken = String(opts.sync_status_token || "").trim();
  if (!requiredToken) return false; // disabled unless explicitly configured

  const url = new URL(req.url || "/", "http://localhost");
  const fromBearer = extractBearerTokenFromAuthHeader(getHeaderStringValue(req.headers, "authorization"));
  const fromHeader = getHeaderStringValue(req.headers, "x-dinodia-sync-status-token").trim();
  const fromQuery = (url.searchParams.get("token") || "").trim();
  const presented = fromBearer || fromHeader || fromQuery;
  return safeTokenEqual(requiredToken, presented);
}

let syncedTokenHashes = new Set();
let agentSeenVersion = 0;
let syncSecret = "";

const HEATING_SCHEMA_VERSION = 1;
const heatingUsageStatePath =
  String(HEATING_USAGE_STATE_PATH_ENV || opts.heating_usage_persist_path || "").trim() ||
  "/data/heating_usage_state.json";

let heatingUsageState = { schemaVersion: HEATING_SCHEMA_VERSION, updatedAt: null, entities: {} };
let heatingUsagePersistTimer = null;

function safeClampInt(n, min, max) {
  if (!Number.isFinite(n)) return null;
  const i = Math.floor(n);
  if (i < min) return min;
  if (i > max) return max;
  return i;
}

function readHeatingUsageStateFromDisk() {
  if (!opts.heating_usage_tracking_enabled) return;
  const state = loadJsonFile(heatingUsageStatePath);
  if (!state || typeof state !== "object") return;

  const schemaVersion = Number(state.schemaVersion);
  if (schemaVersion !== HEATING_SCHEMA_VERSION) return;

  const entities = state.entities && typeof state.entities === "object" ? state.entities : null;
  if (!entities) return;

  heatingUsageState = {
    schemaVersion: HEATING_SCHEMA_VERSION,
    updatedAt: typeof state.updatedAt === "string" ? state.updatedAt : null,
    entities
  };

  const count = Object.keys(heatingUsageState.entities || {}).length;
  log("info", "Loaded cached heating usage state", { entities: count, path: heatingUsageStatePath });
}

function schedulePersistHeatingUsageState() {
  if (!opts.heating_usage_tracking_enabled) return;
  if (heatingUsagePersistTimer) return;

  const delayMs = 15000;
  heatingUsagePersistTimer = setTimeout(() => {
    heatingUsagePersistTimer = null;
    try {
      heatingUsageState.updatedAt = new Date().toISOString();
      writeJsonFile(heatingUsageStatePath, heatingUsageState);
    } catch {
      // ignore
    }
  }, delayMs);

  if (heatingUsagePersistTimer && typeof heatingUsagePersistTimer.unref === "function") {
    heatingUsagePersistTimer.unref();
  }
}

function normalizeLabelName(label) {
  return String(label || "").trim().toLowerCase();
}

function parseFloatOrNull(value) {
  if (value === null || value === undefined) return null;
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(n)) return null;
  return n;
}

function getAttrNumber(attrs, keys) {
  if (!attrs || typeof attrs !== "object") return null;
  for (const k of keys) {
    if (!k) continue;
    if (Object.prototype.hasOwnProperty.call(attrs, k)) {
      const n = parseFloatOrNull(attrs[k]);
      if (n !== null) return n;
    }
  }
  return null;
}

function computeExplicitOff(state, attrs) {
  const s = String(state || "").trim().toLowerCase();
  if (s === "off") return true;
  const hvac = attrs && typeof attrs.hvac_mode === "string" ? attrs.hvac_mode.trim().toLowerCase() : "";
  return hvac === "off";
}

function computeIsOnNow({ current, target, explicitOff }) {
  if (target === null || current === null) return null;
  if (explicitOff) return false;
  return target > current;
}

function updateLocalAccumulator(entityId, label, observedAtIso, isOnNow, processedSnapshot) {
  if (!opts.heating_usage_tracking_enabled) return;

  const entities = heatingUsageState.entities || {};
  const existing = entities[entityId] && typeof entities[entityId] === "object" ? entities[entityId] : null;

  const observedAt = new Date(observedAtIso);
  if (Number.isNaN(observedAt.getTime())) return;

  if (!existing) {
    entities[entityId] = {
      label,
      onSeconds: 0,
      offSeconds: 0,
      lastSeenAt: observedAt.toISOString(),
      lastWasOn: isOnNow,
      dirty: true,
      lastProcessed: processedSnapshot || null,
      lastProcessedAt: observedAt.toISOString(),
    };
    heatingUsageState.entities = entities;
    schedulePersistHeatingUsageState();
    return;
  }

  const lastSeenAt = existing.lastSeenAt ? new Date(existing.lastSeenAt) : null;
  const prevSeenMs = lastSeenAt && !Number.isNaN(lastSeenAt.getTime()) ? lastSeenAt.getTime() : null;
  const nowMs = observedAt.getTime();
  const deltaSecondsRaw = prevSeenMs !== null ? Math.floor((nowMs - prevSeenMs) / 1000) : 0;

  // Guardrail: ignore backwards time; cap huge jumps (e.g. clock skew) to 24h.
  const deltaSeconds = safeClampInt(deltaSecondsRaw, 0, 24 * 60 * 60);

  let onSeconds = safeClampInt(Number(existing.onSeconds || 0), 0, Number.MAX_SAFE_INTEGER) || 0;
  let offSeconds = safeClampInt(Number(existing.offSeconds || 0), 0, Number.MAX_SAFE_INTEGER) || 0;

  const lastWasOn = existing.lastWasOn === true ? true : existing.lastWasOn === false ? false : null;
  if (deltaSeconds > 0) {
    if (lastWasOn === true) onSeconds += deltaSeconds;
    else if (lastWasOn === false) offSeconds += deltaSeconds;
  }

  const next = {
    ...existing,
    label,
    onSeconds,
    offSeconds,
    lastSeenAt: observedAt.toISOString(),
    lastWasOn: isOnNow,
    dirty: true,
    lastProcessed: processedSnapshot || existing.lastProcessed || null,
    lastProcessedAt: observedAt.toISOString(),
  };

  entities[entityId] = next;
  heatingUsageState.entities = entities;
  schedulePersistHeatingUsageState();
}

function listDirtyHeatingUsageDevices(maxDevices = 100) {
  if (!opts.heating_usage_tracking_enabled) return [];
  const entities = heatingUsageState.entities || {};
  const out = [];
  for (const [entityId, entry] of Object.entries(entities)) {
    if (!entry || typeof entry !== "object") continue;
    if (!entry.dirty) continue;
    if (!entry.label || !entry.lastSeenAt) continue;
    out.push({
      label: entry.label,
      entityId,
      onSeconds: Number(entry.onSeconds || 0),
      offSeconds: Number(entry.offSeconds || 0),
      lastSeenAt: entry.lastSeenAt,
      lastWasOn: entry.lastWasOn === true ? true : entry.lastWasOn === false ? false : null,
    });
    if (out.length >= maxDevices) break;
  }
  return out;
}

function clearDirtyHeatingUsageDevices(entityIds) {
  if (!opts.heating_usage_tracking_enabled) return;
  const entities = heatingUsageState.entities || {};
  let changed = false;
  for (const id of entityIds || []) {
    const entry = entities[id];
    if (!entry || typeof entry !== "object") continue;
    if (!entry.dirty) continue;
    entry.dirty = false;
    changed = true;
  }
  if (changed) schedulePersistHeatingUsageState();
}

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
    if (!/^\d+$/.test(p)) return false;
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
    ip.startsWith("172.19.")
  );
}

function collectIpv4Strings(value, out) {
  if (!value) return;
  if (typeof value === "string") {
    const candidate = value.includes("/") ? value.split("/")[0].trim() : value.trim();
    if (isValidIpv4(candidate)) out.push(candidate);
    return;
  }
  if (Array.isArray(value)) {
    for (const v of value) collectIpv4Strings(v, out);
    return;
  }
  if (typeof value === "object") {
    // common shapes
    if (typeof value.address === "string") collectIpv4Strings(value.address, out);
    if (Array.isArray(value.address)) {
      for (const v of value.address) collectIpv4Strings(v, out);
    }
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
    const primary = interfaces.find((i) => i?.primary === true);
    const primaryAddr = primary?.ipv4?.address;
    if (Array.isArray(primaryAddr) && primaryAddr.length > 0) {
      const first = String(primaryAddr[0] || "").split("/")[0].trim();
      if (isValidIpv4(first)) {
        return first;
      }
    }

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

      // Prefer the first structured private IP immediately if present.
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
    const ips = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
    if (ips.length > 0) {
      // Ultra-simple: take the first match.
      return ips[0];
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
      return null;
    }

    let info;
    try { info = text ? JSON.parse(text) : null; } catch { info = null; }
    const ip = pickBestLanIpv4FromSupervisorInfo(info);
    if (!ip) return null;

    return `http://${ip}:8123`;
  } catch (err) {
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

    const dirtyDevices = listDirtyHeatingUsageDevices(100);
    if (dirtyDevices.length > 0) {
      payload.heatingUsage = {
        schemaVersion: HEATING_SCHEMA_VERSION,
        capturedAt: new Date().toISOString(),
        devices: dirtyDevices,
      };
    }

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
    });

    if (dirtyDevices.length > 0) {
      clearDirtyHeatingUsageDevices(dirtyDevices.map((d) => d.entityId));
    }

    log("info", "Platform sync updated tokens", { hashes: syncedTokenHashes.size, agentSeenVersion });
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

  const upstreamUrl = new URL(clientPath.replace(/^\/+/, "") + clientUrl.search, "http://supervisor/core/");

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

async function getStateFromSupervisor(entityId) {
  const id = String(entityId || "").trim();
  if (!id) return null;
  if (!SUPERVISOR_TOKEN) return null;
  try {
    const url = `http://supervisor/core/api/states/${encodeURIComponent(id)}`;
    const res = await fetch(url, {
      method: "GET",
      headers: { authorization: `Bearer ${SUPERVISOR_TOKEN}` },
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

const server = http.createServer((req, res) => {
  try {
    const url = new URL(req.url || "/", "http://localhost");
    if (req.method === "GET" && url.pathname === "/_dinodia/sync-status") {
      if (!isSyncStatusAuthorized(req)) {
        return writeJson(res, 404, { error: "Not found." });
      }
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
    const path = (url.pathname || "/").replace(/\/{2,}/g, "/");
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

function startHeatingUsageTracker() {
  if (!opts.heating_usage_tracking_enabled) {
    log("info", "Heating usage tracking disabled");
    return;
  }

  const wantedLabelsRaw = Array.isArray(opts.heating_usage_tracking_labels) ? opts.heating_usage_tracking_labels : ["Boiler", "Radiator"];
  const wantedLabels = wantedLabelsRaw.map(normalizeLabelName).filter(Boolean);
  const maxTracked = Number(opts.heating_usage_max_tracked_entities);
  const maxTrackedEntities = Number.isFinite(maxTracked) && maxTracked > 0 ? Math.floor(maxTracked) : 200;
  const minProcMs = Number(opts.heating_usage_min_process_interval_ms);
  const minProcessIntervalMs = Number.isFinite(minProcMs) && minProcMs >= 0 ? Math.floor(minProcMs) : 1000;
  const refreshMins = Number(opts.heating_usage_label_refresh_minutes);
  const refreshEveryMs = (Number.isFinite(refreshMins) && refreshMins > 0 ? refreshMins : 30) * 60 * 1000;

  const upstreamUrl = "ws://supervisor/core/api/websocket";
  const upstreamAuthTokens = pickUpstreamAuthTokens();

  let ws = null;
  let reconnectTimer = null;
  let authAttemptIndex = 0;
  let upstreamAuthed = false;
  let upstreamNeedsAuth = false;

  let nextId = 1000;
  const pending = new Map(); // id -> { resolve, reject, timeout }

  let entityLabelById = new Map(); // entity_id -> "Boiler" | "Radiator"
  const entityLastProcessedAtMs = new Map(); // entity_id -> epoch ms
  let lastRegistryRefreshAtMs = 0;

  function clearPending(err) {
    for (const [id, p] of pending.entries()) {
      pending.delete(id);
      try { clearTimeout(p.timeout); } catch {}
      try { p.reject(err); } catch {}
    }
  }

  function send(obj) {
    if (!ws || ws.readyState !== WebSocket.OPEN) return false;
    ws.send(JSON.stringify(obj));
    return true;
  }

  function request(type, payload) {
    const id = nextId++;
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        pending.delete(id);
        reject(new Error(`HA WS timeout waiting for ${type}`));
      }, 15000);

      pending.set(id, { resolve, reject, timeout });
      const ok = send({ id, type, ...(payload || {}) });
      if (!ok) {
        pending.delete(id);
        clearTimeout(timeout);
        reject(new Error("HA WS not connected"));
      }
    });
  }

  function tryAuthUpstream() {
    if (!upstreamNeedsAuth) return;
    if (upstreamAuthed) return;
    const token = upstreamAuthTokens[authAttemptIndex] || "";
    if (!token) {
      log("warn", "Heating usage WS auth failed: no HA auth token available");
      if (ws) ws.close();
      return;
    }
    send({ type: "auth", access_token: token });
  }

  async function refreshLabelEntityRegistryIfNeeded(force = false) {
    if (!upstreamAuthed) return;
    const nowMs = Date.now();
    if (!force && nowMs - lastRegistryRefreshAtMs < refreshEveryMs) return;
    lastRegistryRefreshAtMs = nowMs;

    try {
      const labelsResp = await request("config/label_registry/list");
      const labels = Array.isArray(labelsResp?.result) ? labelsResp.result : [];
      const labelIdByNameLower = new Map();
      for (const row of labels) {
        if (!row || typeof row !== "object") continue;
        const name = normalizeLabelName(row.name);
        const id = typeof row.label_id === "string" ? row.label_id.trim() : "";
        if (name && id) labelIdByNameLower.set(name, id);
      }

      const wantedLabelIds = new Map(); // labelId -> "Boiler"|"Radiator"
      for (const wanted of wantedLabels) {
        const id = labelIdByNameLower.get(wanted);
        if (!id) continue;
        // Keep original casing for payload label field ("Boiler"/"Radiator") by title-casing known labels.
        if (wanted === "boiler") wantedLabelIds.set(id, "Boiler");
        if (wanted === "radiator") wantedLabelIds.set(id, "Radiator");
      }

      if (wantedLabelIds.size === 0) {
        entityLabelById = new Map();
        log("warn", "Heating usage label registry returned no matching labels", { wanted: wantedLabelsRaw });
        return;
      }

      const entitiesResp = await request("config/entity_registry/list_for_display");
      const entities = Array.isArray(entitiesResp?.result?.entities) ? entitiesResp.result.entities : [];

      const next = new Map();
      for (const row of entities) {
        if (!row || typeof row !== "object") continue;
        const entityId = typeof row.ei === "string" ? row.ei.trim() : "";
        if (!entityId) continue;
        const lbs = Array.isArray(row.lb) ? row.lb : [];
        for (const lb of lbs) {
          const label = wantedLabelIds.get(String(lb || "").trim());
          if (label) {
            next.set(entityId, label);
            break;
          }
        }
        if (next.size >= maxTrackedEntities) break;
      }

      entityLabelById = next;
      log("info", "Heating usage label registry refreshed", { entities: entityLabelById.size });
    } catch (err) {
      log("warn", "Heating usage label registry refresh failed", String(err && err.message ? err.message : err));
    }
  }

  function extractHeatingSnapshot(newState) {
    const state = newState && typeof newState.state === "string" ? newState.state : "";
    const attrs = newState && typeof newState.attributes === "object" ? newState.attributes : null;
    const hvacMode = attrs && typeof attrs.hvac_mode === "string" ? attrs.hvac_mode : "";

    const current = getAttrNumber(attrs, ["current_temperature", "current_temp", "currentTemperature"]);
    const target = getAttrNumber(attrs, [
      "temperature",
      "target_temperature",
      "target_temp",
      "targetTemperature",
      "target_temp_low",
      "target_temp_high",
    ]);

    return {
      state: String(state || ""),
      hvac_mode: String(hvacMode || ""),
      current,
      target,
      attrs,
    };
  }

  function isSameProcessedSnapshot(a, b) {
    if (!a || !b) return false;
    return (
      String(a.state || "") === String(b.state || "") &&
      String(a.hvac_mode || "") === String(b.hvac_mode || "") &&
      (a.current === null ? null : Number(a.current)) === (b.current === null ? null : Number(b.current)) &&
      (a.target === null ? null : Number(a.target)) === (b.target === null ? null : Number(b.target))
    );
  }

  function handleStateChangedEvent(event) {
    const entityId = event?.data?.entity_id;
    if (typeof entityId !== "string" || !entityId.trim()) return;
    const label = entityLabelById.get(entityId);
    if (!label) return;

    const nowMs = Date.now();
    const lastMs = entityLastProcessedAtMs.get(entityId) || 0;
    if (minProcessIntervalMs > 0 && nowMs - lastMs < minProcessIntervalMs) return;
    entityLastProcessedAtMs.set(entityId, nowMs);

    const newState = event?.data?.new_state;
    if (!newState || typeof newState !== "object") return;

    const observedAtIso =
      typeof event.time_fired === "string" && event.time_fired ? event.time_fired :
      typeof event?.data?.new_state?.last_updated === "string" && event.data.new_state.last_updated ? event.data.new_state.last_updated :
      new Date().toISOString();

    const snapshot = extractHeatingSnapshot(newState);
    const processedSnapshot = {
      state: snapshot.state,
      hvac_mode: snapshot.hvac_mode,
      current: snapshot.current,
      target: snapshot.target,
    };

    const existing = heatingUsageState.entities && heatingUsageState.entities[entityId];
    const lastProcessed = existing && typeof existing === "object" ? existing.lastProcessed : null;
    if (isSameProcessedSnapshot(lastProcessed, processedSnapshot)) return;

    const explicitOff = computeExplicitOff(snapshot.state, snapshot.attrs || {});
    const isOnNow = computeIsOnNow({ current: snapshot.current, target: snapshot.target, explicitOff });

    updateLocalAccumulator(entityId, label, observedAtIso, isOnNow, processedSnapshot);
  }

  function startSubscriptions() {
    const kick = async () => {
      await refreshLabelEntityRegistryIfNeeded(true);

      // Seed current state once so platform tables populate immediately after install/upgrade,
      // even before the first state_changed event arrives.
      const initialEntries = Array.from(entityLabelById.entries());
      if (initialEntries.length > 0) {
        const CONCURRENCY = 4;
        let idx = 0;

        const worker = async () => {
          while (idx < initialEntries.length) {
            const cur = idx++;
            const [entityId, label] = initialEntries[cur];

            // Only seed entities that don't exist yet locally (avoids extra sends on restart).
            const existing = heatingUsageState.entities && heatingUsageState.entities[entityId];
            if (existing && typeof existing === "object") continue;

            const state = await getStateFromSupervisor(entityId);
            if (!state || typeof state !== "object") continue;

            const observedAtIso =
              typeof state.last_updated === "string" && state.last_updated ? state.last_updated :
              typeof state.last_changed === "string" && state.last_changed ? state.last_changed :
              new Date().toISOString();

            const snapshot = extractHeatingSnapshot(state);
            const processedSnapshot = {
              state: snapshot.state,
              hvac_mode: snapshot.hvac_mode,
              current: snapshot.current,
              target: snapshot.target,
            };

            const explicitOff = computeExplicitOff(snapshot.state, snapshot.attrs || {});
            const isOnNow = computeIsOnNow({ current: snapshot.current, target: snapshot.target, explicitOff });

            updateLocalAccumulator(entityId, label, observedAtIso, isOnNow, processedSnapshot);
          }
        };

        await Promise.all(Array.from({ length: CONCURRENCY }, () => worker()));
        log("info", "Heating usage seeded initial entity states", { entities: initialEntries.length });
      }

      // Subscribe to state changes (we filter locally by labeled entity id).
      await request("subscribe_events", { event_type: "state_changed" });
    };

    kick().catch((err) => {
      log("warn", "Heating usage startup failed", String(err && err.message ? err.message : err));
    });

    const refreshLoop = () => {
      refreshLabelEntityRegistryIfNeeded(false).catch(() => {});
      const t = setTimeout(refreshLoop, refreshEveryMs);
      if (t && typeof t.unref === "function") t.unref();
    };
    const t0 = setTimeout(refreshLoop, 10000);
    if (t0 && typeof t0.unref === "function") t0.unref();
  }

  function scheduleReconnect() {
    if (reconnectTimer) return;
    const delayMs = 2000 + Math.floor(Math.random() * 3000) + Math.min(30000, authAttemptIndex * 2000);
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      connect();
    }, delayMs);
    if (reconnectTimer && typeof reconnectTimer.unref === "function") reconnectTimer.unref();
  }

  function connect() {
    upstreamAuthed = false;
    upstreamNeedsAuth = false;
    clearPending(new Error("HA WS disconnected"));

    try {
      ws = new WebSocket(upstreamUrl, {
        headers: SUPERVISOR_TOKEN ? { Authorization: `Bearer ${SUPERVISOR_TOKEN}` } : undefined
      });
    } catch (err) {
      log("warn", "Heating usage WS connect failed", String(err && err.message ? err.message : err));
      scheduleReconnect();
      return;
    }

    ws.on("message", (data) => {
      let msg;
      try { msg = JSON.parse(String(data)); } catch { return; }

      if (msg && msg.type === "auth_required") {
        upstreamNeedsAuth = true;
        tryAuthUpstream();
        return;
      }

    if (msg && msg.type === "auth_ok") {
      upstreamAuthed = true;
      startSubscriptions();
      return;
    }

      if (msg && msg.type === "auth_invalid") {
        if (!upstreamAuthed && authAttemptIndex + 1 < upstreamAuthTokens.length) {
          authAttemptIndex += 1;
          tryAuthUpstream();
          return;
        }
        log("warn", "Heating usage WS auth_invalid", msg);
        try { ws.close(); } catch {}
        return;
      }

      if (msg && msg.type === "result" && typeof msg.id === "number") {
        const p = pending.get(msg.id);
        if (p) {
          pending.delete(msg.id);
          try { clearTimeout(p.timeout); } catch {}
          if (msg.success) p.resolve(msg);
          else p.reject(new Error((msg.error && msg.error.message) || "HA WS request failed"));
        }
        return;
      }

      if (msg && msg.type === "event" && msg.event && msg.event.event_type === "state_changed") {
        handleStateChangedEvent(msg.event);
        return;
      }
    });

    ws.on("close", () => {
      scheduleReconnect();
    });

    ws.on("error", () => {
      scheduleReconnect();
    });
  }

  readHeatingUsageStateFromDisk();
  connect();
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
startHeatingUsageTracker();
schedulePlatformSyncLoop();

server.listen(opts.port, "0.0.0.0", () => {
  log("info", "Listening", { port: opts.port });
});
