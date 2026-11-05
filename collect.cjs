var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// scripts/collect-configs.ts
var collect_configs_exports = {};
__export(collect_configs_exports, {
  linksInChannelPage: () => linksInChannelPage,
  withName: () => withName
});
module.exports = __toCommonJS(collect_configs_exports);
var import_node_fs4 = require("node:fs");
var import_node_os3 = require("node:os");
var import_node_path3 = require("node:path");

// src/main/core.ts
var import_node_child_process3 = require("node:child_process");
var import_node_crypto4 = require("node:crypto");
var import_node_events = require("node:events");
var import_node_fs3 = require("node:fs");
var import_node_path2 = require("node:path");

// src/main/config.ts
var import_node_fs = require("node:fs");
var import_node_path = require("node:path");

// src/main/parser.ts
var import_node_crypto2 = require("node:crypto");

// src/main/configfile.ts
var b64 = (s) => Buffer.from(s, "utf8").toString("base64");
var str = (v) => v === void 0 || v === null || v === "" ? void 0 : String(v);
var alpnText = (v) => Array.isArray(v) ? v.join(",") : str(v);
var earlyData = (path, ms) => Number(ms) > 0 && path && !/[?&]ed=/.test(path) ? `${path}${path.includes("?") ? "&" : "?"}ed=${ms}` : path;
function toLink(p) {
  if (p.scheme === "vmess") {
    return `vmess://${b64(
      JSON.stringify({ v: "2", ps: p.name, add: p.host, port: p.port, id: p.user, aid: 0, scy: p.cipher ?? "auto", net: p.network ?? "tcp", type: "none", host: p.hostHeader ?? "", path: p.path ?? p.serviceName ?? "", tls: p.security === "tls" ? "tls" : "", sni: p.sni ?? "", alpn: p.alpn ?? "", fp: p.fp ?? "" })
    )}`;
  }
  const params = new URLSearchParams();
  const add = (k, v) => v && params.append(k, v);
  if (p.scheme === "vless") add("encryption", p.encryption ?? "none");
  add("type", p.network ?? "tcp");
  add("security", p.security ?? "none");
  add("host", p.hostHeader);
  add("path", p.path);
  add("serviceName", p.serviceName);
  add("mode", p.mode);
  add("sni", p.sni);
  add("fp", p.fp);
  add("alpn", p.alpn);
  add("allowInsecure", p.insecure ? "1" : void 0);
  add("pbk", p.pbk);
  add("sid", p.sid);
  add("spx", p.spx);
  add("flow", p.flow);
  add("fm", p.finalmask);
  const host = p.host.includes(":") ? `[${p.host}]` : p.host;
  return `${p.scheme}://${encodeURIComponent(p.user)}@${host}:${p.port}?${params}#${encodeURIComponent(p.name)}`;
}
var ssLink = (method, password, host, port, name) => `ss://${b64(`${method}:${password}`)}@${host.includes(":") ? `[${host}]` : host}:${port}#${encodeURIComponent(name)}`;
function dialerFinalmask(outbound, all) {
  const tag = outbound.streamSettings?.sockopt?.dialerProxy;
  if (!tag) return void 0;
  const fragment = all.find((o) => o.tag === tag)?.settings?.fragment;
  if (!fragment) return null;
  return JSON.stringify({ tcp: [{ type: "fragment", settings: { packets: fragment.packets, length: fragment.length, delay: fragment.interval } }] });
}
function fromXrayOutbound(o, all, name) {
  const dialed = dialerFinalmask(o, all);
  if (dialed === null) return void 0;
  const s = o.settings ?? {};
  const st = o.streamSettings ?? {};
  const target = s.vnext?.[0] ?? s.servers?.[0] ?? s;
  const user = target.users?.[0] ?? target;
  const host = str(target.address);
  const port = Number(target.port);
  if (!host || !port) return void 0;
  if (o.protocol === "shadowsocks") return user.method && user.password ? ssLink(user.method, user.password, host, port, name) : void 0;
  if (o.protocol !== "vless" && o.protocol !== "vmess" && o.protocol !== "trojan") return void 0;
  const credential = str(o.protocol === "trojan" ? user.password : user.id);
  if (!credential) return void 0;
  const network = str(st.network ?? st.method) ?? "tcp";
  const transport = st.wsSettings ?? st.httpupgradeSettings ?? st.xhttpSettings ?? st.splithttpSettings ?? {};
  const tls = st.tlsSettings ?? {};
  const reality = st.realitySettings ?? {};
  return toLink({
    scheme: o.protocol,
    user: credential,
    host,
    port,
    name,
    network: network === "raw" ? "tcp" : network === "websocket" ? "ws" : network,
    path: str(transport.path),
    hostHeader: str(transport.host ?? transport.headers?.Host),
    serviceName: str(st.grpcSettings?.serviceName),
    mode: str(transport.mode),
    security: str(st.security),
    sni: str(tls.serverName ?? reality.serverName),
    fp: str(tls.fingerprint ?? reality.fingerprint),
    alpn: alpnText(tls.alpn),
    insecure: !!tls.allowInsecure,
    pbk: str(reality.password ?? reality.publicKey),
    sid: str(reality.shortId),
    spx: str(reality.spiderX),
    flow: str(user.flow),
    encryption: str(user.encryption),
    cipher: str(user.security),
    finalmask: st.finalmask ? JSON.stringify(st.finalmask) : dialed ?? void 0
  });
}
function fromSingBoxOutbound(o) {
  const host = str(o.server);
  const port = Number(o.server_port);
  const name = str(o.tag) ?? `${host}:${port}`;
  if (!host || !port) return void 0;
  if (o.type === "shadowsocks") return o.method && o.password ? ssLink(o.method, o.password, host, port, name) : void 0;
  if (o.type !== "vless" && o.type !== "vmess" && o.type !== "trojan") return void 0;
  const credential = str(o.type === "trojan" ? o.password : o.uuid);
  if (!credential) return void 0;
  const t = o.transport ?? {};
  const tls = o.tls ?? {};
  return toLink({
    scheme: o.type,
    user: credential,
    host,
    port,
    name,
    network: str(t.type),
    path: earlyData(str(t.path), t.max_early_data),
    hostHeader: str(t.headers?.Host ?? t.host),
    serviceName: str(t.service_name),
    security: tls.enabled ? tls.reality?.enabled ? "reality" : "tls" : void 0,
    sni: str(tls.server_name),
    fp: str(tls.utls?.fingerprint),
    alpn: alpnText(tls.alpn),
    insecure: !!tls.insecure,
    pbk: str(tls.reality?.public_key),
    sid: str(tls.reality?.short_id),
    flow: str(o.flow),
    cipher: str(o.security)
  });
}
function fromClashProxy(o) {
  const host = str(o.server);
  const port = Number(o.port);
  const name = str(o.name) ?? `${host}:${port}`;
  if (!host || !port) return void 0;
  if (o.type === "ss") return o.cipher && o.password ? ssLink(o.cipher, o.password, host, port, name) : void 0;
  if (o.type !== "vless" && o.type !== "vmess" && o.type !== "trojan") return void 0;
  const credential = str(o.type === "trojan" ? o.password : o.uuid);
  if (!credential) return void 0;
  const ws = o["ws-opts"] ?? {};
  const reality = o["reality-opts"];
  return toLink({
    scheme: o.type,
    user: credential,
    host,
    port,
    name,
    network: str(o.network),
    path: earlyData(str(ws.path), ws["max-early-data"]),
    hostHeader: str(ws.headers?.Host),
    serviceName: str(o["grpc-opts"]?.["grpc-service-name"]),
    // Trojan is always TLS in Clash, so the file doesn't have to say so.
    security: reality ? "reality" : o.tls || o.type === "trojan" ? "tls" : void 0,
    sni: str(o.servername ?? o.sni),
    fp: str(o["client-fingerprint"]),
    alpn: alpnText(o.alpn),
    insecure: !!o["skip-cert-verify"],
    pbk: str(reality?.["public-key"]),
    sid: str(reality?.["short-id"]),
    flow: str(o.flow),
    cipher: str(o.cipher)
  });
}
var withoutName = (link) => link.startsWith("vmess://") ? link : link.split("#")[0];
function linksFromConfigFile(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return [];
  }
  const links = [];
  for (const config of Array.isArray(parsed) ? parsed : [parsed]) {
    if (!config || typeof config !== "object") continue;
    if (Array.isArray(config.proxies)) links.push(...config.proxies.map(fromClashProxy));
    for (const o of Array.isArray(config.outbounds) ? config.outbounds : []) {
      if (o.type) links.push(fromSingBoxOutbound(o));
      else if (o.protocol) links.push(fromXrayOutbound(o, config.outbounds, str(config.remarks) ?? str(o.tag) ?? "Config"));
    }
  }
  const seen = /* @__PURE__ */ new Set();
  return links.filter((l) => {
    if (!l || seen.has(withoutName(l))) return false;
    seen.add(withoutName(l));
    return true;
  });
}

// src/main/warp.ts
var import_node_crypto = require("node:crypto");
var import_node_zlib = require("node:zlib");

// src/shared/types.ts
var WARP_METHODS = [
  { id: "gool", label: "Gool (WARP in WARP)", hint: "Exits outside Iran: a second WARP hop is opened from inside the first, so Cloudflare gives a foreign address. Much slower than the others, upload most of all.", auto: false },
  { id: "gool-h3", label: "Gool over HTTP/3", hint: "Gool with a faster download than plain Gool. Needs UDP, which some networks block.", auto: false },
  { id: "mim-h2", label: "MASQUE in MASQUE over HTTP/2", hint: "Exits outside Iran another way: a second MASQUE hop inside the first, over TCP. Slower than a single tunnel.", auto: false },
  { id: "mim", label: "MASQUE in MASQUE over HTTP/3", hint: "Exits outside Iran another way: a second MASQUE hop inside the first. Needs UDP, which some networks block.", auto: false },
  { id: "h3", label: "MASQUE over HTTP/3", hint: "Fastest. Needs UDP, which some networks block (often Irancell).", auto: true },
  { id: "h2", label: "MASQUE over HTTP/2", hint: "Runs over TCP, for networks that block QUIC / UDP.", auto: true },
  { id: "h2-fragment", label: "HTTP/2 + fragment", hint: "Splits the TLS handshake, for networks that reset it (some home internet).", auto: true },
  { id: "h2-ipv6", label: "HTTP/2 over IPv6", hint: "For Hamrah-e Aval (MCI), which filters Cloudflare's IPv4 addresses. Needs IPv6.", auto: true },
  { id: "wireguard", label: "WireGuard", hint: "Classic WARP. Usually blocked in Iran; not tried by Auto.", auto: false }
];
function usesTun(mode) {
  return mode === "tun" || mode === "per-app";
}
var HEALTH_INTERVAL_MS = 2e4;

// src/main/warp.ts
var WARP_IDENTITY_FILE = "aether-masque.toml";
var WARP_SHARE_SCHEME = "bridge://warp";
var IDENTITY_FIELDS = /* @__PURE__ */ new Set(["device_id", "access_token", "cert_pem", "key_pem", "cert_issued_at", "ipv4", "ipv6", "wg_private_key", "wg_peer_public_key", "client_id", "organization", "gateway_proxy", "assigned_endpoint"]);
var MAX_IDENTITY_BYTES = 8192;
function newWarpServer() {
  return {
    id: (0, import_node_crypto.randomUUID)(),
    name: "Free WARP (Cloudflare)",
    protocol: "warp",
    server: "Cloudflare WARP",
    port: 0,
    link: "warp://free",
    outbound: { type: "warp" },
    engine: "aether",
    warp: { method: "auto" }
  };
}
function isWarp(s) {
  return s.engine === "aether";
}
function isWarpGateway(peer) {
  const v4 = peer.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}):(\d{1,5})$/);
  if (v4) {
    const [a, b, c, d, port] = v4.slice(1).map(Number);
    if (c > 255 || d > 255 || port < 1 || port > 65535) return false;
    return a === 162 && b === 159 || a === 188 && b === 114 && c >= 96 && c <= 111;
  }
  const v6 = peer.match(/^\[(2606:4700:[0-9a-f:]+)\]:(\d{1,5})$/i);
  return !!v6 && Number(v6[2]) >= 1 && Number(v6[2]) <= 65535;
}
function checkIdentity(text) {
  const keys = text.split(/\r?\n/).flatMap((l) => l.match(/^([a-z0-9_]+)\s*=/)?.[1] ?? []);
  const bad = keys.find((k) => !IDENTITY_FIELDS.has(k));
  if (bad) throw new Error(`This link's WARP account has an unknown field (${bad})`);
  for (const field of ["device_id", "access_token", "cert_pem", "key_pem"]) {
    if (!keys.includes(field)) throw new Error(`This link's WARP account is missing ${field}`);
  }
}
function warpShareLink(warp, identity, name) {
  checkIdentity(identity);
  const query = new URLSearchParams({ m: warp.method });
  if (warp.peer) query.set("p", warp.peer);
  if (warp.exit) query.set("x", warp.exit);
  query.set("a", (0, import_node_zlib.deflateRawSync)(identity).toString("base64url"));
  return `${WARP_SHARE_SCHEME}?${query}#${encodeURIComponent(name)}`;
}
function parseWarpShareLink(link) {
  const [body, hash] = link.split("#");
  if (!body.startsWith(`${WARP_SHARE_SCHEME}?`)) throw new Error("Not a Bridge WARP link");
  const query = new URLSearchParams(body.slice(WARP_SHARE_SCHEME.length + 1));
  const method = query.get("m");
  if (method !== "auto" && method !== "auto-foreign" && !WARP_METHODS.some((m) => m.id === method)) throw new Error("This WARP link names an unknown method");
  const peer = query.get("p") || void 0;
  if (peer && !isWarpGateway(peer)) throw new Error("This WARP link points at an address outside Cloudflare WARP");
  const exit = query.get("x") || void 0;
  if (exit && !/^[A-Z]{2}$/.test(exit)) throw new Error("This WARP link names an unknown exit country");
  let identity;
  try {
    identity = (0, import_node_zlib.inflateRawSync)(Buffer.from(query.get("a") || "", "base64url"), { maxOutputLength: MAX_IDENTITY_BYTES }).toString("utf8");
  } catch {
    throw new Error("This WARP link is damaged; ask for it again");
  }
  checkIdentity(identity);
  let name = "";
  try {
    name = decodeURIComponent(hash || "");
  } catch {
  }
  return { warp: { method, peer, exit, shared: true }, identity, name: name.slice(0, 80) };
}
function warpServerFromLink(link) {
  const { warp, name } = parseWarpShareLink(link);
  return {
    ...newWarpServer(),
    name: name || `Free WARP \xB7 ${warp.method === "auto" || warp.method === "auto-foreign" ? "Auto" : warpLabel(warp.method)}`,
    server: warp.peer?.replace(/:\d+$/, "") ?? "Cloudflare WARP",
    port: Number(warp.peer?.split(":").pop()) || 0,
    link,
    warp
  };
}
function warpMethods(options) {
  const method = options?.method ?? "auto";
  const fast = WARP_METHODS.filter((m) => m.auto).map((m) => m.id);
  return method === "auto" ? fast : method === "auto-foreign" ? ["gool", "mim-h2", ...fast] : [method];
}
var WARP_FIND_METHODS = ["gool", "mim-h2", ...WARP_METHODS.filter((m) => m.auto).map((m) => m.id)];
function warpLabel(method) {
  return WARP_METHODS.find((m) => m.id === method)?.label ?? method;
}
var METHOD_ARGS = {
  // WireGuard inside a MASQUE (HTTP/2) tunnel. Its WireGuard account is made from inside WARP,
  // so it needs no direct access to the WARP API, and Cloudflare gives it a foreign exit.
  gool: ["--gool", "--h2", "-4"],
  "gool-h3": ["--gool", "--h3", "-4"],
  // A MASQUE tunnel inside a MASQUE one. Its second account is made from inside the first.
  "mim-h2": ["--mim", "--h2", "-4"],
  mim: ["--mim", "--h3", "-4"],
  h3: ["--masque", "--h3", "-4"],
  h2: ["--masque", "--h2", "-4"],
  "h2-fragment": ["--masque", "--h2", "--fragment", "-4"],
  "h2-ipv6": ["--masque", "--h2", "-6"],
  wireguard: ["--wg", "-4"]
};
function warpArgs(method, port, configFile, peer, fresh = false, verifyGateway = false, psiphon) {
  return [
    ...METHOD_ARGS[method],
    // A saved gateway: no scan. For the two-hop methods it is the outer hop.
    ...peer ? [method === "mim" || method === "mim-h2" ? "--mim-outer" : "--peer", peer] : [],
    // A gateway from someone else's link has to prove it really is Cloudflare's.
    ...verifyGateway ? ["--tls-verify"] : [],
    // Stop at the first gateway that passes real traffic: connecting fast matters more here. With
    // two hops, "verified" keeps them in separate ranges, which is what moves the exit address.
    "--scan",
    prefersForeignExit(method) ? "verified" : "turbo",
    // The last working gateway is one file shared by every method; "Find configs" ignores it
    // so each method proves a gateway of its own.
    fresh ? "--no-quick-reconnect" : "--quick-reconnect",
    "--bind",
    `127.0.0.1:${port}`,
    "--config",
    configFile,
    // Two hops are there for the foreign exit, so they refuse an Iranian one and look again. The
    // others take what they get: from Iran that is almost always an address Cloudflare
    // registers in Iran (the traffic still leaves abroad, so filtering is bypassed).
    ...prefersForeignExit(method) ? ["--exit-loc", "!IR"] : [],
    // Psiphon inside the tunnel, on a port of its own: aether -> WARP -> Psiphon -> the internet.
    ...psiphon ? ["--psiphon", "--psiphon-bin", psiphon.bin, "--psiphon-bind", `127.0.0.1:${psiphon.port}`, ...psiphon.region ? ["--psiphon-region", psiphon.region] : []] : []
  ];
}
function prefersForeignExit(method) {
  return method === "gool" || method === "gool-h3" || method === "mim" || method === "mim-h2";
}
var WARP_STATE_FILE = "bridge-warp-state.json";
var GOOL_RETRY_MS = 30 * 60 * 1e3;
var H3_RETRY_MS = 6 * 60 * 60 * 1e3;
function waitForGool(state, now = Date.now()) {
  return !state.goolMissedAt || now - state.goolMissedAt >= GOOL_RETRY_MS;
}
function waitForH3(state, now = Date.now()) {
  return !state.h3MissedAt || now - state.h3MissedAt >= H3_RETRY_MS;
}
var WARP_REGISTER_TRIES = [
  // The fragment splits the ClientHello whose server name the firewall looks for.
  { label: "directly, with TLS fragment", args: ["--fragment"], timeoutMs: 15e4 },
  { label: "through your own server", args: [], via: true, timeoutMs: 9e4 },
  { label: "directly", args: [], timeoutMs: 12e4 }
];
function warpRegisterArgs(configFile, extra = [], upstreamPort) {
  return ["--register", "masque", ...extra, ...upstreamPort ? ["--upstream", `socks5://127.0.0.1:${upstreamPort}`] : [], "--config", configFile];
}
function parseWarpLine(line) {
  const m = line.match(/^\[\S+\s+(TRACE|DEBUG|INFO|WARN|ERROR)\s+[^\]]*\]\s*(.*)$/);
  if (!m) return { level: /error|failed|panic/i.test(line) ? "warn" : "info", text: line.trim() };
  return { level: m[1] === "ERROR" ? "error" : m[1] === "WARN" ? "warn" : "info", text: m[2] };
}
function warpReady(text, port) {
  return text.includes(`socks5 server listening on 127.0.0.1:${port}`);
}
function warpExitCountry(text) {
  return text.match(/\bexit: \S+, ([A-Z]{2}) via /)?.[1];
}
function warpGateway(text) {
  return text.match(/using cloudflare edge (\S+:\d+)/)?.[1] ?? text.match(/masque-in-masque ready: (\S+:\d+) \(outer\)/)?.[1];
}
var WARP_EXIT_REFUSED = /exit location [A-Z]{2} rejected/;
var WARP_MAX_EXIT_REFUSED = 5;
var WARP_NO_IPV6 = /host has no IPv6 route/;

// src/main/xray.ts
var XrayLinkError = class extends Error {
};
function truthy(v) {
  return v === "1" || v === "true";
}
function list(v) {
  const items = (v || "").split(",").map((s) => s.trim()).filter(Boolean);
  return items.length ? items : void 0;
}
function clean(o) {
  for (const k of Object.keys(o)) if (o[k] === void 0 || o[k] === "" || o[k] === null) delete o[k];
  return o;
}
function buildStream(p) {
  const type = (p.type || "raw").toLowerCase();
  const stream = {};
  switch (type) {
    case "raw":
    case "tcp":
    case "":
      stream.method = "raw";
      if ((p.headerType || "").toLowerCase() === "http") {
        stream.rawSettings = {
          header: { type: "http", request: clean({ path: list(p.path) || ["/"], headers: p.host ? { Host: list(p.host) } : void 0 }) }
        };
      }
      break;
    case "xhttp":
    case "splithttp": {
      stream.method = "xhttp";
      const xhttp = clean({ host: p.host || void 0, path: p.path || "/", mode: p.mode || "auto" });
      if (p.extra) {
        try {
          xhttp.extra = JSON.parse(p.extra);
        } catch {
        }
      }
      stream.xhttpSettings = xhttp;
      break;
    }
    case "ws":
    case "websocket":
      stream.method = "websocket";
      stream.wsSettings = clean({ path: p.path || "/", host: p.host || void 0 });
      break;
    case "httpupgrade":
      stream.method = "httpupgrade";
      stream.httpupgradeSettings = clean({ path: p.path || "/", host: p.host || void 0 });
      break;
    case "grpc":
      stream.method = "grpc";
      stream.grpcSettings = clean({ serviceName: p.serviceName || p.path || void 0, authority: p.authority || void 0, multiMode: p.mode === "multi" || void 0 });
      break;
    case "kcp":
    case "mkcp":
      stream.method = "mkcp";
      stream.kcpSettings = clean({ seed: p.seed || void 0 });
      break;
    default:
      throw new XrayLinkError(`Transport "${type}" is not supported`);
  }
  const security = (p.security || "none").toLowerCase();
  if (security === "tls") {
    stream.security = "tls";
    stream.tlsSettings = clean({
      serverName: p.sni || p.host || void 0,
      fingerprint: p.fp || "chrome",
      alpn: list(p.alpn),
      allowInsecure: p.insecure || void 0
    });
  } else if (security === "reality") {
    if (!p.pbk) throw new XrayLinkError("REALITY link is missing pbk (public key)");
    stream.security = "reality";
    stream.realitySettings = clean({
      serverName: p.sni || void 0,
      // REALITY needs uTLS, so Xray's "unsafe" (plain Go TLS) is not allowed here.
      fingerprint: p.fp && p.fp !== "unsafe" ? p.fp : "chrome",
      password: p.pbk,
      shortId: p.sid || void 0,
      spiderX: p.spx || void 0,
      mldsa65Verify: p.pqv || void 0
    });
  }
  return stream;
}
function urlParts(link) {
  const url = new URL("http" + link.slice(link.indexOf("://")));
  return {
    user: decodeURIComponent(url.username),
    pass: decodeURIComponent(url.password),
    host: url.hostname.replace(/^\[|\]$/g, ""),
    port: Number(url.port || 443),
    params: url.searchParams
  };
}
function streamFromParams(params, defaults = {}) {
  const g = (k) => params.get(k);
  const stream = baseStream(g, defaults);
  try {
    const mask = JSON.parse(g("fm") || "null");
    if (mask && typeof mask === "object") stream.finalmask = mask;
  } catch {
  }
  return stream;
}
function baseStream(g, defaults) {
  return buildStream({
    type: g("type"),
    security: g("security") ?? defaults.security,
    sni: g("sni") || g("peer"),
    fp: g("fp"),
    alpn: g("alpn"),
    insecure: truthy(g("allowInsecure")) || truthy(g("insecure")),
    pbk: g("pbk"),
    sid: g("sid"),
    spx: g("spx"),
    pqv: g("pqv"),
    host: g("host"),
    path: g("path"),
    mode: g("mode"),
    extra: g("extra"),
    serviceName: g("serviceName"),
    authority: g("authority"),
    headerType: g("headerType"),
    seed: g("seed")
  });
}
function linkToXray(link) {
  const scheme = link.slice(0, link.indexOf("://")).toLowerCase();
  switch (scheme) {
    case "vless": {
      const u = urlParts(link);
      if (!u.user) throw new XrayLinkError("VLESS link is missing the UUID");
      const encryption = u.params.get("encryption") || "none";
      const stream = streamFromParams(u.params);
      return {
        protocol: "vless",
        settings: clean({ address: u.host, port: u.port, id: u.user, encryption, flow: u.params.get("flow") || void 0 }),
        streamSettings: stream
      };
    }
    case "trojan": {
      const u = urlParts(link);
      if (!u.user) throw new XrayLinkError("Trojan link is missing the password");
      return {
        protocol: "trojan",
        settings: { address: u.host, port: u.port, password: u.user },
        streamSettings: streamFromParams(u.params, { security: "tls" })
      };
    }
    case "vmess": {
      const j = JSON.parse(decodeBase64(link.slice("vmess://".length)));
      const s = (k) => j[k] === void 0 || j[k] === null ? "" : String(j[k]);
      if (!s("add") || !s("id")) throw new XrayLinkError("VMess link is missing address or id");
      return {
        protocol: "vmess",
        settings: { address: s("add"), port: Number(s("port") || 443), id: s("id"), security: s("scy") || "auto" },
        streamSettings: buildStream({
          type: s("net"),
          security: s("tls"),
          sni: s("sni"),
          fp: s("fp"),
          alpn: s("alpn"),
          host: s("host"),
          path: s("path"),
          serviceName: s("path"),
          headerType: s("type"),
          mode: s("mode")
        })
      };
    }
    default:
      throw new XrayLinkError(`${scheme}:// links are not handled by the Xray core in Bridge`);
  }
}
function xrayServer(o) {
  return { host: String(o.settings?.address ?? ""), port: Number(o.settings?.port ?? 0) };
}
function xrayWithServerIp(o, ip) {
  const host = o.settings?.address;
  if (typeof host !== "string" || host === ip) return o;
  const out = structuredClone(o);
  out.settings.address = ip;
  const st = out.streamSettings || {};
  if (st.security === "tls") st.tlsSettings = { serverName: host, ...st.tlsSettings };
  keepHost(st, host);
  return out;
}
function keepHost(st, host) {
  for (const key of ["wsSettings", "httpupgradeSettings", "xhttpSettings"]) {
    if (st[key] && !st[key].host) st[key].host = host;
  }
}
function needsRelay(o) {
  if (o.streamSettings?.security) return false;
  if (o.protocol === "vless") return (o.settings?.encryption || "none") === "none";
  return o.protocol === "trojan";
}
function buildXrayConfig(entries, logLevel = "warning", bindInterface) {
  const bind = (o) => bindInterface ? { ...o, streamSettings: { ...o.streamSettings, sockopt: { ...o.streamSettings?.sockopt, interface: bindInterface } } } : o;
  const inbounds = [];
  const outbounds = [];
  const rules = [];
  entries.forEach((e, i) => {
    inbounds.push({ tag: `in-${i}`, listen: "127.0.0.1", port: e.port, protocol: "socks", settings: { auth: "noauth", udp: true } });
    rules.push({ inboundTag: [`in-${i}`], outboundTag: `out-${i}` });
    const o = structuredClone(e.outbound);
    if (!e.relayPort) {
      outbounds.push({ ...bind(o), tag: `out-${i}` });
      return;
    }
    const { host, port } = xrayServer(o);
    o.settings.address = "127.0.0.1";
    o.settings.port = e.relayPort;
    keepHost(o.streamSettings ??= {}, host);
    outbounds.push({ ...o, tag: `out-${i}` });
    inbounds.push({ tag: `relay-in-${i}`, listen: "127.0.0.1", port: e.relayPort, protocol: "dokodemo-door", settings: { address: host, port, network: "tcp,udp" } });
    outbounds.push(bind({ tag: `relay-out-${i}`, protocol: "freedom" }));
    rules.push({ inboundTag: [`relay-in-${i}`], outboundTag: `relay-out-${i}` });
  });
  return { log: { loglevel: logLevel }, inbounds, outbounds, routing: { rules } };
}

// src/main/parser.ts
var UnsupportedLinkError = class extends Error {
};
var FINGERPRINTS = /* @__PURE__ */ new Set(["chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android", "random", "randomized"]);
function normalizeOutbound(outbound) {
  const tls = outbound.tls;
  const fp = tls?.utls?.fingerprint;
  if (!tls?.utls || fp === void 0) return outbound;
  const fixed = FINGERPRINTS.has(fp.toLowerCase()) ? fp.toLowerCase() : "chrome";
  if (fixed === fp) return outbound;
  return { ...outbound, tls: { ...tls, utls: { ...tls.utls, fingerprint: fixed } } };
}
function decodeBase64(input) {
  let s = input.trim().replace(/-/g, "+").replace(/_/g, "/").replace(/\s+/g, "");
  while (s.length % 4 !== 0) s += "=";
  return Buffer.from(s, "base64").toString("utf8");
}
function looksLikeBase64(s) {
  return /^[A-Za-z0-9+/=_-]+$/.test(s.replace(/\s+/g, ""));
}
function extractLinks(text) {
  const trimmed = text.trim();
  if (!trimmed) return [];
  if (/^[[{]/.test(trimmed)) return linksFromConfigFile(trimmed);
  let body = trimmed;
  if (!trimmed.includes("://") && looksLikeBase64(trimmed)) {
    try {
      body = decodeBase64(trimmed);
    } catch {
    }
    if (/^\s*[[{]/.test(body)) return linksFromConfigFile(body);
  }
  return body.split(/\r?\n/).map((l) => l.trim()).filter((l) => /^[a-z0-9]+:\/\//i.test(l));
}
function describeLink(link) {
  const scheme = link.slice(0, link.indexOf("://")).toLowerCase();
  try {
    if (scheme === "vmess") {
      const j = JSON.parse(decodeBase64(link.slice("vmess://".length)));
      return { name: String(j.ps || j.add || "vmess"), kind: `vmess / ${j.net || "tcp"}` };
    }
    const hash = link.indexOf("#");
    const name = hash >= 0 ? safeDecode(link.slice(hash + 1)) : "";
    const query = new URLSearchParams(link.split("#")[0].split("?")[1] || "");
    const transport = query.get("type");
    const security = query.get("security");
    const kind = [scheme, transport, security && security !== "none" ? security : ""].filter(Boolean).join(" / ");
    return { name: name || link.split("@")[1]?.split(/[?#]/)[0] || scheme, kind };
  } catch {
    return { name: link.slice(0, 40), kind: scheme };
  }
}
function parseLink(link) {
  if (link.startsWith(WARP_SHARE_SCHEME)) return warpServerFromLink(link);
  let xray;
  let xrayError;
  try {
    xray = linkToXray(link);
  } catch (e) {
    xrayError = e;
  }
  try {
    return { ...parseSingBoxLink(link), engine: xray?.streamSettings?.finalmask ? "xray" : "sing-box", xray };
  } catch (e) {
    if (!(e instanceof UnsupportedLinkError) || !xray) {
      throw e instanceof UnsupportedLinkError && xrayError ? new UnsupportedLinkError(`${e.message}, and Xray can't run it either: ${xrayError.message}`) : e;
    }
    const { host, port } = xrayServer(xray);
    const { name } = describeLink(link);
    const protocol = link.slice(0, link.indexOf("://")).toLowerCase() === "ss" ? "shadowsocks" : link.slice(0, link.indexOf("://")).toLowerCase();
    return {
      id: (0, import_node_crypto2.randomUUID)(),
      name: name || `${host}:${port}`,
      protocol,
      server: host,
      port,
      link,
      // Placeholder: at connect time sing-box gets a SOCKS hop into xray.exe instead.
      outbound: { type: protocol, server: host, server_port: port },
      engine: "xray",
      xray,
      xrayOnly: true
    };
  }
}
function parseSingBoxLink(link) {
  const scheme = link.slice(0, link.indexOf("://")).toLowerCase();
  switch (scheme) {
    case "vless":
      return parseVless(link);
    case "vmess":
      return parseVmess(link);
    case "trojan":
      return parseTrojan(link);
    case "ss":
      return parseShadowsocks(link);
    case "hysteria2":
    case "hy2":
      return parseHysteria2(link);
    case "tuic":
      return parseTuic(link);
    default:
      throw new UnsupportedLinkError(`Unsupported link type: ${scheme}://`);
  }
}
function parseUrl(link) {
  const url = new URL("http" + link.slice(link.indexOf("://")));
  const host = url.hostname.replace(/^\[|\]$/g, "");
  const port = Number(url.port || 443);
  if (!host) throw new Error("Missing server address");
  return {
    user: decodeURIComponent(url.username),
    pass: decodeURIComponent(url.password),
    host,
    port,
    params: url.searchParams,
    name: safeDecode(url.hash.replace(/^#/, ""))
  };
}
function safeDecode(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}
function truthy2(v) {
  return v === "1" || v === "true";
}
function list2(v) {
  if (!v) return void 0;
  const items = v.split(",").map((s) => s.trim()).filter(Boolean);
  return items.length ? items : void 0;
}
function compact(obj) {
  for (const k of Object.keys(obj)) if (obj[k] === void 0 || obj[k] === "") delete obj[k];
  return obj;
}
function buildTls(o) {
  const security = (o.security || "").toLowerCase();
  if (security !== "tls" && security !== "reality" && security !== "xtls") return void 0;
  const tls = compact({
    enabled: true,
    server_name: o.sni || o.fallbackSni,
    insecure: o.insecure || void 0,
    alpn: list2(o.alpn)
  });
  const fp = o.fp || (security === "reality" ? "chrome" : "");
  if (fp) tls.utls = { enabled: true, fingerprint: fp };
  if (security === "reality") {
    if (!o.publicKey) throw new Error("REALITY link is missing pbk (public key)");
    tls.reality = compact({ enabled: true, public_key: o.publicKey, short_id: o.shortId || void 0 });
  }
  return tls;
}
function buildTransport(o) {
  const type = (o.type || "tcp").toLowerCase();
  switch (type) {
    case "tcp":
    case "raw":
    case "":
      if ((o.headerType || "none").toLowerCase() === "http") {
        throw new UnsupportedLinkError("TCP with HTTP header camouflage (headerType=http) is Xray-only, not supported by the sing-box core");
      }
      return void 0;
    case "ws": {
      let path = o.path || "/";
      const t = { type: "ws" };
      const m = path.match(/[?&]ed=(\d+)/);
      if (m) {
        t.max_early_data = Number(m[1]);
        t.early_data_header_name = "Sec-WebSocket-Protocol";
        path = path.replace(/[?&]ed=\d+/, "").replace(/\?$/, "") || "/";
      }
      t.path = path;
      if (o.host) t.headers = { Host: o.host };
      return t;
    }
    case "grpc":
      return compact({ type: "grpc", service_name: o.serviceName || o.path || void 0 });
    case "http":
    case "h2":
      return compact({ type: "http", host: list2(o.host), path: o.path || void 0 });
    case "httpupgrade":
      return compact({ type: "httpupgrade", host: o.host || void 0, path: o.path || void 0 });
    default:
      throw new UnsupportedLinkError(`Transport "${type}" is not supported by the sing-box core`);
  }
}
function profile(protocol, link, name, server, port, outbound) {
  return {
    id: (0, import_node_crypto2.randomUUID)(),
    name: name || `${server}:${port}`,
    protocol,
    server,
    port,
    link,
    outbound: normalizeOutbound(outbound)
  };
}
function parseVless(link) {
  const u = parseUrl(link);
  const p = u.params;
  if (!u.user) throw new Error("VLESS link is missing the UUID");
  const encryption = (p.get("encryption") || "none").toLowerCase();
  if (encryption !== "none") throw new UnsupportedLinkError(`VLESS Encryption ("${encryption.split(".")[0]}") is Xray-only, not supported by the sing-box core`);
  const outbound = compact({
    type: "vless",
    server: u.host,
    server_port: u.port,
    uuid: u.user,
    flow: p.get("flow") || void 0,
    tls: buildTls({
      security: p.get("security"),
      sni: p.get("sni"),
      fp: p.get("fp"),
      alpn: p.get("alpn"),
      insecure: truthy2(p.get("allowInsecure")) || truthy2(p.get("insecure")),
      publicKey: p.get("pbk"),
      shortId: p.get("sid"),
      fallbackSni: p.get("host") || void 0
    }),
    transport: buildTransport({
      type: p.get("type"),
      host: p.get("host"),
      path: p.get("path"),
      serviceName: p.get("serviceName"),
      headerType: p.get("headerType")
    })
  });
  return profile("vless", link, u.name, u.host, u.port, outbound);
}
function parseVmess(link) {
  const raw = link.slice("vmess://".length);
  let j;
  try {
    j = JSON.parse(decodeBase64(raw));
  } catch {
    throw new Error("VMess link is not valid base64 JSON");
  }
  const s = (k) => j[k] === void 0 || j[k] === null ? "" : String(j[k]);
  const server = s("add");
  const port = Number(s("port") || 443);
  if (!server || !s("id")) throw new Error("VMess link is missing address or id");
  const outbound = compact({
    type: "vmess",
    server,
    server_port: port,
    uuid: s("id"),
    security: s("scy") || "auto",
    alter_id: Number(s("aid") || 0),
    tls: buildTls({
      security: s("tls"),
      sni: s("sni"),
      fp: s("fp"),
      alpn: s("alpn"),
      insecure: truthy2(s("allowInsecure")) || truthy2(s("skip-cert-verify")),
      fallbackSni: s("host") || void 0
    }),
    transport: buildTransport({
      type: s("net"),
      host: s("host"),
      path: s("path"),
      serviceName: s("path"),
      headerType: s("type")
    })
  });
  return profile("vmess", link, s("ps"), server, port, outbound);
}
function parseTrojan(link) {
  const u = parseUrl(link);
  const p = u.params;
  if (!u.user) throw new Error("Trojan link is missing the password");
  const outbound = compact({
    type: "trojan",
    server: u.host,
    server_port: u.port,
    password: u.user,
    tls: buildTls({
      // Trojan is always TLS unless the link explicitly says otherwise.
      security: p.get("security") || "tls",
      sni: p.get("sni") || p.get("peer"),
      fp: p.get("fp"),
      alpn: p.get("alpn"),
      insecure: truthy2(p.get("allowInsecure")) || truthy2(p.get("insecure")),
      publicKey: p.get("pbk"),
      shortId: p.get("sid"),
      fallbackSni: u.host
    }),
    transport: buildTransport({
      type: p.get("type"),
      host: p.get("host"),
      path: p.get("path"),
      serviceName: p.get("serviceName"),
      headerType: p.get("headerType")
    })
  });
  return profile("trojan", link, u.name, u.host, u.port, outbound);
}
function parseShadowsocks(link) {
  let rest = link.slice("ss://".length);
  let name = "";
  const hashAt = rest.indexOf("#");
  if (hashAt >= 0) {
    name = safeDecode(rest.slice(hashAt + 1));
    rest = rest.slice(0, hashAt);
  }
  let query = "";
  const qAt = rest.indexOf("?");
  if (qAt >= 0) {
    query = rest.slice(qAt + 1);
    rest = rest.slice(0, qAt).replace(/\/$/, "");
  }
  if (!rest.includes("@")) rest = decodeBase64(rest);
  const at = rest.lastIndexOf("@");
  if (at < 0) throw new Error("Shadowsocks link is malformed");
  let userinfo = rest.slice(0, at);
  const hostPort = rest.slice(at + 1);
  userinfo = safeDecode(userinfo);
  if (!userinfo.includes(":")) userinfo = decodeBase64(userinfo);
  const colon = userinfo.indexOf(":");
  const method = userinfo.slice(0, colon);
  const password = userinfo.slice(colon + 1);
  const hp = hostPort.match(/^\[?([^\]]+?)\]?:(\d+)$/);
  if (!hp || !method) throw new Error("Shadowsocks link is malformed");
  const server = hp[1];
  const port = Number(hp[2]);
  const outbound = { type: "shadowsocks", server, server_port: port, method, password };
  const plugin = new URLSearchParams(query).get("plugin");
  if (plugin) {
    const [pluginName, ...opts] = plugin.split(";");
    const supported = { "obfs-local": "obfs-local", "simple-obfs": "obfs-local", "v2ray-plugin": "v2ray-plugin" };
    if (!supported[pluginName]) throw new UnsupportedLinkError(`Shadowsocks plugin "${pluginName}" is not supported`);
    outbound.plugin = supported[pluginName];
    outbound.plugin_opts = opts.join(";");
  }
  return profile("shadowsocks", link, name, server, port, outbound);
}
function parseHysteria2(link) {
  const u = parseUrl(link);
  const p = u.params;
  const password = u.pass ? `${u.user}:${u.pass}` : u.user;
  const outbound = compact({
    type: "hysteria2",
    server: u.host,
    server_port: u.port,
    password: password || void 0,
    tls: compact({
      enabled: true,
      server_name: p.get("sni") || u.host,
      insecure: truthy2(p.get("insecure")) || void 0,
      alpn: list2(p.get("alpn")) || ["h3"]
    })
  });
  const obfs = p.get("obfs");
  if (obfs && obfs !== "none") {
    outbound.obfs = { type: obfs, password: p.get("obfs-password") || "" };
  }
  const mport = p.get("mport");
  if (mport) outbound.server_ports = mport.split(",").map((r) => r.replace("-", ":"));
  return profile("hysteria2", link, u.name, u.host, u.port, outbound);
}
function parseTuic(link) {
  const u = parseUrl(link);
  const p = u.params;
  if (!u.user) throw new Error("TUIC link is missing the UUID");
  const outbound = compact({
    type: "tuic",
    server: u.host,
    server_port: u.port,
    uuid: u.user,
    password: u.pass || void 0,
    congestion_control: p.get("congestion_control") || void 0,
    udp_relay_mode: p.get("udp_relay_mode") || void 0,
    tls: compact({
      enabled: true,
      server_name: p.get("sni") || u.host,
      insecure: truthy2(p.get("allow_insecure")) || truthy2(p.get("insecure")) || void 0,
      alpn: list2(p.get("alpn")) || ["h3"]
    })
  });
  return profile("tuic", link, u.name, u.host, u.port, outbound);
}

// src/main/config.ts
var SPEED_TEST_PORTS = { first: 45800, last: 45899 };
var DEFAULT_TUN_MTU = 9e3;
var APP_ACTIONS = ["block", "direct", "other", "proxy"];
var NEVER_MATCH = "^:no-app:$";
function withServerIp(outbound, ip) {
  const host = outbound.server;
  if (typeof host !== "string" || host === ip) return outbound;
  const o = structuredClone(outbound);
  o.server = ip;
  if (o.tls?.enabled && !o.tls.server_name) o.tls.server_name = host;
  const t = o.transport;
  if (t?.type === "ws" && !t.headers?.Host) t.headers = { ...t.headers, Host: host };
  if (t?.type === "http" && !t.host) t.host = [host];
  if (t?.type === "httpupgrade" && !t.host) t.host = host;
  return o;
}
var escapeRegex = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
function processPathRegex(path) {
  const parts = path.split("\\");
  const exe = escapeRegex(parts.pop() || "");
  const dirs = parts.map((dir) => dir.split(/\d+(?:\.\d+)+/).map(escapeRegex).join("[0-9.]+"));
  return "(?i)^" + [...dirs, exe].join("\\\\") + "$";
}
function appRule(rules, action) {
  return rules.filter((r) => r.enabled && r.action === action).map((r) => processPathRegex(r.path));
}
function appRuleSetPath(dir, action) {
  return (0, import_node_path.join)(dir, `apps-${action}.json`);
}
function writeAppRuleSets(dir, rules) {
  (0, import_node_fs.mkdirSync)(dir, { recursive: true });
  for (const action of APP_ACTIONS) {
    const paths = appRule(rules, action);
    const text = JSON.stringify({ version: 3, rules: [{ process_path_regex: paths.length ? paths : [NEVER_MATCH] }] }, null, 2);
    const file = appRuleSetPath(dir, action);
    if (!(0, import_node_fs.existsSync)(file) || (0, import_node_fs.readFileSync)(file, "utf8") !== text) (0, import_node_fs.writeFileSync)(file, text);
  }
}
function buildDns(o, useTun, iranRules) {
  const local = o.dnsRelayPort ? { type: "tcp", tag: "dns-local", server: "127.0.0.1", server_port: o.dnsRelayPort } : o.localDns ? { type: o.localDns.type, tag: "dns-local", server: o.localDns.server } : { type: "local", tag: "dns-local" };
  const rules = [];
  if (o.settings.bypassIran) {
    rules.push({ domain_suffix: [".ir"], server: "dns-local" });
    if (iranRules) rules.push({ rule_set: ["geosite-ir"], server: "dns-local" });
  }
  const servers = [local];
  if (useTun && o.settings.dnsMode === "fakeip") {
    servers.push({ type: "fakeip", tag: "dns-fake", inet4_range: "198.18.0.0/15" });
    rules.push({ query_type: ["A", "AAAA"], server: "dns-fake" });
  }
  return { servers, rules, final: "dns-local", strategy: "ipv4_only", optimistic: { enabled: true, timeout: "1h" } };
}
function buildConfig(o) {
  const { settings } = o;
  const useTun = usesTun(settings.mode);
  const iranRules = settings.bypassIran && o.rulesDir;
  writeAppRuleSets(o.appRulesDir, o.appRules);
  const inbounds = [
    { type: "mixed", tag: "mixed-in", listen: "127.0.0.1", listen_port: settings.mixedPort }
  ];
  if (o.probePort) inbounds.push({ type: "socks", tag: "probe-in", listen: "127.0.0.1", listen_port: o.probePort });
  if (useTun) {
    inbounds.unshift({
      type: "tun",
      tag: "tun-in",
      interface_name: "Bridge",
      address: o.noIpv6 ? ["172.19.0.1/30"] : ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
      mtu: settings.tunMtu >= 1280 && settings.tunMtu <= DEFAULT_TUN_MTU ? settings.tunMtu : DEFAULT_TUN_MTU,
      auto_route: true,
      // Two half routes instead of a default route (OpenVPN's "def1" trick): they are more
      // specific, so all traffic still enters the TUN, but Windows' real default route stays
      // on Wi-Fi / Ethernet. Tools that look up "the" default route to find the internet
      // (EZConnect / WireSock, WireGuard clients) then still find the real adapter instead of
      // Bridge's gateway-less tunnel; with a 0.0.0.0/0 route they failed to connect.
      route_address: o.noIpv6 ? ["0.0.0.0/1", "128.0.0.0/1"] : ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"],
      // Strict mode blocks port 53 outside the adapter, so without DNS-over-HTTPS Direct apps couldn't resolve names.
      strict_route: settings.strictRoute && o.localDns?.type === "https",
      stack: settings.tunStack
    });
  }
  const routeRules = [
    { action: "sniff" },
    { protocol: "dns", action: "hijack-dns" },
    ...o.probePort ? [{ inbound: ["probe-in"], outbound: "proxy" }] : [],
    ...useTun ? [{ inbound: ["tun-in"], source_port_range: [`${SPEED_TEST_PORTS.first}:${SPEED_TEST_PORTS.last}`], outbound: "proxy" }] : [],
    { ip_is_private: true, outbound: "direct" }
  ];
  if (o.bypassProcesses?.length) routeRules.push({ process_path_regex: o.bypassProcesses.map(processPathRegex), outbound: "direct" });
  routeRules.push({ rule_set: ["apps-block"], action: "reject" });
  routeRules.push({ rule_set: ["apps-direct"], outbound: "direct" });
  routeRules.push({ rule_set: ["apps-other"], outbound: "direct-other" });
  if (settings.bypassIran) {
    routeRules.push({ domain_suffix: [".ir"], outbound: "direct" });
    if (iranRules) routeRules.push({ rule_set: ["geosite-ir", "geoip-ir"], outbound: "direct" });
  }
  if (settings.mode === "per-app") {
    routeRules.push({ rule_set: ["apps-proxy"], outbound: "proxy" });
    routeRules.push({ inbound: ["mixed-in"], outbound: "proxy" });
  }
  const ruleSets = APP_ACTIONS.map((action) => ({
    type: "local",
    tag: `apps-${action}`,
    format: "source",
    path: appRuleSetPath(o.appRulesDir, action)
  }));
  if (iranRules) {
    ruleSets.push(
      { type: "local", tag: "geoip-ir", format: "binary", path: (0, import_node_path.join)(o.rulesDir, "geoip-ir.srs") },
      { type: "local", tag: "geosite-ir", format: "binary", path: (0, import_node_path.join)(o.rulesDir, "geosite-ir.srs") }
    );
  }
  const route = {
    rules: routeRules,
    rule_set: ruleSets,
    final: settings.mode === "per-app" ? "direct" : "proxy",
    default_domain_resolver: "dns-local",
    find_process: true
  };
  if (o.defaultInterface) route.default_interface = o.defaultInterface;
  else route.auto_detect_interface = true;
  const experimental = {
    clash_api: { external_controller: `127.0.0.1:${o.clashApi.port}`, secret: o.clashApi.secret }
  };
  if (o.cacheFile) experimental.cache_file = { enabled: true, path: o.cacheFile, store_fakeip: useTun && settings.dnsMode === "fakeip" };
  return {
    log: { level: settings.logLevel, timestamp: true },
    dns: buildDns(o, useTun, !!iranRules),
    inbounds,
    outbounds: [
      { ...normalizeOutbound(o.server.outbound), tag: "proxy" },
      { type: "direct", tag: "direct" },
      // Apps set to "Other VPN" leave through the other tool's adapter, so that tool
      // (e.g. EZConnect) carries them; without one they simply go direct.
      o.otherInterface ? { type: "direct", tag: "direct-other", bind_interface: o.otherInterface } : { type: "direct", tag: "direct-other" }
    ],
    route,
    experimental
  };
}
function buildHelperConfig(server, port, clashApi) {
  return {
    log: { level: "warn", timestamp: true },
    dns: { servers: [{ type: "local", tag: "dns-local" }] },
    inbounds: [{ type: "socks", tag: "helper-in", listen: "127.0.0.1", listen_port: port }],
    outbounds: [{ ...normalizeOutbound(server.outbound), tag: "proxy" }],
    route: { final: "proxy", default_domain_resolver: "dns-local", auto_detect_interface: true },
    experimental: { clash_api: { external_controller: `127.0.0.1:${clashApi.port}`, secret: clashApi.secret } }
  };
}
function buildTestConfig(servers, clashApi) {
  return {
    log: { level: "warn", timestamp: true },
    dns: { servers: [{ type: "local", tag: "dns-local" }] },
    outbounds: [
      { type: "direct", tag: "direct" },
      ...servers.map((s) => ({ ...normalizeOutbound(s.outbound), tag: s.id }))
    ],
    // auto_detect_interface keeps the test's traffic off the running VPN's TUN adapter.
    route: { final: "direct", default_domain_resolver: "dns-local", auto_detect_interface: true },
    experimental: {
      clash_api: { external_controller: `127.0.0.1:${clashApi.port}`, secret: clashApi.secret }
    }
  };
}

// src/main/core.ts
var import_node_net6 = require("node:net");
var import_node_os2 = require("node:os");

// src/main/dnsrelay.ts
var import_node_http2 = require("node:http2");
var import_node_net2 = require("node:net");
var import_node_tls2 = require("node:tls");

// src/main/speedtest.ts
var import_node_crypto3 = require("node:crypto");
var import_node_net = require("node:net");
var import_node_tls = require("node:tls");
var HOST = "speed.cloudflare.com";
var DIAL_TIMEOUT_MS = 15e3;
var FIRST_BYTE_MS = 2e4;
var DOWNLOAD = { streams: 4, durationMs: 6e3, warmupMs: 1500, maxBytes: 15e7 };
var UPLOAD = { streams: 2, durationMs: 4e3, warmupMs: 1e3, maxBytes: 3e7 };
var DOWN_REQUEST_BYTES = 5e7;
var UP_REQUEST_BYTES = 1e7;
var UP_CHUNK = (0, import_node_crypto3.randomBytes)(64 * 1024);
function opened(s) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => s.destroy(new Error("Connecting timed out")), DIAL_TIMEOUT_MS);
    s.once("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    s.once("connect", () => {
      clearTimeout(timer);
      s.removeAllListeners("error");
      s.on("error", () => void 0);
      resolve(s);
    });
  });
}
function readExactly(s, n) {
  return new Promise((resolve, reject) => {
    const tryRead = () => {
      const chunk = s.read(n);
      if (!chunk) return;
      s.off("readable", tryRead);
      s.off("error", reject);
      s.off("close", onClose);
      resolve(chunk);
    };
    const onClose = () => reject(new Error("The local SOCKS connection closed"));
    s.on("readable", tryRead);
    s.once("error", reject);
    s.once("close", onClose);
    tryRead();
  });
}
function socksDialer(port, host = HOST, targetPort = 443) {
  return async () => {
    const s = await opened((0, import_node_net.connect)({ host: "127.0.0.1", port }));
    s.write(Buffer.from([5, 1, 0]));
    if ((await readExactly(s, 2))[1] !== 0) throw new Error("SOCKS refused");
    const name = Buffer.from(host);
    s.write(Buffer.concat([Buffer.from([5, 1, 0, 3, name.length]), name, Buffer.from([targetPort >> 8, targetPort & 255])]));
    const head = await readExactly(s, 4);
    if (head[1] !== 0) throw new Error(`The VPN server could not reach the test server (SOCKS ${head[1]})`);
    await readExactly(s, (head[3] === 1 ? 4 : head[3] === 4 ? 16 : (await readExactly(s, 1))[0]) + 2);
    return s;
  };
}
var nextPort = SPEED_TEST_PORTS.first + Math.floor(Math.random() * (SPEED_TEST_PORTS.last - SPEED_TEST_PORTS.first));
function adapterDialer(findAddress) {
  let address;
  return async () => {
    address ??= findAddress(HOST);
    const ip = await address;
    if (!ip) throw new Error("Could not find the test server's address");
    for (let tries = 0; ; tries++) {
      nextPort = nextPort >= SPEED_TEST_PORTS.last ? SPEED_TEST_PORTS.first : nextPort + 1;
      try {
        return await opened((0, import_node_net.connect)({ host: ip, port: 443, localPort: nextPort, family: 4 }));
      } catch (e) {
        if (e.code !== "EADDRINUSE" || tries >= 20) throw e;
      }
    }
  };
}
function transfer(dial, upload, count, stopped, track) {
  return dial().then(
    (raw) => new Promise((resolve, reject) => {
      const s = (0, import_node_tls.connect)({ socket: raw, servername: HOST, ALPNProtocols: ["http/1.1"] });
      track(s);
      const request2 = upload ? `POST /__up HTTP/1.1\r
Host: ${HOST}\r
User-Agent: Bridge\r
Content-Type: application/octet-stream\r
Content-Length: ${UP_REQUEST_BYTES}\r
Connection: close\r
\r
` : `GET /__down?bytes=${DOWN_REQUEST_BYTES} HTTP/1.1\r
Host: ${HOST}\r
User-Agent: Bridge\r
Accept: */*\r
Connection: close\r
\r
`;
      let head = Buffer.alloc(0);
      const finish = (e) => {
        s.destroy();
        raw.destroy();
        if (e && !stopped()) reject(e);
        else resolve();
      };
      s.once("secureConnect", () => {
        s.write(request2);
        if (!upload) return;
        let left = UP_REQUEST_BYTES;
        const pump = () => {
          if (stopped() || left <= 0 || s.destroyed) return;
          const chunk = left >= UP_CHUNK.length ? UP_CHUNK : UP_CHUNK.subarray(0, left);
          left -= chunk.length;
          s.write(chunk, () => {
            count(chunk.length);
            pump();
          });
        };
        pump();
      });
      s.on("data", (d) => {
        if (!head) {
          if (!upload) count(d.length);
          return;
        }
        head = Buffer.concat([head, d]);
        const end = head.indexOf("\r\n\r\n");
        if (end < 0) return;
        const code = Number(head.subarray(0, end).toString().split(" ")[1]);
        if (code < 200 || code >= 300) return finish(new Error(`The test server answered HTTP ${code}`));
        if (!upload) count(head.length - end - 4);
        head = void 0;
      });
      s.once("error", finish);
      s.once("close", () => finish());
    })
  );
}
function averageMbps(samples, warmupMs) {
  const last = samples.at(-1);
  if (!last) return 0;
  const first = samples[0];
  const start = samples.find((s) => s.at - first.at >= warmupMs && s !== last) ?? first;
  const ms = last.at - start.at;
  return ms > 0 ? (last.bytes - start.bytes) * 8 / ms / 1e3 : 0;
}
async function measure(dial, upload, m, hooks = {}) {
  let bytes = 0;
  let firstAt = 0;
  let stop = false;
  let workerError;
  let problem;
  const sockets = /* @__PURE__ */ new Set();
  const samples = [];
  const halt = () => {
    stop = true;
    for (const s of sockets) s.destroy();
  };
  hooks.signal?.addEventListener("abort", halt);
  const count = (n) => {
    if (n <= 0) return;
    bytes += n;
    if (firstAt) return;
    firstAt = performance.now();
    samples.push({ at: firstAt, bytes });
    if (hooks.verify) {
      setTimeout(() => {
        void hooks.verify?.().then((found) => {
          if (found && !stop) {
            problem = found;
            halt();
          }
        });
      }, 1e3);
    }
  };
  const startedAt = performance.now();
  let lastTick = { at: startedAt, bytes: 0 };
  const ticker = setInterval(() => {
    const at = performance.now();
    if (firstAt) samples.push({ at, bytes });
    if (at > lastTick.at) hooks.onMbps?.((bytes - lastTick.bytes) * 8 / (at - lastTick.at) / 1e3);
    lastTick = { at, bytes };
    const timedOut = firstAt ? at - firstAt >= m.durationMs : at - startedAt >= FIRST_BYTE_MS;
    if (timedOut || bytes >= m.maxBytes) halt();
  }, 250);
  const worker = async () => {
    let failures = 0;
    while (!stop) {
      const before = bytes;
      try {
        await transfer(dial, upload, count, () => stop, (s) => {
          sockets.add(s);
          s.once("close", () => sockets.delete(s));
          if (stop) s.destroy();
        });
      } catch (e) {
        workerError ??= e instanceof Error ? e : new Error(String(e));
        if (++failures >= 3) return;
        await new Promise((r) => setTimeout(r, 300));
      }
      if (bytes > before) failures = 0;
    }
  };
  await Promise.all(Array.from({ length: m.streams }, worker));
  clearInterval(ticker);
  hooks.signal?.removeEventListener("abort", halt);
  stop = true;
  if (firstAt) samples.push({ at: performance.now(), bytes });
  if (hooks.signal?.aborted) throw new Error("Stopped");
  if (problem) throw new Error(problem);
  if (!firstAt) throw workerError ?? new Error("The test server did not answer");
  return { mbps: averageMbps(samples, m.warmupMs), usedBytes: bytes };
}
var QUICK_DOWN_BYTES = 8e6;
var QUICK_UP_BYTES = 3e6;
var QUICK_DOWN_MS = 3e3;
var QUICK_UP_MS = 8e3;
var QUICK_WARMUP_MS = 500;
var QUICK_SOURCES = [
  { host: HOST, path: `/__down?bytes=${QUICK_DOWN_BYTES}` },
  { host: "cachefly.cachefly.net", path: "/10mb.test" },
  { host: "proof.ovh.net", path: "/files/10Mb.dat" }
];
function quickSocket(port, host, start, onData, deadlineMs) {
  return socksDialer(port, host)().then(
    (raw) => new Promise((resolve) => {
      const s = (0, import_node_tls.connect)({ socket: raw, servername: host, ALPNProtocols: ["http/1.1"] });
      const end = () => {
        clearTimeout(timer);
        s.destroy();
        raw.destroy();
        resolve();
      };
      const timer = setTimeout(end, deadlineMs);
      s.once("secureConnect", () => start(s));
      s.on("data", onData);
      s.once("error", end);
      s.once("close", end);
    })
  );
}
async function quickGet(port, host, path, deadlineMs = QUICK_DOWN_MS) {
  let head = Buffer.alloc(0);
  let refused = false;
  let bytes = 0;
  let firstAt = 0;
  let mark;
  let lastAt = 0;
  await quickSocket(
    port,
    host,
    (s) => s.write(`GET ${path} HTTP/1.1\r
Host: ${host}\r
User-Agent: Bridge\r
Accept: */*\r
Connection: close\r
\r
`),
    (d) => {
      let body = d.length;
      if (head) {
        head = Buffer.concat([head, d]);
        const end = head.indexOf("\r\n\r\n");
        if (end < 0) return;
        const code = Number(head.subarray(0, end).toString().split(" ")[1]);
        refused = code < 200 || code >= 300;
        body = head.length - end - 4;
        head = void 0;
      }
      if (refused) return;
      lastAt = performance.now();
      firstAt ||= lastAt;
      bytes += body;
      if (!mark && lastAt - firstAt >= QUICK_WARMUP_MS) mark = { at: lastAt, bytes };
    },
    deadlineMs
  );
  if (refused || !bytes || lastAt <= firstAt) return void 0;
  const from = mark && lastAt > mark.at ? mark : { at: firstAt, bytes: 0 };
  return (bytes - from.bytes) * 8 / (lastAt - from.at) / 1e3;
}
async function quickPost(port) {
  let startAt = 0;
  let doneAt = 0;
  await quickSocket(
    port,
    HOST,
    (s) => {
      s.write(`POST /__up HTTP/1.1\r
Host: ${HOST}\r
User-Agent: Bridge\r
Content-Type: application/octet-stream\r
Content-Length: ${QUICK_UP_BYTES}\r
Connection: close\r
\r
`);
      startAt = performance.now();
      let left = QUICK_UP_BYTES;
      const pump = () => {
        while (left > 0 && !s.destroyed) {
          const chunk = left >= UP_CHUNK.length ? UP_CHUNK : UP_CHUNK.subarray(0, left);
          left -= chunk.length;
          if (!s.write(chunk)) return void s.once("drain", pump);
        }
      };
      pump();
    },
    (d) => {
      if (!doneAt && /^HTTP\/1\.1 2/.test(d.toString("latin1", 0, 12))) doneAt = performance.now();
    },
    QUICK_UP_MS
  );
  return doneAt > startAt ? QUICK_UP_BYTES * 8 / (doneAt - startAt) / 1e3 : void 0;
}
async function quickSpeed(port) {
  let down;
  for (const { host, path } of QUICK_SOURCES) {
    down = await quickGet(port, host, path).catch(() => void 0);
    if (down) break;
  }
  const up = await quickPost(port).catch(() => void 0);
  return { downMbps: down && Math.round(down), upMbps: up && Math.round(up) };
}
async function quickDown(port, bytes, deadlineMs) {
  const from = (host, path, ms) => withDeadline(quickGet(port, host, path, ms), ms + 5e3).catch(() => void 0);
  const down = await from(HOST, `/__down?bytes=${bytes}`, deadlineMs) ?? await from(QUICK_SOURCES[1].host, QUICK_SOURCES[1].path, Math.min(deadlineMs, 1500));
  return down && Math.round(down * 10) / 10;
}
async function quickExit(port) {
  const ask = async (host, path, read) => {
    let text = "";
    await quickSocket(port, host, (s) => s.write(`GET ${path} HTTP/1.1\r
Host: ${host}\r
User-Agent: Bridge\r
Accept: */*\r
Connection: close\r
\r
`), (d) => text += d.toString("latin1"), 6e3);
    const code = read(text);
    return code && /^[A-Za-z]{2}$/.test(code) && code.toUpperCase() !== "XX" ? code.toUpperCase() : void 0;
  };
  const trace = () => ask("www.cloudflare.com", "/cdn-cgi/trace", (b) => b.match(/^loc=(\w+)/m)?.[1]);
  const country = () => ask("api.country.is", "/", (b) => b.match(/"country"\s*:\s*"(\w+)"/)?.[1]);
  return await withDeadline(trace()).catch(() => void 0) ?? await withDeadline(country()).catch(() => void 0);
}
function withDeadline(p, ms = 8e3) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("timeout")), ms);
    p.then(resolve, reject).finally(() => clearTimeout(timer));
  });
}
async function runPath(dial, onProgress, verify, signal) {
  const result = { usedBytes: 0 };
  try {
    const down = await measure(dial, false, DOWNLOAD, { onMbps: (v) => onProgress("download", v), verify, signal });
    result.downMbps = down.mbps;
    result.usedBytes += down.usedBytes;
  } catch (e) {
    if (signal?.aborted) throw e;
    result.error = e instanceof Error ? e.message : String(e);
    return result;
  }
  try {
    const up = await measure(dial, true, UPLOAD, { onMbps: (v) => onProgress("upload", v), signal });
    result.upMbps = up.mbps;
    result.usedBytes += up.usedBytes;
  } catch (e) {
    if (signal?.aborted) throw e;
    result.error = e instanceof Error ? e.message : String(e);
  }
  return result;
}

// src/main/dnsrelay.ts
var HEDGE_MS = [0, 300, 800];
var VIA_VPN_MS = 1500;
var ATTEMPT_MS = 2500;
var ANSWER_MS = 6e3;
var PENALTY_MS = 2e4;
var REPORT_EVERY_MS = 6e4;
var HEADER_BYTES = 12;
var SERVFAIL = 2;
var UNREACHABLE_MS = 5 * 6e4;
var MAX_REMEMBERED = 2e4;
var OTHER_ANSWER_MS = 800;
var TYPE_A = 1;
function skipName(msg, at) {
  for (; ; ) {
    const size = msg[at];
    if (size === void 0) throw new RangeError("Name past the end");
    if (size === 0) return at + 1;
    if ((size & 192) === 192) return at + 2;
    at += size + 1;
  }
}
function answerAddresses(msg) {
  const found = [];
  try {
    const questions = msg.readUInt16BE(4);
    const answers = msg.readUInt16BE(6);
    let at = HEADER_BYTES;
    for (let i = 0; i < questions; i++) at = skipName(msg, at) + 4;
    for (let i = 0; i < answers; i++) {
      at = skipName(msg, at);
      const type = msg.readUInt16BE(at);
      const size = msg.readUInt16BE(at + 8);
      at += 10;
      if (at + size > msg.length) throw new RangeError("Record past the end");
      if (type === TYPE_A && size === 4) found.push({ ip: `${msg[at]}.${msg[at + 1]}.${msg[at + 2]}.${msg[at + 3]}`, offset: at });
      at += size;
    }
  } catch {
    return [];
  }
  return found;
}
var DohClient = class {
  constructor(name, open2) {
    this.name = name;
    this.open = open2;
  }
  session;
  stalledUntil = 0;
  connect() {
    if (this.session) return this.session;
    const opening = this.open().then((s) => {
      const forget = () => {
        if (this.session === opening) this.session = void 0;
      };
      s.once("close", forget);
      s.once("goaway", forget);
      s.once("error", forget);
      return s;
    });
    opening.catch(() => {
      if (this.session === opening) this.session = void 0;
    });
    return this.session = opening;
  }
  /** Drops the connection, so the next question opens a new one instead of waiting on this one. */
  reset() {
    const old = this.session;
    this.session = void 0;
    void old?.then(
      (s) => s.destroy(),
      () => void 0
    );
  }
  async ask(query) {
    const session = await this.connect();
    return new Promise((resolve, reject) => {
      const req = session.request({ [import_node_http2.constants.HTTP2_HEADER_METHOD]: "POST", [import_node_http2.constants.HTTP2_HEADER_PATH]: "/dns-query", [import_node_http2.constants.HTTP2_HEADER_CONTENT_TYPE]: "application/dns-message", [import_node_http2.constants.HTTP2_HEADER_ACCEPT]: "application/dns-message", [import_node_http2.constants.HTTP2_HEADER_CONTENT_LENGTH]: query.length });
      const chunks = [];
      req.on("response", (headers) => {
        if (Number(headers[import_node_http2.constants.HTTP2_HEADER_STATUS]) !== 200) reject(new Error(`HTTP ${headers[import_node_http2.constants.HTTP2_HEADER_STATUS]}`));
      });
      req.on("data", (d) => chunks.push(d));
      req.once("error", reject);
      req.once("close", () => {
        const body = Buffer.concat(chunks);
        if (body.length >= HEADER_BYTES) resolve(body);
        else reject(new Error("Empty answer"));
      });
      req.end(query);
    });
  }
  close() {
    this.reset();
  }
};
function tlsSession(authority, options) {
  return new Promise((resolve, reject) => {
    const tls = (0, import_node_tls2.connect)({ ...options, ALPNProtocols: ["h2"] });
    const session = (0, import_node_http2.connect)(authority, { createConnection: () => tls });
    const fail = (e) => {
      session.destroy();
      tls.destroy();
      reject(e);
    };
    const timer = setTimeout(() => fail(new Error("Connecting timed out")), ATTEMPT_MS);
    session.once("error", fail);
    session.once("connect", () => {
      clearTimeout(timer);
      session.off("error", fail);
      session.on("error", () => void 0);
      resolve(session);
    });
  });
}
var DnsRelay = class {
  constructor(o) {
    this.o = o;
    this.direct = o.servers.map((s) => {
      const port = s.port ?? 443;
      return new DohClient(s.host, () => tlsSession(`https://${s.servername ?? s.host}`, { host: s.host, port, servername: s.servername, localAddress: o.localAddress }));
    });
    const last = o.vpnServer ?? o.servers[0];
    if (o.proxyPort && last) {
      this.viaVpn = new DohClient("the VPN", async () => {
        const port = o.proxyPort?.();
        if (!port) throw new Error("Not connected yet");
        const raw = await socksDialer(port, last.host, last.port ?? 443)();
        return tlsSession(`https://${last.servername ?? last.host}`, { socket: raw, host: last.host, servername: last.servername });
      });
    }
  }
  server;
  direct;
  viaVpn;
  questions = /* @__PURE__ */ new Map();
  sockets = /* @__PURE__ */ new Set();
  watchdogs = /* @__PURE__ */ new Set();
  stats = { answered: 0, backup: 0, viaVpn: 0, failed: 0, slowest: 0, replaced: 0 };
  /** Addresses Direct traffic timed out on, until when they are avoided. */
  unreachable = /* @__PURE__ */ new Map();
  /** Addresses DNS has given out. */
  seen = /* @__PURE__ */ new Set();
  reportTimer;
  /** For tests and logs: how many questions went out, after joining identical ones. */
  upstreamAsked = 0;
  lastError;
  /** Starts listening on a free local port and returns it. */
  start() {
    return new Promise((resolve, reject) => {
      const server = (0, import_node_net2.createServer)((s) => this.serve(s));
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => {
        this.server = server;
        this.reportTimer = setInterval(() => this.report(), REPORT_EVERY_MS);
        this.reportTimer.unref();
        resolve(server.address().port);
      });
    });
  }
  stop() {
    clearInterval(this.reportTimer);
    this.server?.close();
    this.server = void 0;
    for (const s of this.sockets) s.destroy();
    for (const q of this.questions.values()) for (const t of q.timers) clearTimeout(t);
    for (const t of this.watchdogs) clearTimeout(t);
    this.questions.clear();
    for (const c of [...this.direct, this.viaVpn]) c?.close();
  }
  /** DNS over TCP: each message starts with its 2-byte length. */
  serve(socket) {
    this.sockets.add(socket);
    let buffer = Buffer.alloc(0);
    socket.on("data", (d) => {
      buffer = Buffer.concat([buffer, d]);
      while (buffer.length >= 2 && buffer.length >= 2 + buffer.readUInt16BE(0)) {
        const size = buffer.readUInt16BE(0);
        this.onQuery(buffer.subarray(2, 2 + size), socket);
        buffer = buffer.subarray(2 + size);
      }
    });
    socket.on("error", () => void 0);
    socket.once("close", () => this.sockets.delete(socket));
  }
  onQuery(query, socket) {
    if (query.length < HEADER_BYTES) return;
    const id = query.readUInt16BE(0);
    const key = query.subarray(2).toString("latin1");
    const asked = this.questions.get(key);
    if (asked) return void asked.waiters.push({ socket, id });
    const question = { waiters: [{ socket, id }], timers: [], done: false };
    this.questions.set(key, question);
    const wire = Buffer.from(query);
    wire.writeUInt16BE(0, 0);
    this.resolve(key, question, wire);
  }
  resolve(key, question, wire) {
    const t0 = performance.now();
    const now = Date.now();
    const line = [...this.direct].sort((a, b) => Number(a.stalledUntil > now) - Number(b.stalledUntil > now));
    let failures = 0;
    const attempts = Math.min(line.length, HEDGE_MS.length) + (this.viaVpn ? 1 : 0);
    const asked = /* @__PURE__ */ new Set();
    let pending = 0;
    let held;
    const finish = (answer, client) => {
      if (question.done) return;
      question.done = true;
      this.questions.delete(key);
      for (const t of question.timers) clearTimeout(t);
      const ms = performance.now() - t0;
      this.stats.slowest = Math.max(this.stats.slowest, ms);
      if (!answer) this.stats.failed++;
      else {
        this.stats.answered++;
        if (client === this.viaVpn) this.stats.viaVpn++;
        else if (client !== line[0]) this.stats.backup++;
      }
      for (const w of question.waiters) this.reply(w, answer, wire);
    };
    const ask = (client) => {
      this.upstreamAsked++;
      const watchdog = setTimeout(() => {
        client.stalledUntil = Date.now() + PENALTY_MS;
        client.reset();
      }, ATTEMPT_MS);
      this.watchdogs.add(watchdog);
      const settled = () => {
        clearTimeout(watchdog);
        this.watchdogs.delete(watchdog);
      };
      asked.add(client);
      pending++;
      client.ask(wire).then(
        (answer) => {
          settled();
          pending--;
          client.stalledUntil = 0;
          if (question.done) return;
          const usable = this.avoidUnreachable(answer);
          if (usable) return finish(usable, client);
          if (!held) {
            held = { answer, client };
            question.timers.push(setTimeout(() => finish(answer, client), OTHER_ANSWER_MS));
            for (const other of line) if (!asked.has(other)) ask(other);
          }
          if (!pending) finish(held.answer, held.client);
        },
        (e) => {
          settled();
          pending--;
          this.lastError = `${client.name}: ${e instanceof Error ? e.message : e}`;
          if (held && !pending) finish(held.answer, held.client);
          else if (++failures >= attempts) finish(void 0);
        }
      );
    };
    line.slice(0, HEDGE_MS.length).forEach((client, i) => {
      if (HEDGE_MS[i] === 0) ask(client);
      else question.timers.push(setTimeout(() => !question.done && !asked.has(client) && ask(client), HEDGE_MS[i]));
    });
    if (this.viaVpn) {
      const vpn = this.viaVpn;
      const directSilent = line.every((c) => c.stalledUntil > now);
      question.timers.push(setTimeout(() => !question.done && ask(vpn), directSilent ? 0 : VIA_VPN_MS));
    }
    question.timers.push(setTimeout(() => finish(void 0), ANSWER_MS));
  }
  /**
   * Bridge's log says this address timed out on the direct network. Answers stop offering it for a
   * while. Returns whether DNS gave it out, so looking it up again can lead somewhere else; an
   * address an app dialled by itself isn't helped by that.
   * Only addresses that Direct traffic already failed on count: testing every answer ahead of
   * time would show the ISP which blocked sites the apps on the VPN are looking up.
   */
  markUnreachable(ip) {
    this.unreachable.set(ip, Date.now() + UNREACHABLE_MS);
    if (this.unreachable.size > MAX_REMEMBERED) this.unreachable.delete(this.unreachable.keys().next().value);
    return this.seen.has(ip);
  }
  isUnreachable(ip) {
    const until = this.unreachable.get(ip);
    if (until === void 0) return false;
    if (until > Date.now()) return true;
    this.unreachable.delete(ip);
    return false;
  }
  /**
   * The answer with addresses known to time out replaced by a working one from the same answer, or
   * undefined when it has nothing else to offer. They are overwritten rather than removed because
   * other records in the message may point at the bytes around them. Without this, an app sticks
   * to the bad address: the VPN adapter accepts every connection right away, so the app never sees
   * the failure that would make it try the next address.
   */
  avoidUnreachable(answer) {
    const addresses = answerAddresses(answer);
    if (this.seen.size > MAX_REMEMBERED) this.seen.clear();
    for (const a of addresses) this.seen.add(a.ip);
    const bad = addresses.filter((a) => this.isUnreachable(a.ip));
    if (!bad.length) return answer;
    const good = addresses.find((a) => !this.isUnreachable(a.ip));
    if (!good) return void 0;
    const fixed = Buffer.from(answer);
    for (const a of bad) answer.copy(fixed, a.offset, good.offset, good.offset + 4);
    this.stats.replaced += bad.length;
    return fixed;
  }
  reply(w, answer, query) {
    if (w.socket.destroyed) return;
    const body = Buffer.from(answer ?? query);
    body.writeUInt16BE(w.id, 0);
    if (!answer) body.writeUInt16BE(33152 | SERVFAIL, 2);
    const size = Buffer.alloc(2);
    size.writeUInt16BE(body.length, 0);
    w.socket.write(Buffer.concat([size, body]));
  }
  /** One line a minute, only when lookups had trouble, so the logs say what the network is doing. */
  report() {
    const s = this.stats;
    this.stats = { answered: 0, backup: 0, viaVpn: 0, failed: 0, slowest: 0, replaced: 0 };
    if (!s.backup && !s.viaVpn && !s.failed && !s.replaced) return;
    this.o.log?.(`DNS: in the last minute ${s.answered} answered, ${s.backup} by a backup server, ${s.viaVpn} through the VPN because the direct network didn't answer, ${s.failed} not answered, ${s.replaced} addresses that time out replaced; slowest ${Math.round(s.slowest)} ms${this.lastError ? ` (last problem: ${this.lastError})` : ""}`, s.failed || s.viaVpn ? "warn" : "info");
    this.lastError = void 0;
  }
};

// src/main/resolve.ts
var import_node_dns = require("node:dns");
var import_node_fs2 = require("node:fs");
var import_node_net3 = require("node:net");
function isBogusAddress(ip) {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n))) return true;
  const [a, b] = p;
  return a === 0 || a === 10 || // includes Iran's DNS-poisoning answers 10.10.34.x
  a === 127 || a === 100 && b >= 64 && b <= 127 || a === 169 && b === 254 || a === 172 && b >= 16 && b <= 31 || a === 192 && b === 168 || a === 198 && (b === 18 || b === 19) || a >= 224;
}
async function viaDoh(url, name) {
  const res = await fetch(url, { headers: { accept: "application/dns-json" }, signal: AbortSignal.timeout(4e3) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const body = await res.json();
  const ip = body.Answer?.find((a) => a.type === 1 && !isBogusAddress(a.data))?.data;
  if (!ip) throw new Error(`no usable A record for ${name}`);
  return ip;
}
async function viaSystem(name) {
  const { address } = await import_node_dns.promises.lookup(name, { family: 4 });
  if (isBogusAddress(address)) throw new Error(`poisoned answer ${address}`);
  return address;
}
async function dnsServerWorks(server) {
  const resolver = new import_node_dns.Resolver({ timeout: 2e3, tries: 1 });
  resolver.setServers([server]);
  return new Promise((resolve) => {
    resolver.resolve4("www.microsoft.com", (err, addresses) => resolve(!err && addresses.some((a) => !isBogusAddress(a))));
  });
}
function dnsQueryPacket(name) {
  const header = Buffer.from([0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
  const labels = name.split(".").map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)]));
  return Buffer.concat([header, ...labels, Buffer.from([0, 0, 1, 0, 1])]);
}
async function dohServerWorks(server) {
  try {
    const q = dnsQueryPacket("www.microsoft.com").toString("base64url");
    const res = await fetch(`https://${server}/dns-query?dns=${q}`, {
      headers: { accept: "application/dns-message" },
      signal: AbortSignal.timeout(3e3)
    });
    if (!res.ok) return false;
    const body = Buffer.from(await res.arrayBuffer());
    return body.length > 12 && body.readUInt16BE(6) > 0;
  } catch {
    return false;
  }
}
var DOH_SERVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1", "8.8.4.4", "149.112.112.112"];
async function pickDirectDns(networkServers, log) {
  const doh = await Promise.all(DOH_SERVERS.map((s) => dohServerWorks(s)));
  const working = DOH_SERVERS.filter((_, i) => doh[i]);
  if (working.length) return { type: "https", server: working[0], working };
  log("No DNS-over-HTTPS server answered; falling back to plain DNS, Direct apps may not resolve names", "warn");
  const usable = networkServers.filter((s) => !s.startsWith("127.") && !s.startsWith("0."));
  for (const s of networkServers.filter((s2) => !usable.includes(s2))) log(`Network DNS ${s} is a local address (probably another VPN tool), not using it`, "warn");
  const candidates = [.../* @__PURE__ */ new Set([...usable, "1.1.1.1", "8.8.8.8"])];
  const results = await Promise.all(candidates.map((s) => dnsServerWorks(s)));
  const udp = candidates.find((_, i) => results[i]);
  return udp ? { type: "udp", server: udp } : void 0;
}
var RECENT_MS = 6e4;
var ServerResolver = class {
  constructor(cacheFile, log) {
    this.cacheFile = cacheFile;
    this.log = log;
    try {
      if ((0, import_node_fs2.existsSync)(cacheFile)) this.cache = JSON.parse((0, import_node_fs2.readFileSync)(cacheFile, "utf8"));
    } catch {
      this.cache = {};
    }
  }
  cache = {};
  recent = /* @__PURE__ */ new Map();
  /**
   * Returns a usable IPv4 address for a server host, or undefined if none could be found. Asking
   * again soon gets the same answer: a subscription's servers often share one host, and a
   * server test would otherwise open two connections to public DNS servers for each of them.
   */
  async resolve(host) {
    if ((0, import_node_net3.isIP)(host)) return { ip: host, source: "address in link" };
    const recent = this.recent.get(host);
    if (recent && Date.now() - recent.at < RECENT_MS) return recent.result;
    const result = this.lookup(host);
    this.recent.set(host, { at: Date.now(), result });
    return result;
  }
  async lookup(host) {
    const name = encodeURIComponent(host);
    const sources = [
      ["Cloudflare DoH", viaDoh(`https://1.1.1.1/dns-query?name=${name}&type=A`, host)],
      ["Google DoH", viaDoh(`https://8.8.8.8/resolve?name=${name}&type=A`, host)],
      ["system DNS", viaSystem(host)]
    ];
    try {
      const result = await Promise.any(sources.map(([source, p]) => p.then((ip) => ({ ip, source }))));
      if (this.cache[host] !== result.ip) {
        this.cache[host] = result.ip;
        try {
          (0, import_node_fs2.writeFileSync)(this.cacheFile, JSON.stringify(this.cache, null, 2));
        } catch {
        }
      }
      return result;
    } catch (e) {
      const reasons = e instanceof AggregateError ? e.errors.map((err, i) => `${sources[i][0]}: ${err instanceof Error ? err.message : err}`) : [String(e)];
      const cached = this.cache[host];
      if (cached) {
        this.log(`Could not look up ${host} (${reasons.join("; ")}), using last known address ${cached}`, "warn");
        return { ip: cached, source: "last known address" };
      }
      this.log(`Could not look up ${host}: ${reasons.join("; ")}`, "warn");
      return void 0;
    }
  }
};

// src/main/system.ts
var import_node_child_process = require("node:child_process");
var import_node_net4 = require("node:net");
var import_node_os = require("node:os");
var import_node_util = require("node:util");
var exec = (0, import_node_util.promisify)(import_node_child_process.execFile);
function powershell(script) {
  return exec("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], {
    windowsHide: true,
    maxBuffer: 16 * 1024 * 1024
  });
}
function psQuote(s) {
  return "'" + s.replace(/'/g, "''") + "'";
}
function freePort() {
  return new Promise((resolve, reject) => {
    const srv = (0, import_node_net4.createServer)();
    srv.unref();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
  });
}
var INTERNET_SETTINGS = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
var REFRESH = `
Add-Type -Namespace Bridge -Name WinInet -MemberDefinition '[DllImport("wininet.dll")] public static extern bool InternetSetOption(System.IntPtr h, int o, System.IntPtr b, int l);'
[void][Bridge.WinInet]::InternetSetOption([System.IntPtr]::Zero, 39, [System.IntPtr]::Zero, 0)
[void][Bridge.WinInet]::InternetSetOption([System.IntPtr]::Zero, 37, [System.IntPtr]::Zero, 0)
`;
var RUN_ONCE = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
var PROXY_CLEANUP_VALUE = "BridgeClearProxy";
function proxyCleanupCommand(port, settingsPath = INTERNET_SETTINGS) {
  return `powershell -w hidden -nop -c "$p='${settingsPath}';if((gp $p).ProxyServer -eq '127.0.0.1:${port}'){sp $p ProxyEnable 0}"`;
}
async function setSystemProxy(port) {
  const private172 = Array.from({ length: 16 }, (_, i) => `172.${16 + i}.*`).join(";");
  const bypass = `localhost;127.*;10.*;${private172};192.168.*;<local>`;
  await powershell(`
Set-ItemProperty -Path '${RUN_ONCE}' -Name ${PROXY_CLEANUP_VALUE} -Value ${psQuote(proxyCleanupCommand(port))}
Set-ItemProperty -Path '${INTERNET_SETTINGS}' -Name ProxyEnable -Value 1
Set-ItemProperty -Path '${INTERNET_SETTINGS}' -Name ProxyServer -Value '127.0.0.1:${port}'
Set-ItemProperty -Path '${INTERNET_SETTINGS}' -Name ProxyOverride -Value '${bypass}'
${REFRESH}`);
}
async function clearSystemProxy(port) {
  await powershell(`
Remove-ItemProperty -Path '${RUN_ONCE}' -Name ${PROXY_CLEANUP_VALUE} -ErrorAction SilentlyContinue
$s = Get-ItemProperty -Path '${INTERNET_SETTINGS}'
if ($s.ProxyServer -eq '127.0.0.1:${port}') {
  Set-ItemProperty -Path '${INTERNET_SETTINGS}' -Name ProxyEnable -Value 0
  ${REFRESH}
}`);
}
function hasInternetIpv6(realAdapter, interfaces = (0, import_node_os.networkInterfaces)()) {
  return Object.entries(interfaces).some(
    ([name, addresses]) => (realAdapter ? name === realAdapter : name !== "Bridge") && (addresses || []).some((a) => a.family === "IPv6" && !a.internal && /^[23]/.test(a.address) && !/^(2001:0:|2002:)/i.test(a.address))
  );
}
async function networkInfo() {
  try {
    const { stdout } = await powershell(`
$phys = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up')
$metric = { $_.RouteMetric + (Get-NetIPInterface -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).InterfaceMetric }
$routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -ne 'Bridge' })
$best = $routes | Where-Object { $phys.ifIndex -contains $_.ifIndex } | Sort-Object $metric | Select-Object -First 1
if (-not $best) { $best = $routes | Sort-Object $metric | Select-Object -First 1 }
$dns = @()
if ($best) { $dns = @((Get-DnsClientServerAddress -InterfaceIndex $best.ifIndex -AddressFamily IPv4).ServerAddresses) }
$virtual = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'Bridge' -and ($phys.ifIndex -notcontains $_.ifIndex) -and $_.InterfaceDescription -notmatch 'Hyper-V|Loopback|Bluetooth|VirtualBox|VMware' })
# Only adapters that are up carry traffic; others may keep a stale default route
# (EZConnect's WireSock adapter does, even with EZConnect closed).
$others = @($virtual | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { "$($_.Name) ($($_.InterfaceDescription))" })
$tunnelRoutes = @($routes | Where-Object { $virtual.ifIndex -contains $_.ifIndex } | Sort-Object $metric)
$virtualRoute = $tunnelRoutes.Count -gt 0
# The other tool's adapter for "Other VPN" apps: prefer one that is up, else one holding a
# default route (it comes up when that tool connects, even after Bridge started).
$upTunnel = $tunnelRoutes | Where-Object { $i = $_.ifIndex; ($virtual | Where-Object ifIndex -eq $i).Status -eq 'Up' } | Select-Object -First 1
$otherIf = if ($upTunnel) { $upTunnel.InterfaceAlias } elseif ($tunnelRoutes.Count) { $tunnelRoutes[0].InterfaceAlias } else { ($virtual | Where-Object Status -eq 'Up' | Select-Object -First 1).Name }
$defaults = @($routes | Sort-Object $metric | ForEach-Object { "$($_.InterfaceAlias) (metric $(& $metric))" })
[pscustomobject]@{ alias = $best.InterfaceAlias; dns = $dns; others = $others; defaults = $defaults; virtualRoute = $virtualRoute; otherIf = $otherIf } | ConvertTo-Json -Compress`);
    const j = JSON.parse(stdout.trim() || "{}");
    const arr = (v) => Array.isArray(v) ? v : v ? [v] : [];
    const otherTunnels = arr(j.others);
    return {
      interfaceAlias: j.alias || void 0,
      dnsServers: arr(j.dns).filter((ip) => /^\d+\.\d+\.\d+\.\d+$/.test(ip)),
      otherTunnels,
      defaultRoutes: arr(j.defaults),
      bindPhysical: otherTunnels.length > 0 || !!j.virtualRoute,
      otherInterface: j.otherIf || void 0
    };
  } catch {
    return { dnsServers: [], otherTunnels: [], defaultRoutes: [], bindPhysical: false };
  }
}
async function setHostRoutes(ips, interfaceAlias, add) {
  if (!ips.length) return;
  const list3 = ips.map((ip) => psQuote(`${ip}/32`)).join(",");
  const alias = psQuote(interfaceAlias);
  await powershell(
    add ? `foreach ($p in @(${list3})) { New-NetRoute -DestinationPrefix $p -InterfaceAlias ${alias} -NextHop 0.0.0.0 -RouteMetric 0 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null }` : `foreach ($p in @(${list3})) { Remove-NetRoute -DestinationPrefix $p -InterfaceAlias ${alias} -Confirm:$false -ErrorAction SilentlyContinue }`
  );
}
async function flushDns() {
  await exec("ipconfig", ["/flushdns"], { windowsHide: true }).catch(() => void 0);
}

// src/main/handoff.ts
var HANDOFF_MAX_ROUTES = 256;
function isPublicIPv4(ip) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if ([a, b, Number(m[3]), Number(m[4])].some((n) => n > 255)) return false;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b < 128) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b < 32) return false;
  if (a === 192 && b === 168) return false;
  if (a === 198 && (b === 18 || b === 19)) return false;
  return true;
}
function handoffCandidates(connections, known, limit = HANDOFF_MAX_ROUTES) {
  const shared = /* @__PURE__ */ new Set();
  const wanted = /* @__PURE__ */ new Set();
  for (const c of connections) {
    const ip = c.metadata.destinationIP;
    if (!ip || !isPublicIPv4(ip)) continue;
    if (c.chains?.[0] === "direct-other") {
      if (c.metadata.network === "udp") wanted.add(ip);
    } else shared.add(ip);
  }
  const room = Math.max(0, limit - known.size);
  return [...wanted].filter((ip) => !known.has(ip) && !shared.has(ip)).slice(0, room);
}

// src/main/mtu.ts
var import_node_child_process2 = require("node:child_process");
var HEADERS = 28;
var MAX_PAYLOAD = 1500 - HEADERS;
var MIN_PAYLOAD = 1200 - HEADERS;
var SMALL_PAYLOAD = 64;
var MIN_ADAPTER_MTU = 1280;
var VPN_HEADERS = 80;
var MTU_TARGETS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"];
var windowsPing = (host, payload, source) => new Promise((resolve) => {
  const args = ["-n", "1", "-w", "1500", "-f", "-l", String(payload), ...source ? ["-S", source] : [], host];
  (0, import_node_child_process2.execFile)("ping", args, { windowsHide: true, timeout: 5e3 }, (_e, stdout) => resolve(/TTL=/i.test(String(stdout))));
});
async function fits(ping, host, payload, source) {
  return await ping(host, payload, source) || ping(host, payload, source);
}
function recommendMtu(pathMtu) {
  return pathMtu >= 1500 ? void 0 : Math.max(MIN_ADAPTER_MTU, pathMtu - VPN_HEADERS);
}
async function findPathMtu(targets, source, ping = windowsPing) {
  let target;
  for (const t of targets) {
    if (await fits(ping, t, SMALL_PAYLOAD, source)) {
      target = t;
      break;
    }
  }
  if (!target) throw new Error("No test address answered ping on this network, so the MTU can't be measured. Disconnect the VPN and try again.");
  const done = (payload) => ({ pathMtu: payload + HEADERS, target, recommended: recommendMtu(payload + HEADERS) });
  if (await fits(ping, target, MAX_PAYLOAD, source)) return done(MAX_PAYLOAD);
  if (!await fits(ping, target, MIN_PAYLOAD, source)) throw new Error("Even 1200-byte packets don't get through, so packet size isn't the problem here.");
  let low = MIN_PAYLOAD;
  let high = MAX_PAYLOAD;
  while (high - low > 1) {
    const middle = Math.floor((low + high) / 2);
    if (await fits(ping, target, middle, source)) low = middle;
    else high = middle;
  }
  return done(low);
}

// src/main/publicconfigs.ts
var import_node_net5 = require("node:net");
var PUBLIC_TEST_MAX = 400;
var PUBLIC_SAMPLE_MAX = 30;
var PUBLIC_SAMPLE_WORKERS = 5;
var PUBLIC_SAMPLE_BYTES = 1e6;
var PUBLIC_SAMPLE_MS = 2500;
var PUBLIC_MEASURE_MAX = 12;
var PUBLIC_MEASURE_BYTES = 5e6;
var PUBLIC_MEASURE_MS = 4e3;
var PUBLIC_KEEP = 8;
var SLOW_PING_MS = 1500;
var STRONG_SHARE = 0.8;
var MAX_LINKS_PER_LIST = 5e3;
var SOURCES = [
  { repo: "barry-far/V2ray-Config", path: "Splitted-By-Protocol/vless.txt" },
  { repo: "barry-far/V2ray-Config", path: "Splitted-By-Protocol/trojan.txt" },
  { repo: "MatinGhanbari/v2ray-configs", path: "subscriptions/v2ray/super-sub.txt" },
  { repo: "Danialsamadi/v2go", path: "Sub1.txt" },
  { repo: "Rayan-Config/C-Sub", path: "configs/proxy.txt" },
  // Gathered from Telegram channels.
  { repo: "Surfboardv2ray/TGParse", path: "splitted/mixed" },
  { repo: "hamedcode/port-based-v2ray-configs", path: "sub/vless.txt" },
  { repo: "nyeinkokoaung404/V2ray-Configs", path: "All_Configs_Sub.txt" },
  { repo: "mahdibland/V2RayAggregator", branch: "master", path: "Eternity.txt" }
];
var where = ({ repo, branch = "main", path }) => [`https://raw.githubusercontent.com/${repo}/${branch}/${path}`, `https://cdn.jsdelivr.net/gh/${repo}@${branch}/${path}`];
var PUBLIC_SOURCE_LISTS = SOURCES.map(where);
var PUBLIC_CLEAN_LIST = where({ repo: "m4hdisa/Bridge-configs", path: "clean.txt" });
var PUBLIC_CLOUDFLARE_LIST = where({ repo: "m4hdisa/Bridge-configs", path: "cloudflare.txt" });
var COLLECTOR_EXTRA_LISTS = [
  "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt",
  "https://raw.githubusercontent.com/itsyebekhe/PSG/main/subscriptions/xray/mix",
  "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/all_configs.txt",
  "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mtn/sub_1.txt",
  "https://raw.githubusercontent.com/iampedii/whitedns-sub/refs/heads/main/base64.txt",
  "https://raw.githubusercontent.com/iampedii/whitedns-sub/refs/heads/main/cloudflare-base64.txt",
  "https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs_tested.txt",
  "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
  "https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/refs/heads/main/mix/sub.html",
  "https://raw.githubusercontent.com/ShadowException/VPN/refs/heads/main/configs/VPN-cat",
  "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
  "https://raw.githubusercontent.com/v2FreeHub/v2hub-configs/refs/heads/main/Sub-AutoUpdate",
  "https://raw.githubusercontent.com/prominbro/sub/refs/heads/main/212.txt",
  "https://raw.githubusercontent.com/Mahdi0024/ProxyCollector/master/sub/proxies.txt",
  "https://raw.githubusercontent.com/luxxuria/harvester/refs/heads/main/speed_tested.txt",
  "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt",
  "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",
  "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/all_configs.txt",
  "https://raw.githubusercontent.com/ripaojiedian/freenode/main/sub",
  "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
  "https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/vless",
  "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
  "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
  "https://raw.githubusercontent.com/HnCgs/HomayounConfigs/refs/heads/main/configs.txt"
].map((url) => [url]);
function publicKey(s) {
  const t = s.outbound.transport;
  const x = s.xray?.streamSettings;
  const front = x?.wsSettings ?? x?.httpupgradeSettings ?? x?.xhttpSettings;
  const host = t?.headers?.Host ?? t?.host ?? front?.host;
  return host ? `${s.server}:${s.port}|${host}|${t?.path ?? t?.service_name ?? front?.path ?? ""}` : `${s.server}:${s.port}`;
}
function middleOf(values) {
  return [...values].sort((a, b) => a - b)[Math.floor((values.length - 1) / 2)];
}
function rankPublic(found) {
  const slow = (f) => f.latency > SLOW_PING_MS ? 1 : 0;
  return [...found].sort((a, b) => slow(a) - slow(b) || (b.downMbps ?? 0) - (a.downMbps ?? 0) || a.latency - b.latency);
}
async function fetchPublicLinks(get, log, sources = [PUBLIC_CLEAN_LIST, PUBLIC_CLOUDFLARE_LIST, ...PUBLIC_SOURCE_LISTS]) {
  const lists = await Promise.all(
    sources.map(async (urls) => {
      for (const url of urls) {
        try {
          const links = extractLinks(await get(url));
          if (links.length) return links.slice(0, MAX_LINKS_PER_LIST);
        } catch (e) {
          log(`Public configs: ${new URL(url).hostname} didn't answer (${e instanceof Error ? e.message : e})`);
        }
      }
      return [];
    })
  );
  const own = sources.filter((s) => s === PUBLIC_CLEAN_LIST || s === PUBLIC_CLOUDFLARE_LIST).map((s) => lists[sources.indexOf(s)]);
  return { links: [...new Set(lists.flat())], clean: [...new Set(own.flat())] };
}
function isPrivateAddress(ip) {
  if ((0, import_node_net5.isIP)(ip) === 6) return /^(::1?$|f[cd]|fe[89ab]|::ffff:)/i.test(ip);
  const [a, b] = ip.split(".").map(Number);
  return a === 0 || a === 10 || a === 127 || a === 100 && b >= 64 && b <= 127 || a === 169 && b === 254 || a === 172 && b >= 16 && b <= 31 || a === 192 && b === 168 || a >= 224;
}
var LOCAL_HOST = /(^|\.)(localhost|local|lan|internal|home|ir)$/i;
function publicRefusal(s) {
  if (s.warp) return "a WARP config";
  const host = s.server.replace(/^\[|\]$/g, "");
  if ((0, import_node_net5.isIP)(host) ? isPrivateAddress(host) : LOCAL_HOST.test(host) || !host.includes(".")) return "a local or Iranian address";
  const o = s.outbound;
  if (s.protocol === "vmess" && /^(none|zero)$/.test(o.security ?? "")) return "not encrypted";
  if (s.protocol === "shadowsocks" && /^(none|plain)$/.test(o.method ?? "")) return "not encrypted";
  const xray = s.xray;
  if (o.tls?.insecure || xray?.streamSettings?.tlsSettings?.allowInsecure) return "doesn't check the server's certificate";
  if ((s.protocol === "vless" || s.protocol === "trojan") && !o.tls?.enabled && (!xray || needsRelay(xray))) return "not encrypted";
  return void 0;
}
function spreadOut(servers, max) {
  const ranges = /* @__PURE__ */ new Map();
  const protocols = /* @__PURE__ */ new Map();
  const picked = [];
  for (const s of servers) {
    if (picked.length >= max) break;
    const range = (0, import_node_net5.isIP)(s.server) === 4 ? s.server.split(".").slice(0, 3).join(".") : s.server;
    if ((ranges.get(range) ?? 0) >= 2 || (protocols.get(s.protocol) ?? 0) >= Math.ceil(max / 2)) continue;
    ranges.set(range, (ranges.get(range) ?? 0) + 1);
    protocols.set(s.protocol, (protocols.get(s.protocol) ?? 0) + 1);
    picked.push(s);
  }
  return [...picked, ...servers.filter((s) => !picked.includes(s))].slice(0, max);
}
function shuffled(items, random) {
  const a = [...items];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}
function isStrong(s) {
  return !!s.outbound.tls?.enabled || !!s.xray?.streamSettings?.security || s.protocol === "hysteria2" || s.protocol === "tuic";
}
function choosePublicCandidates(links, skip, max = PUBLIC_TEST_MAX, random = Math.random, first = []) {
  if (first.length) {
    const chosen = choosePublicCandidates(first, skip, Math.floor(max / 2), random);
    const held = /* @__PURE__ */ new Set([...skip, ...chosen.map(publicKey)]);
    return [...chosen, ...choosePublicCandidates(links, held, max - chosen.length, random)];
  }
  const seen = new Set(skip);
  const usable = [];
  for (const link of shuffled(links, random)) {
    if (!/^(vless|vmess|trojan|ss|hysteria2|hy2|tuic):\/\//i.test(link)) continue;
    try {
      const s = parseLink(link);
      const key = publicKey(s);
      if (seen.has(key) || publicRefusal(s)) continue;
      seen.add(key);
      usable.push(s);
    } catch {
    }
  }
  const strong = usable.filter(isStrong);
  const rest = usable.filter((s) => !isStrong(s));
  const leading = strong.slice(0, Math.ceil(max * STRONG_SHARE));
  const others = rest.slice(0, max - leading.length);
  return [...leading, ...others, ...strong.slice(leading.length)].slice(0, max);
}

// src/main/warpplus.ts
var import_node_https = require("node:https");
var import_node_tls3 = require("node:tls");
var API_HOSTS = ["api.devices.cloudflare.com", "api.cloudflareclient.com"];
var API_VERSION = "v0a4471";
var CLIENT_VERSION = "a-6.35-4471";
var TIMEOUT_MS = 15e3;
var WarpApiError = class extends Error {
};
function isWarpKey(key) {
  return /^[A-Za-z0-9]{8}-[A-Za-z0-9]{8}-[A-Za-z0-9]{8}$/.test(key);
}
function warpCredentials(identity) {
  const field = (name) => identity.match(new RegExp(`^${name}\\s*=\\s*"([^"]+)"`, "m"))?.[1];
  const deviceId = field("device_id");
  const token = field("access_token");
  if (!deviceId || !token) throw new Error("The WARP account file is incomplete");
  return { deviceId, token };
}
function accountInfo(body) {
  const accountType = body.account_type ?? "free";
  const premiumData = Number(body.premium_data) || 0;
  return { accountType, plus: premiumData > 0 || !["free", "team"].includes(accountType), license: body.license, premiumData };
}
function apiErrorText(body) {
  try {
    const message = JSON.parse(body).errors?.[0]?.message;
    return message || void 0;
  } catch {
    return void 0;
  }
}
function open(host, port) {
  const options = { servername: host, ALPNProtocols: ["http/1.1"], minVersion: "TLSv1.2", maxVersion: "TLSv1.2" };
  if (!port) return Promise.resolve((0, import_node_tls3.connect)({ host, port: 443, ...options }));
  return socksDialer(port, host)().then((socket) => (0, import_node_tls3.connect)({ socket, ...options }));
}
function callHost(host, cred, method, data, port, under) {
  return open(host, port).then(
    (socket) => new Promise((resolve, reject) => {
      const req = (0, import_node_https.request)(
        {
          host,
          method,
          path: `/${API_VERSION}/reg/${encodeURIComponent(cred.deviceId)}/account${under}`,
          createConnection: () => socket,
          headers: {
            "User-Agent": "okhttp/3.12.1",
            "CF-Client-Version": CLIENT_VERSION,
            Authorization: `Bearer ${cred.token}`,
            ...data ? { "Content-Type": "application/json; charset=UTF-8", "Content-Length": Buffer.byteLength(data) } : {}
          }
        },
        (res) => {
          let body = "";
          res.setEncoding("utf8");
          res.on("data", (d) => body += d);
          res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
          res.on("error", reject);
        }
      );
      req.setTimeout(TIMEOUT_MS, () => req.destroy(new Error("timed out")));
      req.on("error", reject);
      socket.once("error", reject);
      req.end(data);
    })
  );
}
async function call(cred, method, data, port, under = "") {
  let lastError;
  for (const host of API_HOSTS) {
    try {
      const { status, body } = await callHost(host, cred, method, data, port, under);
      if (status >= 200 && status < 300) return body;
      if (status === 403 && !apiErrorText(body)) {
        lastError = new Error(`HTTP ${status}`);
        continue;
      }
      throw new WarpApiError(apiErrorText(body) ?? `HTTP ${status}`);
    } catch (e) {
      if (e instanceof WarpApiError) throw e;
      lastError = e;
    }
  }
  throw lastError instanceof Error ? lastError : new Error(String(lastError));
}
async function getWarpAccount(cred, port) {
  return accountInfo(JSON.parse(await call(cred, "GET", void 0, port)));
}
async function putWarpLicense(cred, license, port) {
  await call(cred, "PUT", JSON.stringify({ license }), port);
}

// src/main/core.ts
function socksOutbound(port) {
  return { type: "socks", server: "127.0.0.1", server_port: port, version: "5" };
}
function portOpen(port) {
  return new Promise((resolve) => {
    const s = (0, import_node_net6.connect)({ host: "127.0.0.1", port });
    s.once("connect", () => {
      s.destroy();
      resolve(true);
    });
    s.once("error", () => resolve(false));
  });
}
function connectTime(ip, port, localAddress, timeoutMs = 3e3) {
  return new Promise((resolve, reject) => {
    const started = performance.now();
    const s = (0, import_node_net6.connect)({ host: ip, port, localAddress });
    const timer = setTimeout(() => s.destroy(new Error("timeout")), timeoutMs);
    s.once("connect", () => {
      clearTimeout(timer);
      s.destroy();
      resolve(Math.max(1, Math.round(performance.now() - started)));
    });
    s.once("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
  });
}
function adapterIpv4(alias) {
  if (!alias) return void 0;
  return (0, import_node_os2.networkInterfaces)()[alias]?.find((a) => a.family === "IPv4" && !a.internal)?.address;
}
async function killProcess(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  child.removeAllListeners("exit");
  await new Promise((resolve) => {
    child.once("exit", () => resolve());
    child.kill();
  });
}
var mbpsText = (v) => v === void 0 ? "-" : v.toFixed(1);
var speedLine = (r) => `down ${mbpsText(r.downMbps)} Mbps, up ${mbpsText(r.upMbps)} Mbps, ${Math.round(r.usedBytes / 1e6)} MB used${r.error ? ` (${r.error})` : ""}`;
var Cancelled = class extends Error {
  constructor() {
    super("Connecting was cancelled");
  }
};
var MAX_LOGS = 1e3;
var WARP_ATTEMPT_MS = 75e3;
var WARP_PEER_MS = 25e3;
var WARP_PREFER_WAIT_MS = 6e4;
var PSIPHON_READY_MS = 9e4;
var WARP_PREFER_H3_MS = 8e3;
var WARP_FIND_MORE_MS = 9e4;
var WARP_FIND_ROUNDS = 2;
var WARP_FIND_MAX = 12;
var WARP_FIND_ATTEMPT_MS = 3e4;
var DIRECT_TEST_HOSTS = ["www.aparat.com", "www.digikala.com", "divar.ir"];
var DIRECT_TEST_URLS = DIRECT_TEST_HOSTS.map((h) => `http://${h}/`);
var RULE_RELOAD_DELAY_MS = 1500;
var DIRECT_TIMEOUT = /open connection to (\d+\.\d+\.\d+\.\d+):\d+ using outbound\/direct\[direct\]: dial tcp \S+: i\/o timeout/;
var DIRECT_TIMEOUT_FLUSH_MS = 3e4;
async function clashPost(api, path) {
  await fetch(`http://127.0.0.1:${api.port}${path}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${api.secret}` },
    signal: AbortSignal.timeout(3e3)
  });
}
async function clashDelete(api, path) {
  await fetch(`http://127.0.0.1:${api.port}${path}`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${api.secret}` },
    signal: AbortSignal.timeout(3e3)
  });
}
async function clashGet(api, path, timeoutMs = 3e3) {
  const res = await fetch(`http://127.0.0.1:${api.port}${path}`, {
    headers: { Authorization: `Bearer ${api.secret}` },
    signal: AbortSignal.timeout(timeoutMs)
  });
  if (!res.ok) throw new Error(`Clash API ${path}: HTTP ${res.status} ${await res.text()}`);
  return await res.json();
}
async function launch(singBox, configFile, workDir, api, onLine) {
  const child = (0, import_node_child_process3.spawn)(singBox, ["run", "-c", configFile, "-D", workDir], { windowsHide: true });
  const feed = (isErr) => {
    let buf = "";
    return (chunk) => {
      buf += chunk.toString();
      const lines = buf.split(/\r?\n/);
      buf = lines.pop() || "";
      for (const l of lines) if (l.trim()) onLine(l, isErr);
    };
  };
  child.stdout?.on("data", feed(false));
  child.stderr?.on("data", feed(true));
  let exited = false;
  child.once("exit", () => exited = true);
  const deadline = Date.now() + 15e3;
  while (Date.now() < deadline) {
    if (exited) throw new Error("sing-box exited during startup (see Logs)");
    try {
      await clashGet(api, "/version", 1e3);
      return child;
    } catch {
      await new Promise((r) => setTimeout(r, 200));
    }
  }
  child.kill();
  throw new Error("sing-box did not become ready within 15 seconds");
}
var Core = class extends import_node_events.EventEmitter {
  constructor(paths) {
    super();
    this.paths = paths;
    (0, import_node_fs3.mkdirSync)(paths.dataDir, { recursive: true });
    this.resolver = new ServerResolver((0, import_node_path2.join)(paths.dataDir, "server-addresses.json"), (text, level) => this.log(text, level));
  }
  status = { state: "stopped" };
  logs = [];
  child;
  xrayChild;
  /** aether.exe processes: several while WARP methods race, one once connected. */
  warpChildren = /* @__PURE__ */ new Set();
  /**
   * One of the user's own servers, for creating the WARP account through it when Cloudflare's
   * WARP service is blocked directly. Set by the app shell.
   */
  warpHelper;
  /** Called when a saved WARP config's gateway stopped answering and the scan found another. */
  onWarpPeer;
  /** True while "Find configs" runs; connecting waits for it. */
  scanningWarp = false;
  dnsRelay;
  /** The real Wi-Fi / Ethernet adapter while connected in a TUN mode. */
  realAdapter;
  api;
  proxyPort;
  /** SOCKS port that always exits through the VPN (see BuildOptions.probePort); set while running. */
  probePort;
  /** The WARP tunnel in use, if any; Aether keeps its exit country up to date. */
  wonWarp;
  /** Exit country Aether reported for the WARP tunnel in use, e.g. "DE". */
  get warpExit() {
    return this.wonWarp?.exit;
  }
  statsTimer;
  healthTimer;
  settings;
  lastTotals = { up: 0, down: 0, at: 0 };
  seenConns = /* @__PURE__ */ new Map();
  appTotals = /* @__PURE__ */ new Map();
  /** The other tool's adapter that "Other VPN" apps are handed to (TUN modes only), see handoff.ts. */
  handoffIf;
  handoffIps = /* @__PURE__ */ new Set();
  resolver;
  /**
   * Returns the server with its hostname replaced by a safely resolved IP (see resolve.ts).
   * Must run before TUN starts, so the lookups use the real network.
   */
  async pinAddress(server, quiet = false) {
    const host = server.outbound.server;
    if (typeof host !== "string") return server;
    const r = await this.resolver.resolve(host);
    if (!r) return server;
    if (!quiet && r.ip !== host) this.log(`Server ${host} -> ${r.ip} (${r.source})`);
    return { ...server, outbound: withServerIp(server.outbound, r.ip) };
  }
  /** Same as pinAddress, for a server's Xray outbound. */
  async pinXray(outbound, quiet = false) {
    const { host } = xrayServer(outbound);
    const r = host ? await this.resolver.resolve(host) : void 0;
    if (!r) return outbound;
    if (!quiet && r.ip !== host) this.log(`Server ${host} -> ${r.ip} (${r.source}, Xray)`);
    return xrayWithServerIp(outbound, r.ip);
  }
  xrayLine = (line) => {
    const level = /\[(Error)\]|Failed/.test(line) ? "error" : /\[Warning\]/.test(line) ? "warn" : "info";
    this.log(`[xray] ${line}`, level);
  };
  /** Starts xray.exe with one local SOCKS inbound per entry; resolves once the first port accepts connections. */
  async launchXray(entries, name, bindInterface) {
    const exe = this.paths.xray;
    if (!exe || !(0, import_node_fs3.existsSync)(exe)) throw new Error("Xray core not found; this server needs it (reinstall Bridge)");
    const file = (0, import_node_path2.join)(this.paths.dataDir, `${name}.json`);
    const withRelays = await Promise.all(entries.map(async (e) => needsRelay(e.outbound) ? { ...e, relayPort: await freePort() } : e));
    (0, import_node_fs3.writeFileSync)(file, JSON.stringify(buildXrayConfig(withRelays, "warning", bindInterface), null, 2));
    const child = (0, import_node_child_process3.spawn)(exe, ["run", "-c", file], { windowsHide: true });
    const feed = (chunk) => chunk.toString().split(/\r?\n/).filter((l) => l.trim()).forEach(this.xrayLine);
    child.stdout?.on("data", feed);
    child.stderr?.on("data", feed);
    let exited = false;
    child.once("exit", () => exited = true);
    const deadline = Date.now() + 1e4;
    while (Date.now() < deadline) {
      if (exited) throw new Error("Xray exited during startup (see Logs)");
      if (await portOpen(entries[0].port)) return child;
      await new Promise((r) => setTimeout(r, 150));
    }
    child.kill();
    throw new Error("Xray did not become ready within 10 seconds");
  }
  /**
   * For servers run by Xray, starts xray.exe and returns the server as sing-box should see it:
   * a SOCKS hop into Xray. Other servers are returned unchanged.
   */
  async viaXray(server, bindInterface) {
    if (server.engine !== "xray") return server;
    if (!server.xray) throw new Error("This server has no Xray settings; update its subscription or import it again");
    const port = await freePort();
    this.xrayChild = await this.launchXray([{ port, outbound: await this.pinXray(server.xray) }], "xray-config", bindInterface);
    this.xrayChild.once("exit", (code) => {
      if (this.status.state !== "running") return;
      this.log(`Xray stopped unexpectedly (exit code ${code})`, "error");
      void this.stop().then(() => this.setStatus({ state: "stopped", error: "Xray core stopped unexpectedly, see Logs" }));
    });
    this.log(`Using Xray core for ${server.name} (local SOCKS ${port}${bindInterface ? `, bound to "${bindInterface}"` : ""})`);
    if (needsRelay(server.xray)) this.log(`${server.name} has no TLS, REALITY or VLESS Encryption: the VPN hop itself is not encrypted`, "warn");
    return { ...server, outbound: socksOutbound(port) };
  }
  /** Counts start() calls, so a slow start that was cancelled can't mistake a newer one for itself. */
  startGen = 0;
  /** Throws Cancelled when the user disconnected (or connected again) while this start was still running. */
  checkCancelled(gen) {
    if (this.status.state !== "starting" || gen !== this.startGen) throw new Cancelled();
  }
  get warpDir() {
    return (0, import_node_path2.join)(this.paths.dataDir, "warp");
  }
  get ownWarpAccount() {
    return { config: (0, import_node_path2.join)(this.warpDir, "aether.toml"), verify: false };
  }
  sharedAccountDir(serverId) {
    return (0, import_node_path2.join)(this.warpDir, "shared", serverId);
  }
  /** The account a config received as a link runs on, written out from its link. */
  sharedWarpAccount(server) {
    const dir = this.sharedAccountDir(server.id);
    (0, import_node_fs3.mkdirSync)(dir, { recursive: true });
    const file = (0, import_node_path2.join)(dir, WARP_IDENTITY_FILE);
    if (!(0, import_node_fs3.existsSync)(file)) (0, import_node_fs3.writeFileSync)(file, parseWarpShareLink(server.link).identity);
    return { config: (0, import_node_path2.join)(dir, "aether.toml"), verify: true };
  }
  /** Forgets the account of a received config when the config is deleted. */
  removeSharedWarpAccount(serverId) {
    (0, import_node_fs3.rmSync)(this.sharedAccountDir(serverId), { recursive: true, force: true });
  }
  /**
   * Makes a share link for a WARP server or config. It gets a new WARP account of its own, so
   * the person receiving it needs no access to Cloudflare's sign-up service and the sender's own
   * account stays private. The link is the only copy of that account Bridge keeps.
   */
  async shareWarpLink(server) {
    if (!isWarp(server) || !server.warp) throw new Error("Not a WARP server");
    const exe = this.paths.aether;
    if (!exe || !(0, import_node_fs3.existsSync)(exe)) throw new Error("WARP core (aether.exe) not found; reinstall Bridge");
    const dir = (0, import_node_path2.join)(this.warpDir, `share-${(0, import_node_crypto4.randomUUID)()}`);
    (0, import_node_fs3.mkdirSync)(dir, { recursive: true });
    try {
      await this.registerWarp(() => void 0, dir);
      return warpShareLink(server.warp, (0, import_node_fs3.readFileSync)((0, import_node_path2.join)(dir, WARP_IDENTITY_FILE), "utf8"), server.name);
    } finally {
      (0, import_node_fs3.rmSync)(dir, { recursive: true, force: true });
    }
  }
  /** Starts aether.exe, logging its output under `tag`; `onLine` sees each message. */
  spawnAether(args, tag, onLine) {
    const child = (0, import_node_child_process3.spawn)(this.paths.aether, args, { windowsHide: true, cwd: this.warpDir });
    child.stdin?.end();
    this.warpChildren.add(child);
    child.once("exit", () => this.warpChildren.delete(child));
    const feed = (chunk) => {
      for (const l of chunk.toString().split(/\r?\n/)) {
        if (!l.trim()) continue;
        const { level, text } = parseWarpLine(l);
        this.log(`[${tag}] ${text}`, level);
        onLine?.(text);
      }
    };
    child.stdout?.on("data", feed);
    child.stderr?.on("data", feed);
    return child;
  }
  /**
   * Starts one WARP attempt; resolves once Aether serves a working tunnel on `port`. `peer` is a
   * saved gateway to use without scanning; `fresh` ignores the last working gateway.
   */
  async launchWarp(method, port, opts = {}) {
    const timeoutMs = opts.timeoutMs ?? WARP_ATTEMPT_MS;
    const account = opts.account ?? this.ownWarpAccount;
    const psiphon = this.psiphonChain && !opts.fresh ? { ...this.psiphonChain, port: await freePort() } : void 0;
    return new Promise((resolve, reject) => {
      const t0 = Date.now();
      let won;
      let exit;
      let gateway;
      let refused = 0;
      const child = this.spawnAether(warpArgs(method, port, account.config, opts.peer, opts.fresh, account.verify, psiphon), `warp ${method}`, (text) => {
        if (won) return void (won.exit ??= warpExitCountry(text));
        exit = warpExitCountry(text) ?? exit;
        gateway ??= warpGateway(text);
        if (WARP_EXIT_REFUSED.test(text) && ++refused >= WARP_MAX_EXIT_REFUSED) {
          clearTimeout(timer);
          child.kill();
          return reject(new Error(`${warpLabel(method)}: works, but Cloudflare gave it an exit in ${exit ?? "the refused country"} ${refused} times, so it can't give a foreign exit on this network`));
        }
        if (WARP_NO_IPV6.test(text)) {
          clearTimeout(timer);
          child.kill();
          return reject(new Error(`${warpLabel(method)}: this network has no IPv6`));
        }
        if (!warpReady(text, port)) return;
        clearTimeout(timer);
        resolve(won = { method, port, child, exit, peer: gateway, readyMs: Date.now() - t0, psiphonPort: psiphon?.port });
      });
      const timer = setTimeout(() => {
        child.kill();
        reject(new Error(`${warpLabel(method)}: no working gateway within ${timeoutMs / 1e3} s`));
      }, timeoutMs);
      child.once("exit", (code) => {
        clearTimeout(timer);
        if (!won) reject(new Error(`${warpLabel(method)}: stopped (exit code ${code})`));
      });
    });
  }
  /** Runs one aether.exe to the end (or until `timeoutMs`), for creating the WARP account. */
  runAether(args, timeoutMs) {
    const child = this.spawnAether(args, "warp");
    return new Promise((resolve) => {
      const timer = setTimeout(() => child.kill(), timeoutMs);
      child.once("exit", () => {
        clearTimeout(timer);
        resolve();
      });
    });
  }
  /**
   * Starts a plain local SOCKS proxy into one of the user's own servers (see warpHelper) and
   * returns its port and process, or undefined when there is no server to use or it doesn't start.
   */
  /** Starts a separate core that offers just this server on a local SOCKS port. */
  async launchLocalProxy(server, name) {
    const port = await freePort();
    if (server.engine === "xray" && server.xray) {
      return { port, child: await this.launchXray([{ port, outbound: await this.pinXray(server.xray, true) }], name, this.realAdapter) };
    }
    const api = { port: await freePort(), secret: (0, import_node_crypto4.randomUUID)() };
    const file = (0, import_node_path2.join)(this.paths.dataDir, `${name}.json`);
    (0, import_node_fs3.writeFileSync)(file, JSON.stringify(buildHelperConfig(await this.pinAddress(server, true), port, api), null, 2));
    return { port, child: await launch(this.paths.singBox, file, this.paths.dataDir, api, (line, isErr) => isErr && /FATAL/.test(line) && this.coreLine(line, true)) };
  }
  /** Runs `use` with this server on a local SOCKS port, and stops the core afterwards. */
  async withLocalProxy(server, name, use) {
    let child;
    try {
      const proxy = await this.launchLocalProxy(server, name);
      child = proxy.child;
      return await use(proxy.port);
    } finally {
      await killProcess(child);
    }
  }
  async startWarpHelper() {
    const server = this.warpHelper?.();
    if (!server) return void 0;
    try {
      const { port, child } = await this.launchLocalProxy(server, "warp-helper");
      this.warpChildren.add(child);
      child.once("exit", () => this.warpChildren.delete(child));
      this.log(`Free WARP: using "${server.name}" to reach Cloudflare's WARP service`);
      return { port, child };
    } catch (e) {
      this.log(`Free WARP: could not start "${server.name}" to create the account (${e instanceof Error ? e.message : e})`, "warn");
      return void 0;
    }
  }
  /**
   * Creates a WARP account in `dir`, trying each way in WARP_REGISTER_TRIES until one works.
   * While connected, the VPN itself is tried first: it reaches a blocked sign-up service.
   */
  async registerWarp(checkCancelled, dir = this.warpDir) {
    const config = (0, import_node_path2.join)(dir, "aether.toml");
    const done = () => (0, import_node_fs3.existsSync)((0, import_node_path2.join)(dir, WARP_IDENTITY_FILE));
    this.log(dir === this.warpDir ? "Free WARP: creating a WARP account (first use only, can take a few minutes)" : "Free WARP: creating a separate WARP account");
    this.progress("Creating a free WARP account (first time only)");
    if (this.status.state === "running" && this.probePort) {
      this.log("Free WARP: creating the account through the VPN");
      await this.runAether(warpRegisterArgs(config, [], this.probePort), 6e4);
      if (done()) return this.log("Free WARP: account created");
    }
    for (const t of WARP_REGISTER_TRIES) {
      const helper = t.via ? await this.startWarpHelper() : void 0;
      checkCancelled();
      if (t.via && !helper) continue;
      this.log(`Free WARP: creating the account ${t.label}`);
      await this.runAether(warpRegisterArgs(config, t.args, helper?.port), t.timeoutMs);
      if (helper) {
        this.warpChildren.delete(helper.child);
        await killProcess(helper.child);
      }
      checkCancelled();
      if (done()) return this.log("Free WARP: account created");
    }
    const via = this.warpHelper?.() ? "" : " Adding one of your own servers lets Bridge create it through that server.";
    throw new Error(`Free WARP: could not create a WARP account, because Cloudflare's WARP service is blocked on this network right now (see Logs).${via}`);
  }
  /**
   * For the free WARP server, starts aether.exe and returns the server as sing-box should see
   * it: a SOCKS hop into Aether. With method "auto", the MASQUE methods all run at once (each on
   * its own port) and the first one that carries real traffic wins; the others are stopped.
   */
  async viaWarp(server, gen) {
    const choice = this.settings?.warpPsiphon;
    if (!choice) return this.viaWarpAlone(server, gen);
    const bin = this.paths.psiphon;
    if (!bin || !(0, import_node_fs3.existsSync)(bin)) throw new Error("Psiphon (psiphon-tunnel-core.exe) not found; reinstall Bridge");
    this.psiphonChain = { bin, region: choice === "auto" ? void 0 : choice };
    let tunnel;
    try {
      const single = warpMethods(server.warp).filter((m) => !prefersForeignExit(m));
      tunnel = await this.viaWarpAlone(single.length ? server : { ...server, warp: { method: "auto" } }, gen);
    } finally {
      this.psiphonChain = void 0;
    }
    const port = this.wonWarp?.psiphonPort;
    if (!port) throw new Error("Psiphon did not start inside WARP");
    this.log(`Free WARP: connecting Psiphon through WARP${choice === "auto" ? "" : `, asking for an exit in ${choice}`}`);
    this.progress("Connecting Psiphon through WARP for an exit outside Iran");
    const deadline = Date.now() + PSIPHON_READY_MS;
    while (Date.now() < deadline) {
      this.checkCancelled(gen);
      const exit = await quickExit(port).catch(() => void 0);
      if (exit) {
        this.log(`Free WARP: Psiphon connected, exit ${exit} (local SOCKS ${port})`);
        if (this.wonWarp) this.wonWarp.exit = exit;
        return { ...tunnel, outbound: socksOutbound(port) };
      }
      await new Promise((r) => setTimeout(r, 2e3));
    }
    throw new Error(`Psiphon didn't connect through WARP within ${PSIPHON_READY_MS / 1e3} s. Choose another connection method to use WARP alone.`);
  }
  /** Set while connecting with Psiphon inside WARP: every WARP attempt then carries it. */
  psiphonChain;
  async viaWarpAlone(server, gen) {
    const exe = this.paths.aether;
    if (!exe || !(0, import_node_fs3.existsSync)(exe)) throw new Error("WARP core (aether.exe) not found; reinstall Bridge");
    (0, import_node_fs3.mkdirSync)(this.warpDir, { recursive: true });
    const shared = !!server.warp?.shared;
    const account = shared ? this.sharedWarpAccount(server) : this.ownWarpAccount;
    if (!shared && !(0, import_node_fs3.existsSync)((0, import_node_path2.join)(this.warpDir, WARP_IDENTITY_FILE))) await this.registerWarp(() => this.checkCancelled(gen));
    const methods = warpMethods(server.warp);
    const peer = server.warp?.peer;
    let winner;
    if (peer && methods.length === 1) {
      this.log(`Free WARP: connecting with ${warpLabel(methods[0])} on the saved gateway ${peer}`);
      this.progress("Connecting to the saved WARP config");
      winner = await this.launchWarp(methods[0], await freePort(), { peer, timeoutMs: WARP_PEER_MS, account }).catch((e) => {
        this.checkCancelled(gen);
        this.log(`Free WARP: the saved gateway didn't answer (${e instanceof Error ? e.message : e}); scanning for another`, "warn");
        this.progress("The saved config didn't answer; looking for another way");
        return void 0;
      });
      this.checkCancelled(gen);
    }
    if (!winner) winner = await this.raceWarpMethods(shared ? warpMethods({ method: "auto" }) : methods, gen, account);
    if (peer && winner.peer && winner.peer !== peer) this.onWarpPeer?.(server.id, winner.peer, winner.method);
    const won = winner;
    const losers = [...this.warpChildren].filter((c) => c !== won.child);
    for (const c of losers) this.warpChildren.delete(c);
    await Promise.all(losers.map((c) => killProcess(c)));
    this.checkCancelled(gen);
    won.child.once("exit", (code) => {
      if (this.status.state !== "running") return;
      this.log(`WARP core stopped unexpectedly (exit code ${code})`, "error");
      void this.stop().then(() => this.setStatus({ state: "stopped", error: "WARP core stopped unexpectedly, see Logs" }));
    });
    this.wonWarp = won;
    this.log(`Free WARP connected with ${warpLabel(won.method)}${won.exit ? `, exit ${won.exit}` : ""}${won.peer ? ` via ${won.peer}` : ""} (local SOCKS ${won.port})`);
    if (won.exit === "IR") {
      this.log(
        'Free WARP: Cloudflare registers this exit address in Iran. Filtering is still bypassed (the traffic leaves abroad), but sites that block Iranian users may refuse. If one does, choose "Auto: exit outside Iran" or a Gool config.',
        "warn"
      );
    }
    return { ...server, outbound: socksOutbound(won.port) };
  }
  /** Races `methods` (each on its own port) and returns the winner; see raceWarp. */
  async raceWarpMethods(methods, gen, account = this.ownWarpAccount) {
    this.log(`Free WARP: looking for a way through (${methods.map(warpLabel).join(", ")})`);
    this.progress(methods.length > 1 ? `Finding a way through your network (trying ${methods.length} at once)` : `Connecting with ${warpLabel(methods[0])}`);
    const attempts = await Promise.all(methods.map(async (method) => ({ method, port: await freePort() })));
    const state = this.readWarpState();
    const prefer = methods.length < 2 ? void 0 : methods.find(prefersForeignExit) ?? methods.find((m) => m === "h3");
    const foreign = !!prefer && prefersForeignExit(prefer);
    const wait = !!prefer && (foreign ? waitForGool(state) : waitForH3(state));
    if (prefer && !wait) this.log(`Free WARP: ${foreign ? "Gool" : "HTTP/3"} didn't get through recently, so Bridge takes the first way that works (it gets waited for again after ${GOOL_RETRY_MS / 36e5} h)`);
    let winner;
    try {
      winner = await this.raceWarp(attempts, wait ? prefer : void 0, account);
    } catch (e) {
      this.checkCancelled(gen);
      const reasons = e instanceof AggregateError ? e.errors.map((x) => x instanceof Error ? x.message : String(x)) : [String(e)];
      throw new Error(`Free WARP could not connect on this network. ${reasons.join("; ")}`);
    }
    const missedKey = foreign ? "goolMissedAt" : "h3MissedAt";
    if (prefer && (winner.method === prefer || foreign && prefersForeignExit(winner.method))) this.writeWarpState({ ...state, [missedKey]: void 0 });
    else if (wait) this.writeWarpState({ ...state, [missedKey]: Date.now() });
    return winner;
  }
  /**
   * "Find configs": runs every method at once on the real network (Bridge must be disconnected)
   * and keeps each one that carries traffic, with the gateway it used and its measured speed.
   * Then it looks for further gateways on the methods that work, so there are several to choose
   * from. Each tunnel is stopped as soon as it has been measured.
   */
  async findWarpConfigs() {
    if (this.status.state !== "stopped") throw new Error("Disconnect first: configs are tested on your own network, not through the VPN");
    if (this.scanningWarp) throw new Error("Already finding WARP configs");
    const exe = this.paths.aether;
    if (!exe || !(0, import_node_fs3.existsSync)(exe)) throw new Error("WARP core (aether.exe) not found; reinstall Bridge");
    this.scanningWarp = true;
    try {
      (0, import_node_fs3.mkdirSync)(this.warpDir, { recursive: true });
      const stopped = () => {
        if (this.status.state !== "stopped") throw new Cancelled();
      };
      if (!(0, import_node_fs3.existsSync)((0, import_node_path2.join)(this.warpDir, WARP_IDENTITY_FILE))) await this.registerWarp(stopped);
      const found = /* @__PURE__ */ new Map();
      let speedTurn = Promise.resolve();
      const tryMethod = async (method, timeoutMs) => {
        const w = await this.launchWarp(method, await freePort(), { fresh: true, timeoutMs });
        try {
          for (let i = 0; i < 25 && !w.exit; i++) await new Promise((r) => setTimeout(r, 200));
          if (!w.peer) throw new Error(`${warpLabel(method)}: no gateway in the log`);
          const key = `${method}@${w.peer}`;
          if (found.has(key) || found.size >= WARP_FIND_MAX) return;
          const entry = { method, peer: w.peer, exit: w.exit, readyMs: w.readyMs };
          found.set(key, entry);
          const speed = speedTurn.then(() => quickSpeed(w.port));
          speedTurn = speed.catch(() => void 0);
          Object.assign(entry, await speed);
          entry.exit ??= w.exit;
          this.log(`Free WARP: ${warpLabel(method)} works on ${w.peer}${w.exit ? `, exit ${w.exit}` : ""} (${(w.readyMs / 1e3).toFixed(1)} s, down ${entry.downMbps ?? "?"} / up ${entry.upMbps ?? "?"} Mbps)`);
        } finally {
          this.warpChildren.delete(w.child);
          await killProcess(w.child);
        }
      };
      this.log(`Free WARP: finding configs (${WARP_FIND_METHODS.map(warpLabel).join(", ")})`);
      const first = await Promise.allSettled(WARP_FIND_METHODS.map((m) => tryMethod(m)));
      for (const r of first) if (r.status === "rejected") this.log(`Free WARP: ${r.reason instanceof Error ? r.reason.message : r.reason}`);
      stopped();
      const working = WARP_FIND_METHODS.filter((_, i) => first[i].status === "fulfilled");
      if (working.includes("gool") && working.includes("h3")) working.push("gool-h3");
      if (working.includes("mim-h2") && working.includes("h3")) working.push("mim");
      const deadline = Date.now() + WARP_FIND_MORE_MS;
      for (let round = 0; round < WARP_FIND_ROUNDS && working.length && found.size < WARP_FIND_MAX && Date.now() < deadline; round++) {
        await Promise.allSettled(working.map((m) => tryMethod(m, WARP_FIND_ATTEMPT_MS)));
        stopped();
      }
      this.log(`Free WARP: ${found.size} config${found.size === 1 ? "" : "s"} found`);
      return [...found.values()];
    } finally {
      this.scanningWarp = false;
    }
  }
  /** A local SOCKS port whose traffic always goes through the VPN, while connected. */
  get vpnPort() {
    return this.status.state === "running" ? this.probePort || void 0 : void 0;
  }
  /** Calls Cloudflare's account API: through the VPN if connected, otherwise directly, then through a temporary WARP tunnel. */
  async overWarpApi(use) {
    if (this.status.state === "running" && this.probePort) return use(this.probePort);
    try {
      return await use();
    } catch (e) {
      if (e instanceof WarpApiError || this.status.state !== "stopped") throw e;
      this.log(`Free WARP: Cloudflare's account service can't be reached directly (${e instanceof Error ? e.message : e}), trying through WARP`);
      return this.withWarpProxy((port) => use(port));
    }
  }
  /**
   * Binds the user's own WARP+ key to the account Free WARP uses. Cloudflare has a known bug where
   * an account that has already connected doesn't become WARP+, so if that happens the key goes on
   * a new account, which then replaces the old one. Throws if the account doesn't end up WARP+.
   */
  async setWarpKey(key) {
    if (!isWarpKey(key)) throw new Error("That doesn't look like a WARP+ key. It has three groups of eight letters and digits, like AAAAAAAA-BBBBBBBB-CCCCCCCC");
    const exe = this.paths.aether;
    if (!exe || !(0, import_node_fs3.existsSync)(exe)) throw new Error("WARP core (aether.exe) not found; reinstall Bridge");
    (0, import_node_fs3.mkdirSync)(this.warpDir, { recursive: true });
    const identity = (0, import_node_path2.join)(this.warpDir, WARP_IDENTITY_FILE);
    if (!(0, import_node_fs3.existsSync)(identity)) await this.registerWarp(() => void 0);
    const cred = warpCredentials((0, import_node_fs3.readFileSync)(identity, "utf8"));
    const refused = (e) => e instanceof WarpApiError ? new Error(`Cloudflare refused this key: ${e.message.split(key).join("(key)")}`) : e;
    return this.overWarpApi(async (port) => {
      const before = await getWarpAccount(cred, port);
      await putWarpLicense(cred, key, port).catch((e) => {
        throw refused(e);
      });
      const after = await getWarpAccount(cred, port);
      if (after.plus) {
        const state = this.readWarpState();
        this.writeWarpState({ ...state, plusOriginalLicense: state.plusOriginalLicense ?? before.license });
        this.log("Free WARP: WARP+ key added to the account");
        return after;
      }
      this.log(`Free WARP: after adding the key, Cloudflare reports account type "${after.accountType}" with ${Math.round(after.premiumData / 1e9)} GB of WARP+ data`);
      const putBack = async (c, license) => {
        if (license) await putWarpLicense(c, license, port).catch((e) => this.log(`Free WARP: could not take the key off the account again (${e instanceof Error ? e.message : e})`, "warn"));
      };
      await putBack(cred, before.license);
      this.log("Free WARP: the account did not become WARP+, trying the key on a new account");
      const dir = (0, import_node_path2.join)(this.warpDir, `plus-${(0, import_node_crypto4.randomUUID)()}`);
      (0, import_node_fs3.mkdirSync)(dir, { recursive: true });
      try {
        await this.registerWarp(() => void 0, dir);
        const fresh = (0, import_node_fs3.readFileSync)((0, import_node_path2.join)(dir, WARP_IDENTITY_FILE), "utf8");
        const freshCred = warpCredentials(fresh);
        const freshBefore = await getWarpAccount(freshCred, port);
        await putWarpLicense(freshCred, key, port).catch((e) => {
          throw refused(e);
        });
        const freshAfter = await getWarpAccount(freshCred, port);
        if (!freshAfter.plus) {
          await putBack(freshCred, freshBefore.license);
          throw new Error("This key has no WARP+ on it: Cloudflare accepted it, but its account has no WARP+ data. Every 1.1.1.1 account has a key, even a free one. Your Free WARP account hasn't changed");
        }
        (0, import_node_fs3.writeFileSync)(identity, fresh);
        this.writeWarpState({ ...this.readWarpState(), plusOriginalLicense: freshBefore.license });
        this.log("Free WARP: WARP+ key added on a new account");
        return freshAfter;
      } finally {
        (0, import_node_fs3.rmSync)(dir, { recursive: true, force: true });
      }
    });
  }
  /** Takes the WARP+ key off the account, which frees its place among the key's five devices. */
  async clearWarpKey() {
    const identity = (0, import_node_path2.join)(this.warpDir, WARP_IDENTITY_FILE);
    const state = this.readWarpState();
    if (!(0, import_node_fs3.existsSync)(identity) || !state.plusOriginalLicense) return;
    const cred = warpCredentials((0, import_node_fs3.readFileSync)(identity, "utf8"));
    await this.overWarpApi((port) => putWarpLicense(cred, state.plusOriginalLicense, port));
    this.writeWarpState({ ...state, plusOriginalLicense: void 0 });
    this.log("Free WARP: WARP+ key removed from the account");
  }
  /** Runs `use` with the local port of a temporary WARP tunnel, to reach what the network blocks. Only while disconnected. */
  async withWarpProxy(use) {
    if (this.status.state !== "stopped") throw new Error("Bridge is connected");
    if (this.scanningWarp) throw new Error("Already finding WARP configs");
    const exe = this.paths.aether;
    if (!exe || !(0, import_node_fs3.existsSync)(exe)) throw new Error("WARP core (aether.exe) not found; reinstall Bridge");
    (0, import_node_fs3.mkdirSync)(this.warpDir, { recursive: true });
    const gen = this.startGen;
    if (!(0, import_node_fs3.existsSync)((0, import_node_path2.join)(this.warpDir, WARP_IDENTITY_FILE))) await this.registerWarp(() => this.checkCancelled(gen));
    const won = await this.raceWarpMethods(warpMethods({ method: "auto" }), gen);
    const losers = [...this.warpChildren].filter((c) => c !== won.child);
    for (const c of losers) this.warpChildren.delete(c);
    await Promise.all(losers.map((c) => killProcess(c)));
    try {
      return await use(won.port);
    } finally {
      this.warpChildren.delete(won.child);
      await killProcess(won.child);
    }
  }
  /** Drops configs whose name doesn't resolve, or leads to the user's own network as an address could. */
  async publicOutsideOwnNetwork(candidates) {
    const queue = [...candidates];
    const usable = [];
    const check = async () => {
      for (let s = queue.shift(); s; s = queue.shift()) {
        const host = s.engine === "xray" && s.xray ? xrayServer(s.xray).host : String(s.outbound.server);
        const r = host ? await this.resolver.resolve(host).catch(() => void 0) : void 0;
        if (r && !isPrivateAddress(r.ip)) usable.push(s);
      }
    };
    await Promise.all(Array.from({ length: 16 }, check));
    return usable;
  }
  /** A quick try of real traffic through each, a few at a time. The speeds are only rough, because they share the line. */
  async samplePublic(servers, workers) {
    const sampled = [];
    const queue = [...servers];
    const sample = async (slot) => {
      for (let server = queue.shift(); server; server = queue.shift()) {
        const current = server;
        await this.withLocalProxy(current, `public-test-proxy-${slot}`, async (port) => {
          const exit = await quickExit(port);
          if (exit && exit !== "IR") sampled.push({ server: current, exit, rough: await quickDown(port, PUBLIC_SAMPLE_BYTES, PUBLIC_SAMPLE_MS) });
        }).catch((e) => this.log(`Public configs: one couldn't be started (${e instanceof Error ? e.message : e})`));
      }
    };
    await Promise.all(Array.from({ length: workers }, (_, slot) => sample(slot)));
    return sampled;
  }
  /** The daily list: every config that answers and carries real HTTPS, up to `max`, fastest first. */
  async checkPublicConfigs(candidates, testUrl, max) {
    const usable = await this.publicOutsideOwnNetwork(candidates);
    const latency = await this.testLatency(usable, testUrl, { workers: 64, timeoutMs: 5e3, name: "public-test", quiet: true });
    const answering = usable.filter((s) => (latency.get(s.id) ?? -1) >= 0).sort((a, b) => latency.get(a.id) - latency.get(b.id));
    this.log(`Public configs: ${answering.length} of ${usable.length} answer`);
    const sampled = await this.samplePublic(spreadOut(answering, max), 8);
    this.log(`Public configs: ${sampled.length} carry real HTTPS outside Iran`);
    return sampled.sort((a, b) => (b.rough ?? 0) - (a.rough ?? 0));
  }
  /**
   * Tests configs from public lists on the real network: which answer at all, then which of those
   * really carry HTTPS with valid certificates, leave outside Iran and move data quickly, and
   * finally the speed and steadiness of the best. Returns those it would keep, best first.
   */
  async findPublicConfigs(candidates, testUrl, progress) {
    const usable = await this.publicOutsideOwnNetwork(candidates);
    progress("test", usable.length);
    const latency = await this.testLatency(usable, testUrl, { workers: 40, timeoutMs: 5e3, name: "public-test", quiet: true });
    const answering = usable.filter((s) => (latency.get(s.id) ?? -1) >= 0).sort((a, b) => latency.get(a.id) - latency.get(b.id));
    this.log(`Public configs: ${answering.length} of ${usable.length} answer on this network`);
    const shortlist = spreadOut(answering, PUBLIC_SAMPLE_MAX);
    progress("measure", shortlist.length);
    const sampled = await this.samplePublic(shortlist, PUBLIC_SAMPLE_WORKERS);
    sampled.sort((a, b) => (b.rough ?? 0) - (a.rough ?? 0) || latency.get(a.server.id) - latency.get(b.server.id));
    const finalists = sampled.slice(0, PUBLIC_MEASURE_MAX);
    progress("speed", finalists.length);
    const servers = finalists.map((f) => f.server);
    const rounds = [latency];
    for (let round = 0; round < 2 && servers.length; round++) rounds.push(await this.testLatency(servers, testUrl, { workers: 12, timeoutMs: 5e3, name: "public-test", quiet: true }));
    const found = [];
    for (const { server, exit, rough } of finalists) {
      const pings = rounds.map((r) => r.get(server.id) ?? -1).filter((ms) => ms >= 0);
      if (pings.length < 2) continue;
      const measured = await this.withLocalProxy(server, "public-test-proxy-0", (port) => quickDown(port, PUBLIC_MEASURE_BYTES, PUBLIC_MEASURE_MS)).catch(() => void 0);
      found.push({ server, exit, latency: middleOf(pings), downMbps: measured ?? rough });
    }
    const kept = rankPublic(found).slice(0, PUBLIC_KEEP);
    this.log(`Public configs: ${kept.length} kept, ${kept.map((f) => `${f.downMbps ?? "?"} Mbps / ${f.latency} ms`).join(", ")}`);
    return kept;
  }
  readWarpState() {
    try {
      return JSON.parse((0, import_node_fs3.readFileSync)((0, import_node_path2.join)(this.warpDir, WARP_STATE_FILE), "utf8"));
    } catch {
      return {};
    }
  }
  writeWarpState(state) {
    try {
      (0, import_node_fs3.writeFileSync)((0, import_node_path2.join)(this.warpDir, WARP_STATE_FILE), JSON.stringify(state));
    } catch {
    }
  }
  /**
   * Runs the WARP attempts at the same time. The first that works wins, unless `prefer` is still
   * running: then it gets a little longer (Gool WARP_PREFER_WAIT_MS, HTTP/3 WARP_PREFER_H3_MS),
   * wins outright if it makes it, and the first one is used if it doesn't.
   */
  raceWarp(attempts, prefer, account) {
    return new Promise((resolve, reject) => {
      const foreign = !!prefer && prefersForeignExit(prefer);
      const wanted = new Set(attempts.map((a) => a.method).filter((m) => m === prefer || foreign && prefersForeignExit(m)));
      const errors = [];
      let settled = 0;
      let fallback;
      let wait;
      let done = false;
      const finish = (w) => {
        if (done) return;
        done = true;
        clearTimeout(wait);
        resolve(w);
      };
      for (const a of attempts) {
        this.launchWarp(a.method, a.port, { account }).then(
          (w) => {
            settled++;
            if (wanted.has(a.method)) return finish(w);
            if (fallback) return;
            fallback = w;
            if (!wanted.size) return finish(w);
            const gool = foreign;
            const ms = gool ? WARP_PREFER_WAIT_MS : WARP_PREFER_H3_MS;
            this.log(`Free WARP: ${warpLabel(a.method)} works; waiting up to ${ms / 1e3} s for ${gool ? "a way with two hops, which exits outside Iran" : "HTTP/3, the fastest"}`);
            this.progress(gool ? "Found a way. Waiting a little longer for an exit outside Iran" : "Found a way. Giving HTTP/3, the fastest, a few seconds");
            wait = setTimeout(() => finish(w), ms);
          },
          (e) => {
            settled++;
            wanted.delete(a.method);
            errors.push(e);
            if (fallback && !wanted.size) return finish(fallback);
            if (settled === attempts.length && !fallback && !done) {
              done = true;
              reject(new AggregateError(errors));
            }
          }
        );
      }
    });
  }
  log(text, level = "info") {
    const line = { time: Date.now(), level, text };
    this.logs.push(line);
    if (this.logs.length > MAX_LOGS) this.logs.splice(0, this.logs.length - MAX_LOGS);
    this.emit("log", line);
  }
  setStatus(s) {
    this.status = s;
    this.emit("status", s);
  }
  /** While connecting, tells the window what Bridge is doing now, so a long connect isn't a mystery. */
  progress(text) {
    if (this.status.state === "starting") this.setStatus({ ...this.status, progress: text });
  }
  /** Warned this session that an app got a censored DNS answer (see coreLine). */
  censoredDnsWarned = false;
  censoredDnsFlushedAt = 0;
  /** For the Direct internet ping (see probeDirect): the real adapter's IP in TUN modes, and the test sites' IPs. */
  directSource;
  directIps = {};
  directTimeoutFlushedAt = 0;
  /**
   * An address timed out on the direct network: the DNS relay stops offering it, and the DNS caches
   * are cleared so apps ask again and get another one (at most every so often, because clearing
   * them makes the next lookups slower).
   */
  onDirectTimeout(ip) {
    if (!this.dnsRelay?.markUnreachable(ip)) return;
    if (Date.now() - this.directTimeoutFlushedAt < DIRECT_TIMEOUT_FLUSH_MS) return;
    this.directTimeoutFlushedAt = Date.now();
    if (this.api) void clashPost(this.api, "/cache/dns/flush").catch(() => void 0);
    void flushDns();
  }
  coreLine = (line, isErr) => {
    const level = /\b(ERROR|FATAL)\b/.test(line) ? "error" : /\bWARN\b/.test(line) ? "warn" : isErr ? "warn" : "info";
    const text = line.replace(/\x1b\[[0-9;]*m/g, "");
    this.log(text, level);
    const timedOut = text.match(DIRECT_TIMEOUT)?.[1];
    if (timedOut) this.onDirectTimeout(timedOut);
    if (/inbound connection (from \S+ )?to 10\.10\.34\.\d+:/.test(text)) {
      if (Date.now() - this.censoredDnsFlushedAt > 6e4) {
        this.censoredDnsFlushedAt = Date.now();
        void flushDns();
      }
      if (!this.censoredDnsWarned) {
        this.censoredDnsWarned = true;
        this.log("An app got a censored DNS answer from your ISP (10.10.34.x) instead of Bridge, so a blocked site may not open even on VPN. Bridge cleared Windows' DNS cache so it asks again; if it keeps happening, turn on Strict mode in Settings.", "warn");
      }
    }
  };
  async start(server, settings, appRules) {
    if (this.scanningWarp) throw new Error("Bridge is still finding WARP configs; connect when it is done");
    if (this.status.state !== "stopped") await this.stop();
    if (!(0, import_node_fs3.existsSync)(this.paths.singBox)) throw new Error(`sing-box not found at ${this.paths.singBox}`);
    this.setStatus({ state: "starting", mode: settings.mode, serverId: server.id, connectingAt: Date.now(), progress: "Checking your network" });
    this.settings = settings;
    this.censoredDnsWarned = false;
    const gen = ++this.startGen;
    try {
      const api = { port: await freePort(), secret: (0, import_node_crypto4.randomUUID)() };
      const probePort = await freePort();
      const log = (text, level) => this.log(text, level);
      const usesXray = server.engine === "xray";
      const usesWarp = isWarp(server);
      const tun = usesTun(settings.mode);
      const net = tun ? await networkInfo() : { dnsServers: [], otherTunnels: [], defaultRoutes: [], bindPhysical: false };
      if (net.defaultRoutes.length) this.log(`Default routes before connecting: ${net.defaultRoutes.join(", ")}`);
      const [localDns, pinned] = await Promise.all([
        tun ? pickDirectDns(net.dnsServers, log) : Promise.resolve(void 0),
        // In TUN modes Xray goes straight out of the real adapter instead of looping through TUN.
        usesWarp ? this.viaWarp(server, gen) : usesXray ? (this.progress("Starting Xray"), this.viaXray(server, tun ? net.interfaceAlias : void 0)) : this.pinAddress(server)
      ]);
      this.checkCancelled(gen);
      if (localDns) this.log(`Direct apps resolve names with ${localDns.type === "https" ? `DNS-over-HTTPS ${localDns.working?.join(", ")}` : `DNS ${localDns.server}`}`);
      else if (tun) this.log("No working DNS server found for direct apps; using the system resolver", "warn");
      if (localDns?.working?.length) {
        this.dnsRelay = new DnsRelay({
          servers: localDns.working.map((host) => ({ host })),
          localAddress: adapterIpv4(net.interfaceAlias),
          proxyPort: () => this.probePort,
          log
        });
      }
      const dnsRelayPort = await this.dnsRelay?.start();
      this.realAdapter = tun ? net.interfaceAlias : void 0;
      if (tun && settings.strictRoute && localDns?.type !== "https") this.log("DNS-over-HTTPS is not reachable on this network, so Strict mode stays off for this connection", "warn");
      const defaultInterface = net.bindPhysical ? net.interfaceAlias : void 0;
      if (net.otherTunnels.length) this.log(`Other tunnels are active: ${net.otherTunnels.join(", ")}. They may conflict with Bridge.`, "warn");
      if (defaultInterface) this.log(`Bridge traffic is bound to "${defaultInterface}" to stay out of other tunnels`);
      if (net.otherInterface) this.log(`Apps set to "Other VPN" go through "${net.otherInterface}"`);
      else if (appRules.some((r) => r.enabled && r.action === "other")) this.log('No other VPN adapter found; apps set to "Other VPN" go direct', "warn");
      const noIpv6 = tun && !hasInternetIpv6(net.interfaceAlias);
      if (noIpv6) this.log("This network has no IPv6, so the VPN adapter is IPv4 only");
      else if (tun) this.log(`"${net.interfaceAlias ?? "A network adapter"}" has IPv6, so the VPN adapter keeps IPv6 too`);
      const config = buildConfig({
        noIpv6,
        server: pinned,
        settings,
        appRules,
        clashApi: api,
        rulesDir: (0, import_node_fs3.existsSync)((0, import_node_path2.join)(this.paths.rulesDir, "geosite-ir.srs")) ? this.paths.rulesDir : void 0,
        cacheFile: (0, import_node_path2.join)(this.paths.dataDir, "cache.db"),
        appRulesDir: this.appRulesDir,
        localDns,
        dnsRelayPort,
        // xray.exe's traffic (a safety net; it is bound to the real adapter) and aether.exe's
        // (which can't be bound on Windows, so it does reach TUN) must not loop back into the VPN.
        bypassProcesses: usesXray && this.paths.xray ? [this.paths.xray] : usesWarp && this.paths.aether ? [this.paths.aether] : void 0,
        defaultInterface,
        otherInterface: net.otherInterface,
        probePort
      });
      const configFile = (0, import_node_path2.join)(this.paths.dataDir, "config.json");
      (0, import_node_fs3.writeFileSync)(configFile, JSON.stringify(config, null, 2));
      this.log(`Starting sing-box: ${server.name} (${settings.mode})`);
      this.progress(tun ? "Starting the VPN adapter" : "Starting the VPN");
      const child = await launch(this.paths.singBox, configFile, this.paths.dataDir, api, this.coreLine);
      if (this.status.state !== "starting" || gen !== this.startGen) {
        await killProcess(child);
        if (usesTun(settings.mode)) await flushDns();
        throw new Cancelled();
      }
      this.child = child;
      this.api = api;
      this.probePort = probePort;
      this.child.once("exit", (code) => this.onUnexpectedExit(code));
      if (tun) await flushDns();
      if (settings.mode === "system-proxy" && this.paths.manageSystemProxy !== false) {
        await setSystemProxy(settings.mixedPort);
        this.proxyPort = settings.mixedPort;
      }
      this.resetStats();
      this.handoffIf = tun ? net.otherInterface : void 0;
      this.directSource = tun ? adapterIpv4(net.interfaceAlias) : void 0;
      this.directIps = {};
      this.statsTimer = setInterval(() => void this.pollStats(), 1e3);
      this.setStatus({
        state: "running",
        mode: settings.mode,
        serverId: server.id,
        startedAt: Date.now(),
        otherTunnels: net.otherTunnels.length ? net.otherTunnels : void 0,
        proxyPort: settings.mixedPort
      });
      void this.checkHealth();
      this.healthTimer = setInterval(() => void this.checkHealth(), HEALTH_INTERVAL_MS);
    } catch (e) {
      if (e instanceof Cancelled) {
        if (gen === this.startGen) {
          await this.cleanup();
          this.setStatus({ state: "stopped" });
        }
        return;
      }
      await this.cleanup();
      const msg = e instanceof Error ? e.message : String(e);
      this.log(msg, "error");
      this.setStatus({ state: "stopped", error: msg });
      throw e;
    }
  }
  /**
   * The test's connections really must take the VPN adapter and leave through the VPN, or the
   * number would be about something else. They show in sing-box's list by their source port.
   */
  async speedTestRoute() {
    const api = this.api;
    if (!api) return "Disconnected during the test";
    const snap = await clashGet(api, "/connections");
    const ours = (snap.connections || []).filter((c) => {
      const port = Number(c.metadata.sourcePort);
      return port >= SPEED_TEST_PORTS.first && port <= SPEED_TEST_PORTS.last;
    });
    if (!ours.length) return "The test did not go through the VPN adapter, so another tool may be routing this traffic";
    return ours.every((c) => c.chains?.includes("proxy")) ? void 0 : "The test did not leave through the VPN server";
  }
  /** Measures the running server: first the way apps reach it (TUN modes), then skipping the adapter. */
  async speedTest(server, onProgress, signal) {
    const settings = this.settings;
    const probePort = this.probePort;
    if (this.status.state !== "running" || !settings || !probePort) throw new Error("Connect first, then run the speed test");
    const result = { core: { usedBytes: 0 }, serverName: server.name, mode: settings.mode, tunStack: settings.tunStack, tunMtu: settings.tunMtu, at: Date.now() };
    if (usesTun(settings.mode)) {
      const findAddress = async (host) => (await this.resolver.resolve(host))?.ip;
      result.adapter = await runPath(adapterDialer(findAddress), (phase, mbps) => onProgress("adapter", phase, mbps), () => this.speedTestRoute().catch(() => void 0), signal);
      this.log(`Speed test through the VPN adapter (stack ${settings.tunStack}, MTU ${settings.tunMtu || "auto"}): ${speedLine(result.adapter)}`);
    }
    result.core = await runPath(socksDialer(probePort), (phase, mbps) => onProgress("core", phase, mbps), void 0, signal);
    this.log(`Speed test skipping the adapter: ${speedLine(result.core)}`);
    return result;
  }
  /** Finds the largest packet the network carries, toward the VPN server if it answers ping. */
  async findMtu(server) {
    const ip = server && !isWarp(server) ? (await this.resolver.resolve(server.server).catch(() => void 0))?.ip : void 0;
    const running = this.status.state === "running" && !!this.settings && usesTun(this.settings.mode);
    const result = await findPathMtu(ip ? [ip, ...MTU_TARGETS] : MTU_TARGETS, running ? this.directSource : void 0);
    this.log(`Largest packet on this network: ${result.pathMtu} bytes (tested against ${result.target === ip ? "the VPN server" : result.target})`);
    return result;
  }
  /** Runs a real request through one outbound ("proxy" = VPN server, "direct" = normal internet). */
  async probe(api, outbound, testUrl) {
    const checkedAt = Date.now();
    try {
      const r = await clashGet(api, `/proxies/${outbound}/delay?timeout=5000&url=${encodeURIComponent(testUrl)}`, 7e3);
      return { ok: true, latency: r.delay, checkedAt };
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return { ok: false, error: /timeout|504|408/i.test(msg) ? "No response (timeout)" : msg.replace(/^Clash API [^:]+: /, ""), checkedAt };
    }
  }
  /**
   * Direct internet is checked against several Iranian sites at once and the fastest answer
   * counts: from Iran, foreign test URLs (gstatic) often fail or crawl without a VPN, which
   * made the check look broken while the connection was fine.
   */
  async probeDirect(api) {
    const checkedAt = Date.now();
    const times = await Promise.all(
      DIRECT_TEST_HOSTS.map(async (host) => {
        try {
          const found = this.directIps[host] ?? (await this.resolver.resolve(host))?.ip;
          if (!found) throw new Error("no address");
          const ip = this.directIps[host] = found;
          const first = await connectTime(ip, 443, this.directSource);
          return Math.min(first, await connectTime(ip, 443, this.directSource).catch(() => first));
        } catch {
          delete this.directIps[host];
          return void 0;
        }
      })
    );
    const best = times.filter((t) => t !== void 0).sort((a, b) => a - b)[0];
    if (best !== void 0) return { ok: true, latency: best, checkedAt };
    const checks = await Promise.all(DIRECT_TEST_URLS.map((url) => this.probe(api, "direct", url)));
    const ok = checks.filter((c) => c.ok).sort((a, b) => a.latency - b.latency);
    return ok[0] ?? checks[0];
  }
  /** Checks the VPN server and the normal internet, and reports the result in status.health. */
  async checkHealth() {
    const api = this.api;
    if (!api || this.status.state !== "running") return;
    const testUrl = this.settings?.testUrl || "https://www.gstatic.com/generate_204";
    const [server, internet] = await Promise.all([this.probe(api, "proxy", testUrl), this.probeDirect(api)]);
    if (this.api !== api || this.status.state !== "running") return;
    const prev = this.status.health?.server;
    if (prev && prev.ok !== server.ok) {
      this.log(server.ok ? `VPN server is responding again (${server.latency} ms)` : `VPN server is not responding: ${server.error}`, server.ok ? "info" : "warn");
    }
    this.setStatus({ ...this.status, health: { server, internet } });
  }
  get appRulesDir() {
    return (0, import_node_path2.join)(this.paths.dataDir, "app-rules");
  }
  /**
   * Applies app rule changes to the running core without restarting it: sing-box
   * reloads the rule-set files on its own. Open connections of the affected apps
   * are then closed so those apps reconnect through their new route; nothing else
   * on the system is interrupted.
   */
  async updateAppRules(rules, affectedPaths) {
    writeAppRuleSets(this.appRulesDir, rules);
    const api = this.api;
    if (this.status.state !== "running" || !api || !affectedPaths.length) return;
    await new Promise((r) => setTimeout(r, RULE_RELOAD_DELAY_MS));
    const affected = affectedPaths.map((p) => new RegExp(processPathRegex(p).replace("(?i)", ""), "i"));
    try {
      const snap = await clashGet(api, "/connections");
      const targets = (snap.connections || []).filter((c) => affected.some((re) => re.test(c.metadata.processPath || "")));
      await Promise.all(targets.map((c) => clashDelete(api, `/connections/${encodeURIComponent(c.id)}`)));
      if (targets.length) this.log(`App rules updated, reconnecting ${targets.length} connection(s)`);
    } catch (e) {
      this.log(`Could not reset app connections: ${e instanceof Error ? e.message : e}`, "warn");
    }
  }
  async stop() {
    if (this.status.state === "stopped") return;
    this.setStatus({ ...this.status, state: "stopping" });
    await this.cleanup();
    this.log("Disconnected");
    this.setStatus({ state: "stopped" });
  }
  /** Adds the VPN's exit location to the status (looked up by the app shell). */
  setExit(exit) {
    if (this.status.state === "running") this.setStatus({ ...this.status, exit });
  }
  async cleanup() {
    this.dnsRelay?.stop();
    this.dnsRelay = void 0;
    this.realAdapter = void 0;
    this.probePort = void 0;
    this.wonWarp = void 0;
    if (this.statsTimer) clearInterval(this.statsTimer);
    if (this.healthTimer) clearInterval(this.healthTimer);
    this.statsTimer = this.healthTimer = void 0;
    const handoffIf = this.handoffIf;
    const handedOff = [...this.handoffIps];
    this.handoffIf = void 0;
    this.handoffIps.clear();
    if (handoffIf && handedOff.length) {
      await setHostRoutes(handedOff, handoffIf, false).catch((e) => this.log(`Could not remove the routes to "${handoffIf}": ${e}`, "warn"));
    }
    const usedTun = !!this.child && !!this.settings && usesTun(this.settings.mode);
    if (this.proxyPort !== void 0) {
      await clearSystemProxy(this.proxyPort).catch((e) => this.log(`Could not clear system proxy: ${e}`, "warn"));
      this.proxyPort = void 0;
    }
    const xrayChild = this.xrayChild;
    this.xrayChild = void 0;
    await killProcess(xrayChild);
    const warpChildren = [...this.warpChildren];
    this.warpChildren.clear();
    await Promise.all(warpChildren.map((c) => killProcess(c)));
    const child = this.child;
    this.child = void 0;
    this.api = void 0;
    if (child && child.exitCode === null) {
      child.removeAllListeners("exit");
      await new Promise((resolve) => {
        child.once("exit", () => resolve());
        child.kill();
      });
    }
    if (usedTun) await flushDns();
  }
  onUnexpectedExit(code) {
    this.log(`sing-box stopped unexpectedly (exit code ${code})`, "error");
    this.child = void 0;
    if (this.settings && usesTun(this.settings.mode)) void flushDns();
    void this.cleanup().then(() => this.setStatus({ state: "stopped", error: "Core stopped unexpectedly, see Logs" }));
  }
  resetStats() {
    this.lastTotals = { up: 0, down: 0, at: Date.now() };
    this.seenConns.clear();
    this.appTotals.clear();
  }
  async pollStats() {
    const api = this.api;
    if (!api) return;
    try {
      const snap = await clashGet(api, "/connections");
      const now = Date.now();
      const secs = Math.max((now - this.lastTotals.at) / 1e3, 1e-3);
      const upSpeed = Math.max(0, (snap.uploadTotal - this.lastTotals.up) / secs);
      const downSpeed = Math.max(0, (snap.downloadTotal - this.lastTotals.down) / secs);
      this.lastTotals = { up: snap.uploadTotal, down: snap.downloadTotal, at: now };
      const live = /* @__PURE__ */ new Map();
      const routes = /* @__PURE__ */ new Map();
      for (const c of snap.connections || []) {
        const path = c.metadata.processPath || "";
        const outbound = c.chains?.[0];
        if (outbound) routes.set(path, (routes.get(path) || /* @__PURE__ */ new Set()).add(outbound));
        const prev = this.seenConns.get(c.id) || { path, up: 0, down: 0 };
        let app = this.appTotals.get(path);
        if (!app) {
          app = { path, name: path ? path.split("\\").pop() : "Other / system", upload: 0, download: 0, connections: 0 };
          this.appTotals.set(path, app);
        }
        app.upload += Math.max(0, c.upload - prev.up);
        app.download += Math.max(0, c.download - prev.down);
        this.seenConns.set(c.id, { path, up: c.upload, down: c.download });
        live.set(path, (live.get(path) || 0) + 1);
      }
      if (this.handoffIf) this.handOff(snap.connections || []);
      const liveIds = new Set((snap.connections || []).map((c) => c.id));
      for (const id of this.seenConns.keys()) if (!liveIds.has(id)) this.seenConns.delete(id);
      for (const app of this.appTotals.values()) {
        app.connections = live.get(app.path) || 0;
        const r = routes.get(app.path);
        if (r) app.route = r.size > 1 ? "mixed" : r.has("proxy") ? "vpn" : "direct";
      }
      const stats = {
        upSpeed,
        downSpeed,
        upTotal: snap.uploadTotal,
        downTotal: snap.downloadTotal,
        apps: [...this.appTotals.values()].sort((a, b) => b.upload + b.download - (a.upload + a.download))
      };
      this.emit("stats", stats);
    } catch {
    }
  }
  /** Routes new UDP destinations of "Other VPN" apps straight to the other tool's adapter. */
  handOff(connections) {
    const adapter = this.handoffIf;
    const ips = adapter ? handoffCandidates(connections, this.handoffIps) : [];
    if (!adapter || !ips.length) return;
    for (const ip of ips) this.handoffIps.add(ip);
    setHostRoutes(ips, adapter, true).then(
      () => this.log(`Handed ${ips.length} address(es) of "Other VPN" apps straight to "${adapter}": ${ips.join(", ")}`),
      (e) => this.log(`Could not add routes to "${adapter}": ${e}`, "warn")
    );
  }
  /**
   * Real latency test: starts a separate sing-box with every server as an outbound
   * and asks each one to fetch the test URL. Returns ms per server id, -1 on failure.
   */
  async testLatency(servers, testUrl, opts = {}) {
    const { workers = 8, timeoutMs = 6e3, name = "latency-test", quiet = false } = opts;
    const results = /* @__PURE__ */ new Map();
    servers = servers.filter((s) => !isWarp(s));
    if (!servers.length) return results;
    const configFile = (0, import_node_path2.join)(this.paths.dataDir, `${name}.json`);
    const workDir = (0, import_node_path2.join)(this.paths.dataDir, name);
    (0, import_node_fs3.mkdirSync)(workDir, { recursive: true });
    const lookups = /* @__PURE__ */ new Map();
    const isXray = (s) => s.engine === "xray";
    for (const s of servers) if (isXray(s) && !s.xray) results.set(s.id, -1);
    let testable = await Promise.all(
      servers.filter((s) => !isXray(s) || s.xray).map((s) => {
        if (isXray(s)) return s;
        const key = String(s.outbound.server);
        if (!lookups.has(key)) lookups.set(key, this.pinAddress(s, true));
        return lookups.get(key).then((p) => ({ ...s, outbound: withServerIp(s.outbound, String(p.outbound.server)) }));
      })
    );
    let xrayTest;
    const xrayEntries = [];
    for (const s of testable.filter(isXray)) xrayEntries.push({ id: s.id, port: await freePort(), outbound: await this.pinXray(s.xray, true) });
    if (xrayEntries.length) {
      try {
        xrayTest = await this.launchXray(xrayEntries, `xray-${name}`, this.realAdapter);
        const ports = new Map(xrayEntries.map((e) => [e.id, e.port]));
        testable = testable.map((s) => ports.has(s.id) ? { ...s, outbound: socksOutbound(ports.get(s.id)) } : s);
      } catch (e) {
        this.log(`Latency test: Xray servers skipped (${e instanceof Error ? e.message : e})`, "warn");
        for (const s of testable.filter(isXray)) results.set(s.id, -1);
        testable = testable.filter((s) => !isXray(s));
      }
    }
    let child;
    let api = { port: 0, secret: "" };
    while (!child && testable.length) {
      api = { port: await freePort(), secret: (0, import_node_crypto4.randomUUID)() };
      (0, import_node_fs3.writeFileSync)(configFile, JSON.stringify(buildTestConfig(testable, api), null, 2));
      let fatal = "";
      try {
        child = await launch(this.paths.singBox, configFile, workDir, api, (line, isErr) => {
          if (/FATAL/.test(line)) fatal = line;
          if (!quiet && isErr && /ERROR|FATAL/.test(line)) this.coreLine(line, true);
        });
      } catch (e) {
        const index = Number(fatal.match(/outbound\[(\d+)\]/)?.[1]) - 1;
        const bad = testable[index];
        if (!bad) throw e;
        if (!quiet) this.log(`Latency test: skipping "${bad.name}" (${fatal.replace(/^.*?outbound\[\d+\]:\s*/, "")})`, "warn");
        results.set(bad.id, -1);
        testable = testable.filter((s) => s !== bad);
      }
    }
    if (!child) {
      await killProcess(xrayTest);
      return results;
    }
    try {
      const queue = [...testable];
      const worker = async () => {
        for (let s = queue.shift(); s; s = queue.shift()) {
          try {
            const r = await clashGet(
              api,
              `/proxies/${encodeURIComponent(s.id)}/delay?timeout=${timeoutMs}&url=${encodeURIComponent(testUrl)}`,
              timeoutMs + 2e3
            );
            results.set(s.id, r.delay);
          } catch {
            results.set(s.id, -1);
          }
        }
      };
      await Promise.all(Array.from({ length: Math.min(workers, testable.length) }, worker));
    } finally {
      await killProcess(child);
      await killProcess(xrayTest);
    }
    return results;
  }
};

// src/main/cloudflarecdn.ts
var CLOUDFLARE_ADDRESS = "188.114.98.0";
var TLS_PORTS = /* @__PURE__ */ new Set(["443", "2053", "2083", "2087", "2096", "8443"]);
var HTTP_PORTS = /* @__PURE__ */ new Set(["80", "8080", "8880", "2052", "2082", "2086", "2095"]);
var TRANSPORTS = /* @__PURE__ */ new Set(["ws", "websocket", "httpupgrade", "xhttp", "splithttp", "grpc"]);
var DROPPED = /* @__PURE__ */ new Set(["allowinsecure", "insecure", "skip-cert-verify", "fm", "dialmode", "ech", "echoutbound", "fp", "cs", "pqv"]);
var CLOUDFLARE_FRAGMENT = JSON.stringify({ tcp: [{ type: "fragment", settings: { packets: "tlshello", length: "100-200", delay: "1" } }] });
function toCloudflare(link) {
  const scheme = link.slice(0, link.indexOf("://")).toLowerCase();
  if (scheme !== "vless" && scheme !== "trojan") return void 0;
  let url;
  try {
    url = new URL(`http${link.slice(link.indexOf("://"))}`);
  } catch {
    return void 0;
  }
  const params = /* @__PURE__ */ new Map();
  for (const [k, v] of url.searchParams) params.set(k.toLowerCase(), v);
  const security = (params.get("security") ?? "").toLowerCase();
  const transport = (params.get("type") ?? "tcp").toLowerCase();
  const host = (params.get("host") ?? "").split(",")[0].trim();
  const port = url.port || (security === "tls" ? "443" : "80");
  if (!url.username || !host || !TRANSPORTS.has(transport) || !["", "tls", "none"].includes(security)) return void 0;
  if (TLS_PORTS.has(port) ? security !== "tls" : !HTTP_PORTS.has(port) || security === "tls") return void 0;
  const out = new URLSearchParams();
  for (const [k, v] of params) if (!DROPPED.has(k) && !["security", "sni", "alpn", "host"].includes(k)) out.set(k, v);
  out.set("security", "tls");
  out.set("host", host);
  out.set("sni", host);
  out.set("fp", "chrome");
  if (transport === "ws" || transport === "websocket" || transport === "httpupgrade") out.set("alpn", "http/1.1");
  else if (params.get("alpn")) out.set("alpn", params.get("alpn"));
  const name = link.includes("#") ? link.slice(link.indexOf("#")) : "";
  return `${scheme}://${url.username}@${CLOUDFLARE_ADDRESS}:443?${out}${name}`;
}
function cloudflareKey(link) {
  return link.split("#")[0];
}
function withFragment(link) {
  const [body, name = ""] = link.split("#");
  return `${body}&fm=${encodeURIComponent(CLOUDFLARE_FRAGMENT)}${name ? `#${name}` : ""}`;
}

// src/main/store.ts
var DEFAULT_SETTINGS = {
  mode: "per-app",
  bypassIran: true,
  mixedPort: 2080,
  testUrl: "https://www.gstatic.com/generate_204",
  strictRoute: true,
  dnsMode: "fakeip",
  tunStack: "mixed",
  tunMtu: 0,
  logLevel: "info",
  autoPing: true,
  autoServer: false,
  showInDiscord: true,
  language: "en",
  buttonStyle: "dashboard",
  warpPsiphon: "",
  settingsVersion: 2
};

// scripts/collect-configs.ts
var TEST_MAX = Number(arg("--test-max") ?? 1500);
var KEEP_MAX = Number(arg("--keep-max") ?? 300);
var CF_TEST_MAX = Number(arg("--cf-test-max") ?? 6e3);
var CF_KEEP_MAX = Number(arg("--cf-keep-max") ?? 150);
var KEEP_MIN = Number(arg("--keep-min") ?? 20);
var LINK = /(?:vless|vmess|trojan|ss|hysteria2|hy2|tuic):\/\/[^\s<>"']+/g;
function arg(name) {
  const i = process.argv.indexOf(name);
  return i < 0 ? void 0 : process.argv[i + 1];
}
async function getText(url) {
  const res = await fetch(url, { signal: AbortSignal.timeout(3e4), headers: { "User-Agent": "Mozilla/5.0" } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.text();
}
var unescapeHtml = (s) => s.replace(/&amp;/g, "&").replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n))).replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCodePoint(parseInt(n, 16)));
function linksInChannelPage(html) {
  return (html.match(LINK) ?? []).map(unescapeHtml);
}
async function fromChannels(names) {
  const queue = [...names];
  const links = [];
  let answered = 0;
  await Promise.all(
    Array.from({ length: 6 }, async () => {
      for (let name = queue.shift(); name; name = queue.shift()) {
        const found = await getText(`https://t.me/s/${encodeURIComponent(name)}`).then(linksInChannelPage, () => void 0);
        if (found) answered++;
        links.push(...found ?? []);
      }
    })
  );
  return { links, answered };
}
function withName(link, name) {
  if (!link.startsWith("vmess://")) return `${link.split("#")[0]}#${encodeURIComponent(name)}`;
  const body = JSON.parse(decodeBase64(link.slice("vmess://".length)));
  return `vmess://${Buffer.from(JSON.stringify({ ...body, ps: name }), "utf8").toString("base64")}`;
}
async function main() {
  const started = Date.now();
  const cores = arg("--cores") ?? (0, import_node_path3.join)(__dirname, "cores");
  const out = arg("--out") ?? process.cwd();
  const channelFile = arg("--channels");
  const names = channelFile && (0, import_node_fs4.existsSync)(channelFile) ? (0, import_node_fs4.readFileSync)(channelFile, "utf8").split(/\r?\n/).map((l) => l.trim()).filter((l) => /^[A-Za-z0-9_]{4,40}$/.test(l)) : [];
  const fromLists = (await fetchPublicLinks(getText, (t) => console.log(t), [...PUBLIC_SOURCE_LISTS, ...COLLECTOR_EXTRA_LISTS])).links;
  const channels = await fromChannels(names);
  const all = [.../* @__PURE__ */ new Set([...channels.links, ...fromLists])];
  console.log(`${fromLists.length} links from lists, ${channels.links.length} from ${channels.answered} of ${names.length} channels, ${all.length} different`);
  const candidates = choosePublicCandidates(all, /* @__PURE__ */ new Set(), TEST_MAX);
  console.log(`${candidates.length} candidates after the filters`);
  const converted = /* @__PURE__ */ new Map();
  for (const link of all) {
    const cf = toCloudflare(link);
    if (cf && !converted.has(cloudflareKey(cf))) converted.set(cloudflareKey(cf), cf);
  }
  const cfCandidates = [...converted.values()].sort(() => Math.random() - 0.5).flatMap((link) => {
    try {
      const s = parseLink(link);
      return publicRefusal(s) ? [] : [s];
    } catch {
      return [];
    }
  }).slice(0, CF_TEST_MAX);
  console.log(`${converted.size} configs behind Cloudflare, ${cfCandidates.length} of them tested`);
  const dataDir = (0, import_node_fs4.mkdtempSync)((0, import_node_path3.join)((0, import_node_os3.tmpdir)(), "bridge-collect-"));
  const core = new Core({ singBox: (0, import_node_path3.join)(cores, "sing-box.exe"), xray: (0, import_node_path3.join)(cores, "xray.exe"), rulesDir: (0, import_node_path3.join)(cores, "rules"), dataDir });
  core.on("log", (l) => /^Public configs/.test(l.text) && console.log(l.text));
  const kept = await core.checkPublicConfigs(candidates, DEFAULT_SETTINGS.testUrl, KEEP_MAX);
  const cfKept = await core.checkPublicConfigs(cfCandidates, DEFAULT_SETTINGS.testUrl, CF_KEEP_MAX);
  await core.stop().catch(() => void 0);
  (0, import_node_fs4.rmSync)(dataDir, { recursive: true, force: true });
  const seconds = Math.round((Date.now() - started) / 1e3);
  console.log(`${kept.length} kept and ${cfKept.length} behind Cloudflare in ${seconds} s`);
  if (kept.length < KEEP_MIN) throw new Error(`Only ${kept.length} configs passed; keeping the previous list`);
  const links = kept.map((k, i) => withName(k.server.link, `Bridge ${i + 1}`));
  (0, import_node_fs4.mkdirSync)(out, { recursive: true });
  (0, import_node_fs4.writeFileSync)((0, import_node_path3.join)(out, "clean.txt"), `${links.join("\n")}
`);
  const cfLinks = cfKept.flatMap((k, i) => [withName(k.server.link, `Bridge CF ${i + 1}`), withName(withFragment(k.server.link), `Bridge CF ${i + 1} F`)]);
  if (cfLinks.length) (0, import_node_fs4.writeFileSync)((0, import_node_path3.join)(out, "cloudflare.txt"), `${cfLinks.join("\n")}
`);
  const count = (protocol) => kept.filter((k) => k.server.protocol === protocol).length;
  (0, import_node_fs4.writeFileSync)(
    (0, import_node_path3.join)(out, "stats.json"),
    `${JSON.stringify({ updatedAt: (/* @__PURE__ */ new Date()).toISOString(), collected: all.length, tested: candidates.length, kept: kept.length, cloudflare: cfKept.length, cloudflareFound: converted.size, vless: count("vless"), trojan: count("trojan"), vmess: count("vmess"), shadowsocks: count("shadowsocks"), hysteria2: count("hysteria2"), tuic: count("tuic"), channelsAnswered: channels.answered, seconds }, null, 2)}
`
  );
}
void main().then(
  () => process.exit(0),
  (e) => {
    console.error(e instanceof Error ? e.message : e);
    process.exit(1);
  }
);
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  linksInChannelPage,
  withName
});
