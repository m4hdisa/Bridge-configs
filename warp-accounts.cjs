// scripts/warp-accounts.ts
var import_node_child_process = require("node:child_process");
var import_node_fs = require("node:fs");
var import_node_os = require("node:os");
var import_node_path = require("node:path");

// src/main/warp.ts
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

// src/main/warp.ts
var WARP_IDENTITY_FILE = "aether-masque.toml";
var WARP_SHARE_SCHEME = "bridge://warp";
var IDENTITY_FIELDS = /* @__PURE__ */ new Set(["device_id", "access_token", "cert_pem", "key_pem", "cert_issued_at", "ipv4", "ipv6", "wg_private_key", "wg_peer_public_key", "client_id", "organization", "gateway_proxy", "assigned_endpoint"]);
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
var WARP_FIND_METHODS = ["gool", "mim-h2", ...WARP_METHODS.filter((m) => m.auto).map((m) => m.id)];
var GOOL_RETRY_MS = 30 * 60 * 1e3;
var H3_RETRY_MS = 6 * 60 * 60 * 1e3;
function warpRegisterArgs(configFile, extra = [], upstreamPort) {
  return ["--register", "masque", ...extra, ...upstreamPort ? ["--upstream", `socks5://127.0.0.1:${upstreamPort}`] : [], "--config", configFile];
}

// scripts/warp-accounts.ts
var arg = (name, fallback) => {
  const i = process.argv.indexOf(`--${name}`);
  const value = i >= 0 ? process.argv[i + 1] : fallback;
  if (value === void 0) throw new Error(`--${name} is required`);
  return value;
};
var aether = arg("aether");
var count = Number(arg("count", "60"));
var out = arg("out", ".");
var MAX_FAILURES_IN_A_ROW = 3;
var links = [];
var failuresInARow = 0;
for (let i = 0; i < count && failuresInARow < MAX_FAILURES_IN_A_ROW; i++) {
  const dir = (0, import_node_fs.mkdtempSync)((0, import_node_path.join)((0, import_node_os.tmpdir)(), "warp-starter-"));
  try {
    const run = (0, import_node_child_process.spawnSync)(aether, warpRegisterArgs((0, import_node_path.join)(dir, "aether.toml")), { timeout: 6e4, encoding: "utf8", windowsHide: true });
    const file = (0, import_node_path.join)(dir, WARP_IDENTITY_FILE);
    if (!(0, import_node_fs.existsSync)(file)) {
      failuresInARow++;
      console.log(`account ${i + 1}: failed (${(run.stderr || run.stdout || String(run.error ?? "")).trim().split(/\r?\n/).pop()})`);
      continue;
    }
    failuresInARow = 0;
    links.push(warpShareLink({ method: "auto" }, (0, import_node_fs.readFileSync)(file, "utf8"), "Free WARP"));
  } finally {
    (0, import_node_fs.rmSync)(dir, { recursive: true, force: true });
  }
}
console.log(`${links.length} of ${count} WARP starter accounts made`);
if (links.length) (0, import_node_fs.writeFileSync)((0, import_node_path.join)(out, "warp.txt"), links.join("\n") + "\n");
else process.exitCode = 1;
